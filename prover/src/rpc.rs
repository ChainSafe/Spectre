use super::args::Spec;
use ethers::prelude::*;
use itertools::Itertools;
use jsonrpc_v2::{Error as JsonRpcError, Params};
use jsonrpc_v2::{MapRouter as JsonRpcMapRouter, Server as JsonRpcServer};
use lightclient_circuits::halo2_proofs::halo2curves::bn256::Fr;
use lightclient_circuits::{
    committee_update_circuit::CommitteeUpdateCircuit,
    sync_step_circuit::StepCircuit,
    util::{gen_srs, AppCircuit},
};
use preprocessor::{
    fetch_rotation_args, fetch_step_args, rotation_args_from_update, step_args_from_finality_update,
};
use snark_verifier_sdk::{evm::evm_verify, halo2::aggregation::AggregationCircuit, Snark};
use std::path::PathBuf;
use url::Url;

use crate::rpc_api::{
    EvmProofResult, GenProofRotationParams, GenProofRotationWithWitnessParams, GenProofStepParams,
    GenProofStepWithWitnessParams, SyncCommitteePoseidonParams, SyncCommitteePoseidonResult,
    EVM_PROOF_ROTATION_CIRCUIT, EVM_PROOF_ROTATION_CIRCUIT_WITH_WITNESS, EVM_PROOF_STEP_CIRCUIT,
    EVM_PROOF_STEP_CIRCUIT_WITH_WITNESS, SYNC_COMMITTEE_POSEIDON_COMPRESSED,
    SYNC_COMMITTEE_POSEIDON_UNCOMPRESSED,
};

fn gen_app_snark<S: eth_types::Spec>(
    app_config_path: PathBuf,
    app_pk_path: PathBuf,
    witness: <CommitteeUpdateCircuit<S, Fr> as AppCircuit>::Witness,
) -> eyre::Result<Snark> {
    let params = gen_srs(CommitteeUpdateCircuit::<S, Fr>::get_degree(
        &app_config_path,
    ));

    let app_pk = CommitteeUpdateCircuit::<S, Fr>::create_pk(
        &params,
        app_pk_path,
        &app_config_path,
        &<CommitteeUpdateCircuit<S, Fr> as AppCircuit>::Witness::default(),
    );

    Ok(CommitteeUpdateCircuit::<S, Fr>::gen_snark_shplonk(
        &params,
        &app_pk,
        app_config_path,
        None::<PathBuf>,
        &witness,
    )?)
}

fn gen_evm_proof<C: AppCircuit>(
    k: Option<u32>,
    build_dir: PathBuf,
    pk_filename: String,
    config_path: PathBuf,
    witness: C::Witness,
) -> (Vec<u8>, Vec<Vec<Fr>>) {
    let k = k.unwrap_or_else(|| C::get_degree(&config_path));
    let params = gen_srs(k);

    let pk = C::create_pk(&params, build_dir.join(pk_filename), &config_path, &witness);

    let (proof, instances) = C::gen_evm_proof_shplonk(&params, &pk, &config_path, None, &witness)
        .map_err(|e| eyre::eyre!("Failed to generate calldata: {}", e))
        .unwrap();

    println!("Proof size: {}", proof.len());
    let deployment_code =
        C::gen_evm_verifier_shplonk(&params, &pk, Some("contractyul"), &witness).unwrap();
    println!("deployment_code size: {}", deployment_code.len());
    evm_verify(deployment_code, instances.clone(), proof.clone());
    println!("Gen evm proof done");
    (proof, instances)
}

pub(crate) async fn gen_evm_proof_rotation_circuit_handler(
    Params(params): Params<GenProofRotationParams>,
) -> Result<EvmProofResult, JsonRpcError> {
    let GenProofRotationParams {
        spec,
        k,
        beacon_api,
    } = params;

    // TODO: use config/build paths from CLI flags
    let app_config_path = PathBuf::from("../lightclient-circuits/config/committee_update.json");

    let agg_l2_pk_path = PathBuf::from("./build/step_agg_l2.pkey");
    let agg_l1_pk_path = PathBuf::from("./build/step_agg_l1.pkey");

    let agg_l2_config_path =
        PathBuf::from("../lightclient-circuits/config/committee_update_aggregation_2.json");
    let agg_l1_config_path =
        PathBuf::from("../lightclient-circuits/config/committee_update_aggregation_1.json");

    let l0_snark = match spec {
        Spec::Minimal => {
            let app_pk_path = PathBuf::from("./build/committee_update_circuit_minimal.pkey");
            let client = beacon_api_client::minimal::Client::new(Url::parse(&beacon_api)?);
            let witness: lightclient_circuits::witness::CommitteeRotationArgs<
                eth_types::Minimal,
                Fr,
            > = fetch_rotation_args(&client).await?;
            gen_app_snark::<eth_types::Minimal>(app_config_path, app_pk_path, witness)?
        }
        Spec::Testnet => {
            let app_pk_path = PathBuf::from("./build/committee_update_circuit_testnet.pkey");
            let client = beacon_api_client::mainnet::Client::new(Url::parse(&beacon_api)?);
            let witness = fetch_rotation_args(&client).await?;
            gen_app_snark::<eth_types::Testnet>(app_config_path, app_pk_path, witness)?
        }
        Spec::Mainnet => {
            let app_pk_path = PathBuf::from("./build/committee_update_circuit_mainnet.pkey");
            let client = beacon_api_client::mainnet::Client::new(Url::parse(&beacon_api)?);
            let witness = fetch_rotation_args(&client).await?;
            gen_app_snark::<eth_types::Mainnet>(app_config_path, app_pk_path, witness)?
        }
    };

    let l1_snark = {
        let k = k.unwrap_or(24);
        let p1 = gen_srs(k);
        let pk_l1 = AggregationCircuit::read_pk(&p1, agg_l1_pk_path, &vec![l0_snark.clone()]);

        let snark = AggregationCircuit::gen_snark_shplonk(
            &p1,
            &pk_l1,
            agg_l1_config_path,
            None::<String>,
            &vec![l0_snark.clone()],
        )
        .map_err(JsonRpcError::internal)?;
        println!("L1 snark size: {}", snark.proof.len());

        snark
    };

    let (proof, instances) = {
        let k = k.unwrap_or(24);
        let p2 = gen_srs(k);
        let pk_l2 = AggregationCircuit::read_pk(&p2, agg_l2_pk_path, &vec![l1_snark.clone()]);
        AggregationCircuit::gen_evm_proof_shplonk(
            &p2,
            &pk_l2,
            agg_l2_config_path,
            None,
            &vec![l1_snark.clone()],
        )
        .map_err(JsonRpcError::internal)?
    };

    let public_inputs = instances[0]
        .iter()
        .map(|pi| U256::from_little_endian(&pi.to_bytes()))
        .collect();
    Ok(EvmProofResult {
        proof,
        public_inputs,
    })
}

pub(crate) async fn gen_evm_proof_rotation_circuit_with_witness_handler(
    Params(params): Params<GenProofRotationWithWitnessParams>,
) -> Result<EvmProofResult, JsonRpcError> {
    let GenProofRotationWithWitnessParams {
        spec,
        k,
        light_client_update,
    } = params;

    // TODO: use config/build paths from CLI flags
    let app_config_path = PathBuf::from("../lightclient-circuits/config/committee_update.json");
    let agg_l2_pk_path = PathBuf::from("./build/step_agg_l2.pkey");
    let agg_l1_pk_path = PathBuf::from("./build/step_agg_l1.pkey");

    let agg_l2_config_path =
        PathBuf::from("../lightclient-circuits/config/committee_update_aggregation_2.json");
    let agg_l1_config_path =
        PathBuf::from("../lightclient-circuits/config/committee_update_aggregation_1.json");
    let _build_dir = PathBuf::from("./build");

    let (l0_snark, _pk_filename) = match spec {
        Spec::Minimal => {
            let mut update = serde_json::from_slice(&light_client_update).unwrap();
            let app_pk_path = PathBuf::from("./build/committee_update_circuit_minimal.pkey");

            let witness = rotation_args_from_update(&mut update).await.unwrap();
            (
                gen_app_snark::<eth_types::Minimal>(app_config_path, app_pk_path, witness)?,
                "agg_rotation_circuit_minimal.pkey",
            )
        }
        Spec::Testnet => {
            let mut update = serde_json::from_slice(&light_client_update).unwrap();
            let app_pk_path = PathBuf::from("./build/committee_update_circuit_testnet.pkey");

            let witness = rotation_args_from_update(&mut update).await.unwrap();

            (
                gen_app_snark::<eth_types::Testnet>(app_config_path, app_pk_path, witness)?,
                "agg_rotation_circuit_testnet.pkey",
            )
        }
        Spec::Mainnet => {
            let mut update = serde_json::from_slice(&light_client_update).unwrap();
            let app_pk_path = PathBuf::from("./build/committee_update_circuit_mainnet.pkey");

            let witness = rotation_args_from_update(&mut update).await.unwrap();

            (
                gen_app_snark::<eth_types::Mainnet>(app_config_path, app_pk_path, witness)?,
                "agg_rotation_circuit_mainnet.pkey",
            )
        }
    };

    let l1_snark = {
        let k = k.unwrap_or(24);
        let p1 = gen_srs(k);
        let pk_l1 = AggregationCircuit::read_pk(&p1, agg_l1_pk_path, &vec![l0_snark.clone()]);

        let snark = AggregationCircuit::gen_snark_shplonk(
            &p1,
            &pk_l1,
            agg_l1_config_path,
            None::<String>,
            &vec![l0_snark.clone()],
        )
        .map_err(JsonRpcError::internal)?;
        println!("L1 snark size: {}", snark.proof.len());

        snark
    };

    let (proof, instances) = {
        let k = k.unwrap_or(24);
        let p2 = gen_srs(k);
        let pk_l2 = AggregationCircuit::read_pk(&p2, agg_l2_pk_path, &vec![l1_snark.clone()]);
        AggregationCircuit::gen_evm_proof_shplonk(
            &p2,
            &pk_l2,
            agg_l2_config_path,
            None,
            &vec![l1_snark.clone()],
        )
        .map_err(JsonRpcError::internal)?
    };

    let public_inputs = instances[0]
        .iter()
        .map(|pi| U256::from_little_endian(&pi.to_bytes()))
        .collect();
    Ok(EvmProofResult {
        proof,
        public_inputs,
    })
}

pub(crate) async fn gen_evm_proof_step_circuit_handler(
    Params(params): Params<GenProofStepParams>,
) -> Result<EvmProofResult, JsonRpcError> {
    let GenProofStepParams {
        spec,
        k,
        beacon_api,
    } = params.clone();

    let config_path = PathBuf::from("../lightclient-circuits/config/sync_step.json");
    let build_dir = PathBuf::from("./build");

    let (proof, instances) = match spec {
        Spec::Minimal => {
            let pk_filename = format!("step_circuit_minimal.pkey");
            let client = beacon_api_client::minimal::Client::new(Url::parse(&beacon_api)?);

            let witness = fetch_step_args(&client).await.unwrap();
            gen_evm_proof::<StepCircuit<eth_types::Minimal, Fr>>(
                k,
                build_dir,
                pk_filename,
                config_path,
                witness,
            )
        }
        Spec::Testnet => {
            let pk_filename = format!("step_circuit_testnet.pkey");
            let client = beacon_api_client::mainnet::Client::new(Url::parse(&beacon_api)?);

            let witness = fetch_step_args(&client).await.unwrap();

            gen_evm_proof::<StepCircuit<eth_types::Testnet, Fr>>(
                k,
                build_dir,
                pk_filename,
                config_path,
                witness,
            )
        }
        Spec::Mainnet => {
            let pk_filename = format!("step_circuit_mainnet.pkey");
            let client = beacon_api_client::mainnet::Client::new(Url::parse(&beacon_api)?);

            let witness = fetch_step_args(&client).await.unwrap();

            gen_evm_proof::<StepCircuit<eth_types::Mainnet, Fr>>(
                k,
                build_dir,
                pk_filename,
                config_path,
                witness,
            )
        }
    };

    let public_inputs = instances[0]
        .iter()
        .map(|pi| U256::from_little_endian(&pi.to_bytes()))
        .collect();
    Ok(EvmProofResult {
        proof,
        public_inputs,
    })
}

pub(crate) async fn gen_evm_proof_step_circuit_with_witness_handler(
    Params(params): Params<GenProofStepWithWitnessParams>,
) -> Result<EvmProofResult, JsonRpcError> {
    let GenProofStepWithWitnessParams {
        spec,
        k,
        light_client_finality_update,
        domain,
        pubkeys,
    } = params;

    let config_path = PathBuf::from("../lightclient-circuits/config/sync_step.json");
    let build_dir = PathBuf::from("./build");

    let (proof, instances) = match spec {
        Spec::Minimal => {
            let pk_filename = format!("step_circuit_minimal.pkey");

            let update = serde_json::from_slice(&light_client_finality_update).unwrap();
            let pubkeys = serde_json::from_slice(&pubkeys).unwrap();

            let witness = step_args_from_finality_update(update, pubkeys, domain)
                .await
                .unwrap();
            gen_evm_proof::<StepCircuit<eth_types::Minimal, Fr>>(
                k,
                build_dir,
                pk_filename,
                config_path,
                witness,
            )
        }
        Spec::Testnet => {
            let pk_filename = format!("step_circuit_testnet.pkey");
            let update = serde_json::from_slice(&light_client_finality_update).unwrap();
            let pubkeys = serde_json::from_slice(&pubkeys).unwrap();

            let witness = step_args_from_finality_update(update, pubkeys, domain)
                .await
                .unwrap();
            gen_evm_proof::<StepCircuit<eth_types::Testnet, Fr>>(
                k,
                build_dir,
                pk_filename,
                config_path,
                witness,
            )
        }
        Spec::Mainnet => {
            let pk_filename = format!("step_circuit_mainnet.pkey");
            let update = serde_json::from_slice(&light_client_finality_update).unwrap();
            let pubkeys = serde_json::from_slice(&pubkeys).unwrap();

            let witness = step_args_from_finality_update(update, pubkeys, domain)
                .await
                .unwrap();
            gen_evm_proof::<StepCircuit<eth_types::Mainnet, Fr>>(
                k,
                build_dir,
                pk_filename,
                config_path,
                witness,
            )
        }
    };

    let public_inputs = instances[0]
        .iter()
        .map(|pi| U256::from_little_endian(&pi.to_bytes()))
        .collect();
    Ok(EvmProofResult {
        proof,
        public_inputs,
    })
}

pub(crate) async fn sync_committee_poseidon_compressed_handler(
    Params(params): Params<SyncCommitteePoseidonParams>,
) -> Result<SyncCommitteePoseidonResult, JsonRpcError> {
    let SyncCommitteePoseidonParams { pubkeys } = params;

    let pubkeys = pubkeys
        .into_iter()
        .map(|mut b| {
            b.reverse();
            b
        })
        .collect_vec();

    let commitment = lightclient_circuits::poseidon::poseidon_committee_commitment_from_compressed(
        pubkeys.as_slice(),
    )?;

    Ok(SyncCommitteePoseidonResult { commitment })
}
pub(crate) async fn sync_committee_poseidon_uncompressed_handler(
    Params(params): Params<SyncCommitteePoseidonParams>,
) -> Result<SyncCommitteePoseidonResult, JsonRpcError> {
    let SyncCommitteePoseidonParams { pubkeys } = params;

    let pubkeys = pubkeys
        .into_iter()
        .map(|mut b| {
            b.reverse();
            b
        })
        .collect_vec();

    let commitment =
        lightclient_circuits::poseidon::poseidon_committee_commitment_from_uncompressed(
            pubkeys.as_slice(),
        )?;

    Ok(SyncCommitteePoseidonResult { commitment })
}

pub(crate) fn jsonrpc_server() -> JsonRpcServer<JsonRpcMapRouter> {
    JsonRpcServer::new()
        .with_method(EVM_PROOF_STEP_CIRCUIT, gen_evm_proof_step_circuit_handler)
        .with_method(
            EVM_PROOF_ROTATION_CIRCUIT,
            gen_evm_proof_rotation_circuit_handler,
        )
        .with_method(
            EVM_PROOF_ROTATION_CIRCUIT_WITH_WITNESS,
            gen_evm_proof_rotation_circuit_with_witness_handler,
        )
        .with_method(
            EVM_PROOF_STEP_CIRCUIT_WITH_WITNESS,
            gen_evm_proof_step_circuit_with_witness_handler,
        )
        .with_method(
            SYNC_COMMITTEE_POSEIDON_UNCOMPRESSED,
            sync_committee_poseidon_uncompressed_handler,
        )
        .with_method(
            SYNC_COMMITTEE_POSEIDON_COMPRESSED,
            sync_committee_poseidon_compressed_handler,
        )
        .finish_unwrapped()
}
