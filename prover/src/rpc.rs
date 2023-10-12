use super::args::Spec;

use ethers::prelude::*;
use halo2curves::bn256::Fr;

use jsonrpc_v2::{Error as JsonRpcError, Params};
use lightclient_circuits::{
    aggregation::AggregationConfigPinning,
    committee_update_circuit::CommitteeUpdateCircuit,
    sync_step_circuit::SyncStepCircuit,
    util::{gen_srs, AppCircuit, Halo2ConfigPinning},
};
use preprocessor::{fetch_rotation_args, fetch_step_args};

use jsonrpc_v2::{MapRouter as JsonRpcMapRouter, Server as JsonRpcServer};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::gates::builder::CircuitBuilderStage;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    CircuitExt, Snark, SHPLONK,
};
use std::path::PathBuf;

use crate::rpc_api::{
    EvmProofResult, GenProofRotationParams, GenProofStepParams, EVM_PROOF_ROTATION_CIRCUIT,
    EVM_PROOF_STEP_CIRCUIT,
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
    let app_pk_path = PathBuf::from("./build/committee_update_circuit.pkey");

    let agg_l2_config_path =
        PathBuf::from("../lightclient-circuits/config/committee_update_aggregation_2.json");
    let agg_l1_config_path =
        PathBuf::from("../lightclient-circuits/config/committee_update_aggregation_1.json");
    let _build_dir = PathBuf::from("./build");

    let (l0_snark, _pk_filename) = match spec {
        Spec::Minimal => {
            let witness = fetch_rotation_args(beacon_api).await?;
            (
                gen_app_snark::<eth_types::Minimal>(app_config_path, app_pk_path, witness)?,
                "agg_rotation_circuit_minimal.pkey",
            )
        }
        Spec::Testnet => {
            let witness = fetch_rotation_args(beacon_api).await?;
            (
                gen_app_snark::<eth_types::Testnet>(app_config_path, app_pk_path, witness)?,
                "agg_rotation_circuit_testnet.pkey",
            )
        }
        Spec::Mainnet => {
            let witness = fetch_rotation_args(beacon_api).await?;
            (
                gen_app_snark::<eth_types::Mainnet>(app_config_path, app_pk_path, witness)?,
                "agg_rotation_circuit_mainnet.pkey",
            )
        }
    };

    let l1_snark = {
        let k = k.unwrap_or(24);
        let p1 = gen_srs(k);
        let mut circuit = AggregationCircuit::keygen::<SHPLONK>(&p1, vec![l0_snark.clone()]);
        circuit.expose_previous_instances(false);

        println!("L1 Keygen num_instances: {:?}", circuit.num_instance());

        let pk_l1 = gen_pk(&p1, &circuit, None);
        let pinning = AggregationConfigPinning::from_path(agg_l1_config_path);
        let lookup_bits = k as usize - 1;
        let mut circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            Some(pinning.break_points),
            lookup_bits,
            &p1,
            std::iter::once(l0_snark),
        );
        circuit.expose_previous_instances(false);

        println!("L1 Prover num_instances: {:?}", circuit.num_instance());
        let snark = gen_snark_shplonk(&p1, &pk_l1, circuit, None::<String>);
        println!("L1 snark size: {}", snark.proof.len());

        snark
    };

    let (proof, instances) = {
        let k = k.unwrap_or(24);
        let p2 = gen_srs(k);
        let mut circuit =
            AggregationCircuit::keygen::<SHPLONK>(&p2, std::iter::once(l1_snark.clone()));
        circuit.expose_previous_instances(true);

        let pk_l2 = gen_pk(&p2, &circuit, None);
        let pinning = AggregationConfigPinning::from_path(agg_l2_config_path);

        let mut circuit = AggregationCircuit::prover::<SHPLONK>(
            &p2,
            std::iter::once(l1_snark),
            pinning.break_points,
        );
        circuit.expose_previous_instances(true);

        let instances = circuit.instances();

        let proof =
            snark_verifier_sdk::evm::gen_evm_proof_shplonk(&p2, &pk_l2, circuit, instances.clone());

        (proof, instances)
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
            let witness = fetch_step_args(beacon_api).await.unwrap();
            gen_evm_proof::<SyncStepCircuit<eth_types::Minimal, Fr>>(
                k,
                build_dir,
                pk_filename,
                config_path,
                witness,
            )
        }
        Spec::Testnet => {
            let pk_filename = format!("step_circuit_testnet.pkey");
            let witness = fetch_step_args(beacon_api).await.unwrap();

            gen_evm_proof::<SyncStepCircuit<eth_types::Testnet, Fr>>(
                k,
                build_dir,
                pk_filename,
                config_path,
                witness,
            )
        }
        Spec::Mainnet => {
            let pk_filename = format!("step_circuit_mainnet.pkey");
            let witness = fetch_step_args(beacon_api).await.unwrap();

            gen_evm_proof::<SyncStepCircuit<eth_types::Mainnet, Fr>>(
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

pub(crate) fn jsonrpc_server() -> JsonRpcServer<JsonRpcMapRouter> {
    JsonRpcServer::new()
        .with_method(EVM_PROOF_STEP_CIRCUIT, gen_evm_proof_step_circuit_handler)
        .with_method(
            EVM_PROOF_ROTATION_CIRCUIT,
            gen_evm_proof_rotation_circuit_handler,
        )
        .finish_unwrapped()
}
