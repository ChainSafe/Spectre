use super::args::Spec;
use axum::{http::StatusCode, response::IntoResponse, routing::post, Router};
use ethers::prelude::*;
use itertools::Itertools;
use jsonrpc_v2::RequestObject as JsonRpcRequestObject;
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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use url::Url;

pub type JsonRpcServerState = Arc<JsonRpcServer<JsonRpcMapRouter>>;

use crate::rpc_api::{
    EvmProofResult, GenProofRotationParams, GenProofRotationWithWitnessParams, GenProofStepParams,
    GenProofStepWithWitnessParams, SyncCommitteePoseidonParams, SyncCommitteePoseidonResult,
    EVM_PROOF_ROTATION_CIRCUIT, EVM_PROOF_ROTATION_CIRCUIT_WITH_WITNESS, EVM_PROOF_STEP_CIRCUIT,
    EVM_PROOF_STEP_CIRCUIT_WITH_WITNESS, SYNC_COMMITTEE_POSEIDON_COMPRESSED,
    SYNC_COMMITTEE_POSEIDON_UNCOMPRESSED,
};

fn gen_committee_update_snark<S: eth_types::Spec>(
    config_path: PathBuf,
    pk_path: PathBuf,
    witness: <CommitteeUpdateCircuit<S, Fr> as AppCircuit>::Witness,
) -> eyre::Result<Snark> {
    let params = gen_srs(CommitteeUpdateCircuit::<S, Fr>::get_degree(&config_path));

    let app_pk = CommitteeUpdateCircuit::<S, Fr>::read_pk(
        &params,
        pk_path,
        &<CommitteeUpdateCircuit<S, Fr> as AppCircuit>::Witness::default(),
    );

    Ok(CommitteeUpdateCircuit::<S, Fr>::gen_snark_shplonk(
        &params,
        &app_pk,
        config_path,
        None::<PathBuf>,
        &witness,
    )?)
}

fn gen_evm_proof<C: AppCircuit>(
    pk_path: impl AsRef<Path>,
    config_path: PathBuf,
    witness: C::Witness,
    yul_path_if_verify: Option<impl AsRef<Path>>,
) -> eyre::Result<(Vec<u8>, Vec<Vec<Fr>>)> {
    let k = C::get_degree(&config_path);
    let params = gen_srs(k);

    let pk = C::read_pk(&params, pk_path, &witness);

    let (proof, instances) = C::gen_evm_proof_shplonk(&params, &pk, &config_path, None, &witness)
        .map_err(|e| eyre::eyre!("Failed to generate calldata: {}", e))?;

    println!("Proof size: {}", proof.len());
    if let Some(deployment_code_path) = yul_path_if_verify {
        let deployment_code =
            C::gen_evm_verifier_shplonk(&params, &pk, Some(deployment_code_path), &witness)?;
        println!("Deployment code size: {}", deployment_code.len());
        evm_verify(deployment_code, instances.clone(), proof.clone());
    }
    Ok((proof, instances))
}

pub(crate) async fn gen_evm_proof_rotation_circuit_handler(
    Params(params): Params<GenProofRotationParams>,
) -> Result<EvmProofResult, JsonRpcError> {
    let GenProofRotationParams { spec, beacon_api } = params;

    // TODO: use config/build paths from CLI flags

    let (snark, verifier_filename) = match spec {
        Spec::Minimal => {
            let client = beacon_api_client::minimal::Client::new(Url::parse(&beacon_api)?);
            let witness = fetch_rotation_args(&client).await?;
            let snark = gen_committee_update_snark::<eth_types::Minimal>(
                PathBuf::from("./lightclient-circuits/config/committee_update_minimal.json"),
                PathBuf::from("./build/committee_update_minimal.pkey"),
                witness,
            )?;

            (snark, "committee_update_verifier_minimal")
        }
        Spec::Testnet => {
            let client = beacon_api_client::mainnet::Client::new(Url::parse(&beacon_api)?);
            let witness = fetch_rotation_args(&client).await?;
            let snark = gen_committee_update_snark::<eth_types::Testnet>(
                PathBuf::from("./lightclient-circuits/config/committee_update_testnet.json"),
                PathBuf::from("./build/committee_update_testnet.pkey"),
                witness,
            )?;

            (snark, "committee_update_verifier_testnet")
        }
        Spec::Mainnet => {
            let client = beacon_api_client::mainnet::Client::new(Url::parse(&beacon_api)?);
            let witness = fetch_rotation_args(&client).await?;
            let snark = gen_committee_update_snark::<eth_types::Mainnet>(
                PathBuf::from("./lightclient-circuits/config/committee_update_mainnet.json"),
                PathBuf::from("./build/committee_update_mainnet.pkey"),
                witness,
            )?;

            (snark, "committee_update_verifier_mainnet")
        }
    };

    let (proof, instances) = {
        let pinning_path = format!("./lightclient-circuits/config/{verifier_filename}.json");

        let agg_k = AggregationCircuit::get_degree(&pinning_path);
        let params_agg = gen_srs(agg_k);
        let pk_agg = AggregationCircuit::read_pk(
            &params_agg,
            format!("./build/{verifier_filename}.pkey"),
            &vec![snark.clone()],
        );

        AggregationCircuit::gen_evm_proof_shplonk(
            &params_agg,
            &pk_agg,
            pinning_path,
            None,
            &vec![snark.clone()],
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
        light_client_update,
    } = params;

    // TODO: use config/build paths from CLI flags

    let (snark, verifier_filename) = match spec {
        Spec::Minimal => {
            let mut update = ssz_rs::deserialize(&light_client_update)?;
            let witness = rotation_args_from_update(&mut update).await?;
            let snark = gen_committee_update_snark::<eth_types::Minimal>(
                PathBuf::from("./lightclient-circuits/config/committee_update_minimal.json"),
                PathBuf::from("./build/committee_update_minimal.pkey"),
                witness,
            )?;

            (snark, "committee_update_verifier_minimal")
        }
        Spec::Testnet => {
            let mut update = ssz_rs::deserialize(&light_client_update)?;
            let witness = rotation_args_from_update(&mut update).await?;
            let snark = gen_committee_update_snark::<eth_types::Testnet>(
                PathBuf::from("./lightclient-circuits/config/committee_update_testnet.json"),
                PathBuf::from("./build/committee_update_testnet.pkey"),
                witness,
            )?;

            (snark, "committee_update_verifier_testnet")
        }
        Spec::Mainnet => {
            let mut update = ssz_rs::deserialize(&light_client_update)?;
            let witness = rotation_args_from_update(&mut update).await?;
            let snark = gen_committee_update_snark::<eth_types::Mainnet>(
                PathBuf::from("./lightclient-circuits/config/committee_update_mainnet.json"),
                PathBuf::from("./build/committee_update_mainnet.pkey"),
                witness,
            )?;

            (snark, "committee_update_verifier_mainnet")
        }
    };

    let (proof, instances) = {
        let pinning_path = format!("./lightclient-circuits/config/{verifier_filename}.json");

        // Circuits of all specs have the same pinning type so we can just use Mainnet spec.
        let agg_k = AggregationCircuit::get_degree(&pinning_path);
        let params_agg = gen_srs(agg_k);
        let pk_agg = AggregationCircuit::read_pk(
            &params_agg,
            format!("./build/{verifier_filename}.pkey"),
            &vec![snark.clone()],
        );

        AggregationCircuit::gen_evm_proof_shplonk(
            &params_agg,
            &pk_agg,
            pinning_path,
            None,
            &vec![snark.clone()],
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
    let GenProofStepParams { spec, beacon_api } = params.clone();

    let (proof, instances) = match spec {
        Spec::Minimal => {
            let client = beacon_api_client::minimal::Client::new(Url::parse(&beacon_api)?);
            let witness = fetch_step_args(&client).await?;

            gen_evm_proof::<StepCircuit<eth_types::Minimal, Fr>>(
                PathBuf::from("./build/sync_step_minimal.pkey"),
                PathBuf::from("./lightclient-circuits/config/sync_step_minimal.json"),
                witness,
                None::<PathBuf>,
            )?
        }
        Spec::Testnet => {
            let client = beacon_api_client::mainnet::Client::new(Url::parse(&beacon_api)?);
            let witness = fetch_step_args(&client).await?;

            gen_evm_proof::<StepCircuit<eth_types::Testnet, Fr>>(
                PathBuf::from("./build/sync_step_testnet.pkey"),
                PathBuf::from("./lightclient-circuits/config/sync_step_testnet.json"),
                witness,
                None::<PathBuf>,
            )?
        }
        Spec::Mainnet => {
            let client = beacon_api_client::mainnet::Client::new(Url::parse(&beacon_api)?);
            let witness = fetch_step_args(&client).await?;

            gen_evm_proof::<StepCircuit<eth_types::Mainnet, Fr>>(
                PathBuf::from("./build/sync_step_mainnet.pkey"),
                PathBuf::from("./lightclient-circuits/config/sync_step_mainnet.json"),
                witness,
                None::<PathBuf>,
            )?
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
        light_client_finality_update,
        domain,
        pubkeys,
    } = params;

    let (proof, instances) = match spec {
        Spec::Minimal => {
            let update = ssz_rs::deserialize(&light_client_finality_update)?;
            let pubkeys = ssz_rs::deserialize(&pubkeys)?;
            let witness = step_args_from_finality_update(update, pubkeys, domain).await?;

            gen_evm_proof::<StepCircuit<eth_types::Minimal, Fr>>(
                PathBuf::from("./build/sync_step_minimal.pkey"),
                PathBuf::from("./lightclient-circuits/config/sync_step_minimal.json"),
                witness,
                None::<PathBuf>,
            )?
        }
        Spec::Testnet => {
            let update = ssz_rs::deserialize(&light_client_finality_update)?;
            let pubkeys = ssz_rs::deserialize(&pubkeys)?;
            let witness = step_args_from_finality_update(update, pubkeys, domain).await?;

            gen_evm_proof::<StepCircuit<eth_types::Testnet, Fr>>(
                PathBuf::from("./build/sync_step_testnet.pkey"),
                PathBuf::from("./lightclient-circuits/config/sync_step_testnet.json"),
                witness,
                None::<PathBuf>,
            )?
        }
        Spec::Mainnet => {
            let update = ssz_rs::deserialize(&light_client_finality_update)?;
            let pubkeys = ssz_rs::deserialize(&pubkeys)?;
            let witness = step_args_from_finality_update(update, pubkeys, domain).await?;

            gen_evm_proof::<StepCircuit<eth_types::Mainnet, Fr>>(
                PathBuf::from("./build/sync_step_mainnet.pkey"),
                PathBuf::from("./lightclient-circuits/config/sync_step_mainnet.json"),
                witness,
                None::<PathBuf>,
            )?
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

    let pubkeys = pubkeys.into_iter().collect_vec();

    let commitment = lightclient_circuits::poseidon::poseidon_committee_commitment_from_compressed(
        pubkeys.as_slice(),
    )?;

    Ok(SyncCommitteePoseidonResult { commitment })
}
pub(crate) async fn sync_committee_poseidon_uncompressed_handler(
    Params(params): Params<SyncCommitteePoseidonParams>,
) -> Result<SyncCommitteePoseidonResult, JsonRpcError> {
    let SyncCommitteePoseidonParams { pubkeys } = params;

    let pubkeys = pubkeys.into_iter().collect_vec();

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

pub async fn run_rpc(port: usize) -> Result<(), eyre::Error> {
    let tcp_listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    let rpc_server = Arc::new(jsonrpc_server());

    let router = Router::new()
        .route("/rpc", post(handler))
        .layer(TraceLayer::new_for_http())
        .with_state(rpc_server);

    log::info!("Ready for RPC connections");

    axum::serve(tcp_listener, router.into_make_service())
        .await
        .map_err(|e| eyre::eyre!("RPC server error: {}", e))
}

async fn handler(
    axum::extract::State(rpc_server): axum::extract::State<JsonRpcServerState>,
    axum::Json(rpc_call): axum::Json<JsonRpcRequestObject>,
) -> impl IntoResponse {
    let response_headers = [("content-type", "application/json-rpc;charset=utf-8")];
    log::debug!("RPC request with method: {}", rpc_call.method_ref());

    let response = rpc_server.handle(rpc_call).await;
    let response_str = serde_json::to_string(&response);
    log::debug!("RPC response: {:?}", response_str);
    match response_str {
        Ok(result) => (StatusCode::OK, response_headers, result),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            response_headers,
            err.to_string(),
        ),
    }
}
