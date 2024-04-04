// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use ark_std::{end_timer, start_timer};
use axum::{http::StatusCode, response::IntoResponse, routing::post, Router};
use ethereum_types::{
    EthSpec, FixedVector, ForkName, LightClientFinalityUpdate, LightClientUpdate, PublicKeyBytes,
};
use ethers::prelude::*;
use jsonrpc_v2::{Data, RequestObject as JsonRpcRequestObject};
use jsonrpc_v2::{Error as JsonRpcError, Params};
use jsonrpc_v2::{MapRouter as JsonRpcMapRouter, Server as JsonRpcServer};
use lightclient_circuits::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use lightclient_circuits::halo2_proofs::plonk::ProvingKey;
use lightclient_circuits::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use lightclient_circuits::sync_step_circuit::StepCircuit;
use lightclient_circuits::{committee_update_circuit::CommitteeUpdateCircuit, util::AppCircuit};
use preprocessor::{rotation_args_from_update, step_args_from_finality_update};
use snark_verifier_sdk::evm::encode_calldata;
use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, Snark};
use spectre_prover::prover::ProverState;
use ssz::Decode;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

pub type JsonRpcServerState = Arc<JsonRpcServer<JsonRpcMapRouter>>;
use crate::rpc_api::{
    CommitteeUpdateEvmProofResult, GenProofCommitteeUpdateParams, GenProofStepParams,
    SyncStepCompressedEvmProofResult, RPC_EVM_PROOF_COMMITTEE_UPDATE_CIRCUIT_COMPRESSED,
    RPC_EVM_PROOF_STEP_CIRCUIT_COMPRESSED,
};

pub(crate) fn jsonrpc_server<S: eth_types::Spec>(
    state: ProverState,
) -> JsonRpcServer<JsonRpcMapRouter>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::SYNC_COMMITTEE_ROOT_INDEX]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::FINALIZED_HEADER_INDEX]:,
{
    JsonRpcServer::new()
        .with_data(Data::new(state))
        .with_method(
            RPC_EVM_PROOF_COMMITTEE_UPDATE_CIRCUIT_COMPRESSED,
            gen_evm_proof_committee_update_handler::<S>,
        )
        .with_method(
            RPC_EVM_PROOF_STEP_CIRCUIT_COMPRESSED,
            gen_evm_proof_sync_step_compressed_handler::<S>,
        )
        .finish_unwrapped()
}

pub(crate) async fn gen_evm_proof_committee_update_handler<S: eth_types::Spec>(
    Data(state): Data<ProverState>,
    Params(params): Params<GenProofCommitteeUpdateParams>,
) -> Result<CommitteeUpdateEvmProofResult, JsonRpcError>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::SYNC_COMMITTEE_ROOT_INDEX]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::FINALIZED_HEADER_INDEX]:,
{
    let _permit = state
        .concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| {
            JsonRpcError::internal(format!("Failed to acquire concurrency lock: {}", e))
        })?;

    let GenProofCommitteeUpdateParams {
        light_client_update,
        fork_name,
    } = params;

    let fork_name = ForkName::from_str(&fork_name)
        .map_err(|e| JsonRpcError::internal(format!("Failed to parse fork version: {}", e)))?;

    let update = LightClientUpdate::<S::EthSpec>::from_ssz_bytes(&light_client_update, fork_name)
        .map_err(|e| {
        JsonRpcError::internal(format!(
            "Failed to deserialize light client update: {:?}",
            e
        ))
    })?;
    let witness = rotation_args_from_update(&update).await?;
    let params = state.params.get(state.committee_update.degree()).unwrap();

    let snark = gen_uncompressed_snark::<CommitteeUpdateCircuit<S, Fr>>(
        state.committee_update.config_path(),
        params,
        state.committee_update.pk(),
        witness,
    )?;

    let (proof, instances) = AggregationCircuit::gen_evm_proof_shplonk(
        state
            .params
            .get(state.committee_update_verifier.degree())
            .unwrap(),
        state.committee_update_verifier.pk(),
        state.committee_update_verifier.config_path(),
        None,
        &vec![snark],
    )
    .map_err(JsonRpcError::internal)?;

    let calldata = encode_calldata(&instances, &proof);

    let committee_poseidon = U256::from_little_endian(&instances[0][12].to_bytes());

    Ok(CommitteeUpdateEvmProofResult {
        proof: calldata,
        committee_poseidon,
    })
}

pub(crate) async fn gen_evm_proof_sync_step_compressed_handler<S: eth_types::Spec>(
    Data(state): Data<ProverState>,
    Params(params): Params<GenProofStepParams>,
) -> Result<SyncStepCompressedEvmProofResult, JsonRpcError>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
{
    let _permit = state
        .concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| {
            JsonRpcError::internal(format!("Failed to acquire concurrency lock: {}", e))
        })?;

    let GenProofStepParams {
        light_client_finality_update,
        domain,
        pubkeys,
        fork_name,
    } = params;

    let fork_name = ForkName::from_str(&fork_name)
        .map_err(|e| JsonRpcError::internal(format!("Failed to parse fork version: {}", e)))?;

    let update = LightClientFinalityUpdate::<S::EthSpec>::from_ssz_bytes(
        &light_client_finality_update,
        fork_name,
    )
    .map_err(|e| {
        JsonRpcError::internal(format!(
            "Failed to deserialize light client finality update: {:?}",
            e
        ))
    })?;
    let pubkeys =
        FixedVector::<PublicKeyBytes, <S::EthSpec as EthSpec>::SyncCommitteeSize>::from_ssz_bytes(
            &pubkeys,
        )
        .map_err(|e| JsonRpcError::internal(format!("Failed to deserialize pubkeys: {:?}", e)))?;
    let witness = step_args_from_finality_update(update, &pubkeys, domain).await?;
    let params = state.params.get(state.step.degree()).unwrap();

    let snark = gen_uncompressed_snark::<StepCircuit<S, Fr>>(
        state.step.config_path(),
        params,
        state.step.pk(),
        witness,
    )?;

    let (proof, instances) = AggregationCircuit::gen_evm_proof_shplonk(
        state.params.get(state.step_verifier.degree()).unwrap(),
        state.step_verifier.pk(),
        state.step_verifier.config_path(),
        None,
        &vec![snark],
    )
    .map_err(JsonRpcError::internal)?;

    let calldata = encode_calldata(&instances, &proof);

    Ok(SyncStepCompressedEvmProofResult { proof: calldata })
}

fn gen_uncompressed_snark<Circuit: AppCircuit>(
    config_path: &Path,
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    witness: Circuit::Witness,
) -> eyre::Result<Snark>
where
    Circuit::Witness: Default,
{
    Ok(Circuit::gen_snark_shplonk(
        params,
        pk,
        config_path,
        None::<PathBuf>,
        &witness,
    )?)
}

pub async fn run_rpc<S: eth_types::Spec>(
    port: usize,
    config_dir: impl AsRef<Path>,
    build_dir: impl AsRef<Path>,
    concurrency: usize,
) -> Result<(), eyre::Error>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::SYNC_COMMITTEE_ROOT_INDEX]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::FINALIZED_HEADER_INDEX]:,
{
    let tcp_listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    let timer = start_timer!(|| "Load Prover State and Context");
    let state = ProverState::new::<S>(config_dir.as_ref(), build_dir.as_ref(), concurrency);
    end_timer!(timer);
    let rpc_server = Arc::new(jsonrpc_server::<S>(state));
    let router = Router::new()
        .route("/rpc", post(handler))
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
