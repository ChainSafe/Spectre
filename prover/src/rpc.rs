use super::{args, args::Spec};

use ethers::prelude::*;
use halo2curves::bn256::Fr;

use jsonrpc_v2::{Error as JsonRpcError, Params};
use lightclient_circuits::{
    committee_update_circuit::CommitteeUpdateCircuit,
    sync_step_circuit::SyncStepCircuit,
    util::{gen_srs, AppCircuit},
};
use preprocessor::{fetch_rotation_args, fetch_step_args};
use serde::{Deserialize, Serialize};

use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, Snark};

use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofRotationParams {
    spec: args::Spec,

    k: Option<u32>,
    #[serde(default = "default_beacon_api")]
    beacon_api: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofStepParams {
    spec: args::Spec,

    k: Option<u32>,
    #[serde(default = "default_beacon_api")]
    beacon_api: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmProofResult {
    proof: Vec<u8>,
    public_inputs: Vec<U256>,
}

fn default_beacon_api() -> String {
    String::from("http://127.0.0.1:5052")
}

fn gen_app_snark<S: eth_types::Spec>(
    app_config_path: PathBuf,
    app_pk_path: PathBuf,
    witness: <CommitteeUpdateCircuit<S, Fr> as AppCircuit>::Witness,
) -> eyre::Result<Snark> {
    let params = gen_srs(CommitteeUpdateCircuit::<S, Fr>::get_degree(
        &app_config_path,
    ));

    let app_pk = CommitteeUpdateCircuit::<S, Fr>::read_pk(
        &params,
        app_pk_path,
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
    path_out: PathBuf,
    witness: C::Witness,
    default_witness: C::Witness,
) -> (Vec<u8>, Vec<Vec<Fr>>) {
    let k = k.unwrap_or_else(|| C::get_degree(&config_path));
    let params = gen_srs(k);

    let pk = C::read_or_create_pk(
        &params,
        build_dir.join(pk_filename),
        &config_path,
        true,
        &default_witness,
    );

    let (proof, instances) =
        C::gen_evm_proof_shplonk(&params, &pk, &config_path, path_out, None, &witness)
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

    let app_config_path = PathBuf::from("./lightclient-circuits/config/committee_update.json");
    let app_pk_path = PathBuf::from("./build/committee_update_circuit.pkey");

    let config_path =
        PathBuf::from("./lightclient-circuits/config/committee_update_aggregation.json");
    let build_dir = PathBuf::from("./build");
    let path_out = PathBuf::from(".");

    let (snark, pk_filename) = match spec {
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
    let (proof, instances) = gen_evm_proof::<AggregationCircuit>(
        k,
        build_dir,
        pk_filename.to_string(),
        config_path,
        path_out,
        vec![snark.clone()],
        vec![snark],
    );

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

    let config_path = PathBuf::from("./lightclient-circuits/config/step_sync.json");
    let build_dir = PathBuf::from("./build");
    let path_out = PathBuf::from(".");

    let (proof, instances) = match spec {
        Spec::Minimal => {
            let pk_filename = format!("step_circuit_minimal.pkey");
            let witness = fetch_step_args(beacon_api).await.unwrap();
            gen_evm_proof::<SyncStepCircuit<eth_types::Minimal, Fr>>(
                k,
                build_dir,
                pk_filename,
                config_path,
                path_out,
                witness,
                Default::default(),
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
                path_out,
                witness,
                Default::default(),
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
                path_out,
                witness,
                Default::default(),
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
