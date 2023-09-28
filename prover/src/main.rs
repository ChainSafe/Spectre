#![allow(incomplete_features)]
#![feature(associated_type_bounds)]
use std::{fs, future::Future, path::Path, sync::Arc, net::TcpListener};

use args::{Args, Options, Out, Proof};
use axum::{body::Body, response::{Json, IntoResponse}, routing::post, Router};
use cli_batteries::version;
use ethers::prelude::*;
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use itertools::Itertools;
use jsonrpc_v2::{Data, Error as JsonRpcError, Params, Server as JsonRpcServer, MapRouter as JsonRpcMapRouter};
use lightclient_circuits::{
    committee_update_circuit::CommitteeUpdateCircuit,
    sync_step_circuit::SyncStepCircuit,
    util::{gen_srs, AppCircuit},
};
use preprocessor::{fetch_rotation_args, fetch_step_args};
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::halo2_proofs::{
        plonk::VerifyingKey, poly::kzg::commitment::ParamsKZG,
    },
    system::halo2::Config,
};
use http::{HeaderMap, StatusCode};
use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, read_instances, Snark};
mod args;
use jsonrpc_v2::RequestObject as JsonRpcRequestObject;
pub type JsonRpcServerState = Arc<JsonRpcServer<JsonRpcMapRouter>>;

ethers::contract::abigen!(
    SnarkVerifierSol,
    r#"[
        function verify(uint256[1] calldata pubInputs,bytes calldata proof) public view returns (bool)
    ]"#,
);

// fn main() {
//     cli_batteries::run(version!(), app);
// }
async fn handler(
    axum::extract::State(rpc_server): axum::extract::State<JsonRpcServerState>,
    axum::Json(rpc_call): axum::Json<JsonRpcRequestObject>,
) -> impl IntoResponse {
    let response_headers = [("content-type", "application/json-rpc;charset=utf-8")];
    let response = rpc_server.handle(rpc_call).await;

    let response_str = serde_json::to_string(&response);
    match response_str {
        Ok(result) => (StatusCode::OK, response_headers, result),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            response_headers,
            err.to_string(),
        ),
    }
}

async fn gen_snark_handler(
    Params(params): Params<()>
) -> Result<(), JsonRpcError> {
    Ok(())
}

// async fn generic_circuit_cli<
//     Circuit: AppCircuit,
//     FnFetch: FnOnce(String) -> Fut,
//     Fut: Future<Output = eyre::Result<Circuit::Witness>>,
// >(
//     args: &Args,
//     fetch: FnFetch,
//     name: &str,
//     default_witness: Circuit::Witness,
// ) -> eyre::Result<()> {
//     let k = args
//         .k
//         .unwrap_or_else(|| Circuit::get_degree(&args.config_path));
//     let params = gen_srs(k);
//     let pk_filename = format!("{}.pkey", name);

//     match args.out {
//         Out::Snark => {
//             let pk = Circuit::read_or_create_pk(
//                 &params,
//                 args.build_dir.join(&pk_filename),
//                 &args.config_path,
//                 true,
//                 &default_witness,
//             );
//             let witness = fetch(args.beacon_api_url.clone()).await?;
//             Circuit::gen_snark_shplonk(
//                 &params,
//                 &pk,
//                 &args.config_path,
//                 Some(&args.path_out),
//                 &witness,
//             )
//             .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))?;
//         }
//         Out::Artifacts => {
//             Circuit::create_pk(
//                 &params,
//                 args.build_dir.join(&pk_filename),
//                 &args.config_path,
//                 &default_witness,
//             );
//         }
//         Out::EvmVerifier => {
//             let pk = Circuit::read_or_create_pk(
//                 &params,
//                 args.build_dir.join(&pk_filename),
//                 &args.config_path,
//                 true,
//                 &default_witness,
//             );
//             let deplyment_code = Circuit::gen_evm_verifier_shplonk(
//                 &params,
//                 &pk,
//                 Some(&args.path_out),
//                 &default_witness,
//             )
//             .map_err(|e| eyre::eyre!("Failed to EVM verifier: {}", e))?;
//             println!("yul size: {}", deplyment_code.len());
//             let sol_contract = halo2_solidity_verifier::fix_verifier_sol(args.path_out.clone(), 1)
//                 .map_err(|e| eyre::eyre!("Failed to generate Solidity verifier: {}", e))?;
//             let mut sol_contract_path = args.path_out.clone();
//             sol_contract_path.set_extension("sol");
//             let mut f = File::create(sol_contract_path).unwrap();
//             f.write(sol_contract.as_bytes())
//                 .map_err(|e| eyre::eyre!("Failed to write Solidity verifier: {}", e))?;
//         }
//         Out::Calldata => {
//             let pk = Circuit::read_or_create_pk(
//                 &params,
//                 args.build_dir.join(&pk_filename),
//                 &args.config_path,
//                 true,
//                 &default_witness,
//             );
//             let witness = fetch(args.beacon_api_url.clone()).await?;

//             let deplyment_code =
//                 Circuit::gen_evm_verifier_shplonk(&params, &pk, None::<&Path>, &default_witness)
//                     .map_err(|e| eyre::eyre!("Failed to EVM verifier: {}", e))?;

//             Circuit::gen_calldata(
//                 &params,
//                 &pk,
//                 &args.config_path,
//                 &args.path_out,
//                 Some(deplyment_code),
//                 &witness,
//             )
//             .map_err(|e| eyre::eyre!("Failed to generate calldata: {}", e))?;
//         }
//         Out::Tx => {
//             let provider = Arc::new(Provider::new(Http::new(
//                 args.ethereum_rpc.parse::<url::Url>().unwrap(),
//             )));

//             let pk = Circuit::read_or_create_pk(
//                 &params,
//                 args.build_dir.join(&pk_filename),
//                 &args.config_path,
//                 true,
//                 &default_witness,
//             );
//             let witness = fetch(args.beacon_api_url.clone()).await?;

//             let (proof, instances) = Circuit::gen_evm_proof_shplonk(
//                 &params,
//                 &pk,
//                 &args.config_path,
//                 &args.path_out,
//                 None,
//                 &witness,
//             )
//             .map_err(|e| eyre::eyre!("Failed to generate calldata: {}", e))?;

//             let public_inputs = instances[0]
//                 .iter()
//                 .map(|pi| U256::from_little_endian(&pi.to_bytes()))
//                 .collect_vec()
//                 .try_into()
//                 .unwrap();

//             let contract_addr = Address::from_str(
//                 args.verifier_address
//                     .as_ref()
//                     .expect("verifier address is required"),
//             )
//             .unwrap();
//             let snark_verifier = SnarkVerifierSol::new(contract_addr, provider);

//             let result = snark_verifier
//                 .verify(public_inputs, proof.into())
//                 .await
//                 .unwrap();

//             assert!(result);
//         }
//     }
// }
async fn gen_artifacts_handler(
    Params(params): Params<()>
) -> Result<(), JsonRpcError> {
    Ok(())
}
async fn gen_evm_verifier_handler(
    Params(params): Params<()>
) -> Result<(), JsonRpcError> {
    Ok(())
}
async fn gen_call_data_handler(
    Params(params): Params<()>
) -> Result<(), JsonRpcError> {
    Ok(())
}
#[tokio::main]
async fn main() {
    let tcp_listener = TcpListener::bind("0.0.0.0:3000").unwrap();
    let rpc_server = Arc::new(
        JsonRpcServer::new()
            // .with_data(Data(state))
            .with_method("genSnark", gen_snark_handler)
            .with_method("genArtifacts", gen_artifacts_handler)
            .with_method("genEvmVerifier", gen_evm_verifier_handler)
            .with_method("genCallData", gen_call_data_handler)
            .finish_unwrapped(),
    );
    let router = Router::new()
        .route("/rpc", post(handler))
        .with_state(rpc_server);

        // log::info!("Ready for RPC connections");
        let server = axum::Server::from_tcp(tcp_listener).unwrap().serve(router.into_make_service());
        server.await.unwrap();
    
        // info!("Stopped accepting RPC connections");
    
        // Ok(())
}
