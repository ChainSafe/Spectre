#![allow(incomplete_features)]
#![feature(associated_type_bounds)]
mod rpc;
use args::{Args, Cli, Out, Proof};
use axum::{response::IntoResponse, routing::post, Router};
use cli_batteries::version;
use ethers::prelude::*;
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use http::StatusCode;
use itertools::Itertools;
use jsonrpc_v2::{MapRouter as JsonRpcMapRouter, Server as JsonRpcServer};
use lightclient_circuits::{
    committee_update_circuit::CommitteeUpdateCircuit,
    sync_step_circuit::SyncStepCircuit,
    util::{gen_srs, AppCircuit},
};
use preprocessor::{fetch_rotation_args, fetch_step_args};
use rpc::{gen_evm_proof_rotation_circuit_handler, gen_evm_proof_step_circuit_handler};

use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::halo2_proofs::{
        plonk::VerifyingKey, poly::kzg::commitment::ParamsKZG,
    },
    system::halo2::Config,
};
use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, read_instances, Snark};
use std::str::FromStr;
use std::{
    fs::{self, File},
    future::Future,
    io::Write,
    net::TcpListener,
    path::Path,
    sync::Arc,
};
mod args;
use jsonrpc_v2::RequestObject as JsonRpcRequestObject;

use crate::args::RpcOptions;
pub type JsonRpcServerState = Arc<JsonRpcServer<JsonRpcMapRouter>>;

ethers::contract::abigen!(
    SnarkVerifierSol,
    r#"[
        function verify(uint256[1] calldata pubInputs,bytes calldata proof) public view returns (bool)
    ]"#,
);

async fn app(options: Cli) -> eyre::Result<()> {
    match options.subcommand {
        args::Subcommands::Rpc(op) => {
            let RpcOptions { port } = op;

            let tcp_listener = TcpListener::bind(&format!("0.0.0.0:{}", port)).unwrap();
            let rpc_server = Arc::new(
                JsonRpcServer::new()
                    .with_method(
                        "genEvmProofAndInstancesStepSyncCircuit",
                        gen_evm_proof_step_circuit_handler,
                    )
                    .with_method(
                        "genEvmProofAndInstancesRotationCircuit",
                        gen_evm_proof_rotation_circuit_handler,
                    )
                    .finish_unwrapped(),
            );
            let router = Router::new()
                .route("/rpc", post(handler))
                .with_state(rpc_server);

            log::info!("Ready for RPC connections");
            let server = axum::Server::from_tcp(tcp_listener)
                .unwrap()
                .serve(router.into_make_service());
            server.await.unwrap();

            log::info!("Stopped accepting RPC connections");
        }
        args::Subcommands::Circuit(op) => match op.spec {
            args::Spec::Minimal => spec_app::<eth_types::Minimal>(&op.proof).await.unwrap(),
            args::Spec::Testnet => spec_app::<eth_types::Testnet>(&op.proof).await.unwrap(),
            args::Spec::Mainnet => spec_app::<eth_types::Testnet>(&op.proof).await.unwrap(),
        },
    }
    Ok(())
}

async fn spec_app<S: eth_types::Spec>(proof: &Proof) -> eyre::Result<()> {
    match proof {
        Proof::CommitteeUpdate(args) => {
            generic_circuit_cli::<CommitteeUpdateCircuit<S, Fr>, _, _>(
                args,
                fetch_rotation_args,
                "committee_update",
                <CommitteeUpdateCircuit<S, Fr> as AppCircuit>::Witness::default(),
            )
            .await
        }
        Proof::SyncStep(args) => {
            generic_circuit_cli::<SyncStepCircuit<S, Fr>, _, _>(
                args,
                fetch_step_args,
                "sync_step",
                <SyncStepCircuit<S, Fr> as AppCircuit>::Witness::default(),
            )
            .await
        }
        Proof::Aggregation(args) => {
            let params = gen_srs(CommitteeUpdateCircuit::<S, Fr>::get_degree(
                &args.app_config_path,
            ));

            let app_pk = CommitteeUpdateCircuit::<S, Fr>::read_pk(
                &params,
                &args.app_pk_path,
                &<CommitteeUpdateCircuit<S, Fr> as AppCircuit>::Witness::default(),
            );

            let snark = read_snark(
                &params,
                app_pk.get_vk(),
                args.aggregation
                    .input_path
                    .as_ref()
                    .expect("path to SNARK is required"),
            )?;

            generic_circuit_cli::<AggregationCircuit, _, _>(
                &args.aggregation,
                |_| async { Ok(vec![snark.clone()]) },
                "aggregation",
                vec![snark.clone()],
            )
            .await
        }
    }
}

async fn generic_circuit_cli<
    Circuit: AppCircuit,
    FnFetch: FnOnce(String) -> Fut,
    Fut: Future<Output = eyre::Result<Circuit::Witness>>,
>(
    args: &Args,
    fetch: FnFetch,
    name: &str,
    default_witness: Circuit::Witness,
) -> eyre::Result<()> {
    let k = args
        .k
        .unwrap_or_else(|| Circuit::get_degree(&args.config_path));
    let params = gen_srs(k);
    let pk_filename = format!("{}.pkey", name);

    match args.out {
        Out::Snark => {
            let pk = Circuit::read_or_create_pk(
                &params,
                args.build_dir.join(&pk_filename),
                &args.config_path,
                true,
                &default_witness,
            );
            let witness = fetch(args.beacon_api_url.clone()).await?;
            Circuit::gen_snark_shplonk(
                &params,
                &pk,
                &args.config_path,
                Some(&args.path_out),
                &witness,
            )
            .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))?;
        }
        Out::Artifacts => {
            Circuit::create_pk(
                &params,
                args.build_dir.join(&pk_filename),
                &args.config_path,
                &default_witness,
            );
        }
        Out::EvmVerifier => {
            let pk = Circuit::read_or_create_pk(
                &params,
                args.build_dir.join(&pk_filename),
                &args.config_path,
                true,
                &default_witness,
            );
            let deplyment_code = Circuit::gen_evm_verifier_shplonk(
                &params,
                &pk,
                Some(&args.path_out),
                &default_witness,
            )
            .map_err(|e| eyre::eyre!("Failed to EVM verifier: {}", e))?;
            println!("yul size: {}", deplyment_code.len());
            let sol_contract = halo2_solidity_verifier::fix_verifier_sol(args.path_out.clone(), 1)
                .map_err(|e| eyre::eyre!("Failed to generate Solidity verifier: {}", e))?;
            let mut sol_contract_path = args.path_out.clone();
            sol_contract_path.set_extension("sol");
            let mut f = File::create(sol_contract_path).unwrap();
            f.write(sol_contract.as_bytes())
                .map_err(|e| eyre::eyre!("Failed to write Solidity verifier: {}", e))?;
        }
        Out::Calldata => {
            let pk = Circuit::read_or_create_pk(
                &params,
                args.build_dir.join(&pk_filename),
                &args.config_path,
                true,
                &default_witness,
            );
            let witness = fetch(args.beacon_api_url.clone()).await?;

            let deplyment_code =
                Circuit::gen_evm_verifier_shplonk(&params, &pk, None::<&Path>, &default_witness)
                    .map_err(|e| eyre::eyre!("Failed to EVM verifier: {}", e))?;

            Circuit::gen_calldata(
                &params,
                &pk,
                &args.config_path,
                &args.path_out,
                Some(deplyment_code),
                &witness,
            )
            .map_err(|e| eyre::eyre!("Failed to generate calldata: {}", e))?;
        }
        Out::Tx => {
            let provider = Arc::new(Provider::new(Http::new(
                args.ethereum_rpc.parse::<url::Url>().unwrap(),
            )));

            let pk = Circuit::read_or_create_pk(
                &params,
                args.build_dir.join(&pk_filename),
                &args.config_path,
                true,
                &default_witness,
            );
            let witness = fetch(args.beacon_api_url.clone()).await?;

            let (proof, instances) = Circuit::gen_evm_proof_shplonk(
                &params,
                &pk,
                &args.config_path,
                &args.path_out,
                None,
                &witness,
            )
            .map_err(|e| eyre::eyre!("Failed to generate calldata: {}", e))?;

            let public_inputs = instances[0]
                .iter()
                .map(|pi| U256::from_little_endian(&pi.to_bytes()))
                .collect_vec()
                .try_into()
                .unwrap();

            let contract_addr = Address::from_str(
                args.verifier_address
                    .as_ref()
                    .expect("verifier address is required"),
            )
            .unwrap();
            let snark_verifier = SnarkVerifierSol::new(contract_addr, provider);

            let result = snark_verifier
                .verify(public_inputs, proof.into())
                .await
                .unwrap();

            assert!(result);
        }
    }
    Ok(())
}

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

fn main() {
    cli_batteries::run(version!(), app);
}

fn read_snark(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    path: &Path,
) -> eyre::Result<Snark> {
    let path_str = path.to_str().unwrap();

    let proof = fs::read(format!("{path_str}.proof"))
        .map_err(|e| eyre::eyre!("Error reading proof file: {}", e))?;
    let instances = read_instances(format!("{path_str}.instances"))
        .map_err(|e| eyre::eyre!("Error reading instances file: {}", e))?;

    let protocol = snark_verifier::system::halo2::compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(instances.iter().map(|i| i.len()).collect())
            .with_accumulator_indices(None), // FIXME: use <C: CircuitExt<Fr>>::accumulator_indices()
    );

    Ok(Snark {
        protocol,
        proof,
        instances,
    })
}
