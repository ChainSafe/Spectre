#![allow(incomplete_features)]
#![feature(associated_type_bounds)]
#![feature(generic_const_exprs)]
mod cli;
mod rpc;
mod rpc_api;
pub mod rpc_client;

use args::Cli;
use axum::{response::IntoResponse, routing::post, Router};
use beacon_api_client::{mainnet::MainnetClientTypes, minimal::MinimalClientTypes};
use cli_batteries::version;

use http::StatusCode;
use jsonrpc_v2::{MapRouter as JsonRpcMapRouter, Server as JsonRpcServer};

use crate::{cli::spec_app, rpc::jsonrpc_server};

use std::{net::TcpListener, sync::Arc};
mod args;
use jsonrpc_v2::RequestObject as JsonRpcRequestObject;

use crate::args::RpcOptions;
pub type JsonRpcServerState = Arc<JsonRpcServer<JsonRpcMapRouter>>;

async fn app(options: Cli) -> eyre::Result<()> {
    match options.subcommand {
        args::Subcommands::Rpc(op) => {
            let RpcOptions { port } = op;

            let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", port)).unwrap();
            let rpc_server = Arc::new(jsonrpc_server());
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
            args::Spec::Minimal => spec_app::<eth_types::Minimal, MinimalClientTypes>(&op.proof)
                .await
                .unwrap(),
            args::Spec::Testnet => spec_app::<eth_types::Testnet, MainnetClientTypes>(&op.proof)
                .await
                .unwrap(),
            args::Spec::Mainnet => spec_app::<eth_types::Testnet, MainnetClientTypes>(&op.proof)
                .await
                .unwrap(),
        },
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
