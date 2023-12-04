#![allow(incomplete_features)]
#![feature(associated_type_bounds)]
#![feature(generic_const_exprs)]
mod cli;
mod rpc;
mod rpc_api;
pub mod rpc_client;

use crate::args::RpcOptions;
use crate::{cli::spec_app, rpc::run_rpc};
use args::Cli;
use cli_batteries::version;

mod args;

async fn app(options: Cli) -> eyre::Result<()> {
    match options.subcommand {
        args::BaseCmd::Rpc(op) => {
            let RpcOptions { port } = op;

            run_rpc(port.parse().unwrap()).await.unwrap();

            log::info!("Stopped accepting RPC connections");
        }
        args::BaseCmd::Circuit(op) => match op.spec {
            args::Spec::Minimal => spec_app::<eth_types::Minimal>(op.proof, &options.args)
                .await
                .unwrap(),
            args::Spec::Testnet => spec_app::<eth_types::Testnet>(op.proof, &options.args)
                .await
                .unwrap(),
            args::Spec::Mainnet => spec_app::<eth_types::Mainnet>(op.proof, &options.args)
                .await
                .unwrap(),
        },
    }
    Ok(())
}

fn main() {
    cli_batteries::run(version!(), app);
}
