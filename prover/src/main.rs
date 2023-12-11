#![allow(incomplete_features)]
#![feature(associated_type_bounds)]
#![feature(generic_const_exprs)]
mod cli;
mod rpc;
mod rpc_api;
pub mod rpc_client;
mod utils;

use crate::{cli::spec_app, rpc::run_rpc};
use args::Cli;
use cli_batteries::version;
use utils::utils_cli;

mod args;

async fn app(options: Cli) -> eyre::Result<()> {
    match options.subcommand {
        args::BaseCmd::Rpc { port } => {
            run_rpc(port.parse().unwrap()).await?;

            log::info!("Stopped accepting RPC connections");

            Ok(())
        }
        args::BaseCmd::Circuit { proof, spec } => match spec {
            args::Spec::Minimal => spec_app::<eth_types::Minimal>(proof, &options.args).await,
            args::Spec::Testnet => spec_app::<eth_types::Testnet>(proof, &options.args).await,
            args::Spec::Mainnet => spec_app::<eth_types::Mainnet>(proof, &options.args).await,
        },
        args::BaseCmd::Utils { method } => utils_cli(method).await,
    }
}

fn main() {
    cli_batteries::run(version!(), app);
}
