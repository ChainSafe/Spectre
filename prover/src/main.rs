// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

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
use clap::Parser;
use utils::utils_cli;
mod args;

async fn app(options: Cli) -> eyre::Result<()> {
    match options.subcommand {
        args::BaseCmd::Rpc {
            port,
            spec,
            build_dir,
            concurrency,
        } => {
            match spec {
                args::Spec::Testnet => {
                    run_rpc::<eth_types::Testnet>(
                        port.parse().unwrap(),
                        options.args.config_dir,
                        build_dir,
                        concurrency,
                    )
                    .await
                }
                args::Spec::Mainnet => {
                    run_rpc::<eth_types::Mainnet>(
                        port.parse().unwrap(),
                        options.args.config_dir,
                        build_dir,
                        concurrency,
                    )
                    .await
                }
                args::Spec::Minimal => Err(eyre::eyre!("Minimal spec is not supported for RPC")),
            }?;

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

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    tracing_subscriber::fmt::init();
    app(args).await.unwrap();
}
