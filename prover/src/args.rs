// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use strum::EnumString;

#[derive(Clone, clap::Parser)]
#[command(name = "spectre-prover")]
#[command(
    about = "Spectre prover",
    long_about = "Spectre is a Zero-Knowledge (ZK) coprocessor designed to offload intensive verification of block headers via Altair lightclient protocol.
"
)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: BaseCmd,

    #[clap(flatten)]
    pub args: BaseArgs,
}

#[derive(Clone, clap::Args)]
pub struct BaseArgs {
    /// Path to config directory
    #[clap(long, short, default_value = "./lightclient-circuits/config")]
    pub config_dir: PathBuf,
}

#[derive(Clone, clap::Parser)]
#[allow(clippy::large_enum_variant)]
pub enum BaseCmd {
    /// Deploy prover RPC server.
    Rpc {
        /// Port for RPC server to listen on
        #[clap(long, short, default_value = "3000")]
        port: String,

        /// Network specification [mainnet, testnet]
        #[clap(long, short, default_value = "mainnet")]
        spec: Spec,

        /// Path to directory with circuit artifacts
        #[clap(long, short, default_value = "./build")]
        build_dir: PathBuf,

        /// How many proofs can be run at the same tome
        #[clap(long, short, default_value = "1")]
        concurrency: usize,
    },
    /// Circuit related commands.
    Circuit {
        #[command(subcommand)]
        proof: ProofCmd,

        /// Network spec
        #[clap(long, short, default_value = "mainnet")]
        spec: Spec,
    },
    /// Misc utility commands.
    Utils {
        #[command(subcommand)]
        method: UtilsCmd,
    },
}

#[derive(Clone, clap::Subcommand)]
pub enum ProofCmd {
    /// Step circuit - verifies Beacon chain block header and the execution payload.
    SyncStep {
        #[command(subcommand)]
        operation: OperationCmd,

        /// Circuit degree
        #[clap(long, short, default_value = "22")]
        k: u32,

        /// Path to prover key
        #[clap(long, short)]
        pk_path: PathBuf,
    },
    /// Step circuit (compressed) - verifies Beacon chain block header and the execution payload. Uses aggregation to reduce verifier cost.
    SyncStepCompressed {
        #[command(subcommand)]
        operation: OperationCmd,

        /// Circuit degree (first stage)
        #[clap(long, short, default_value = "20")]
        k: u32,

        /// Path to prover key (first stage)
        #[clap(long, short)]
        pk_path: PathBuf,

        /// Circuit degree (compression stage)
        #[clap(short = 'K', long, default_value = "23")]
        verifier_k: u32,

        /// Path to prover key (compression stage)
        #[clap(short = 'P', long)]
        verifier_pk_path: PathBuf,

        /// Number of lookup bits (compression stage)
        #[clap(short = 'L', long)]
        verifier_lookup_bits: Option<usize>,
    },
    /// Committee update circuit (compressed) - maps next sync committee root to the Poseidon commitment. Uses aggregation to reduce verifier cost.
    CommitteeUpdate {
        #[command(subcommand)]
        operation: OperationCmd,

        /// Circuit degree (first stage)
        #[clap(long, short, default_value = "20")]
        k: u32,

        /// Path to prover key (first stage)
        #[clap(long, short)]
        pk_path: PathBuf,

        /// Circuit degree (compression stage)
        #[clap(short = 'K', long, default_value = "24")]
        verifier_k: u32,

        /// Path to prover key (compression stage)
        #[clap(short = 'P', long)]
        verifier_pk_path: PathBuf,

        /// Number of lookup bits (compression stage)
        #[clap(short = 'L', long)]
        verifier_lookup_bits: Option<usize>,
    },
}

#[derive(Clone, clap::Subcommand)]
pub enum OperationCmd {
    /// Generate prover and verifier keys
    Setup,
    /// Generate Solidity verifier contract
    GenVerifier {
        /// Path to generedated Solidity contract
        #[clap(long, short = 'o')]
        solidity_out: PathBuf,

        /// Flag whether to estimate gas
        #[clap(long, short)]
        estimate_gas: bool,
    },
}

#[derive(Clone, Debug, PartialEq, EnumString, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Spec {
    #[strum(serialize = "minimal")]
    Minimal,
    #[strum(serialize = "testnet")]
    Testnet,
    #[strum(serialize = "mainnet")]
    Mainnet,
}

#[derive(Clone, clap::Subcommand)]
pub enum UtilsCmd {
    /// Get `INITIAL_SYNC_PERIOD`, `INITIAL_COMMITTEE_POSEIDON` for contracts deployment.
    CommitteePoseidon {
        /// Beacon API URL
        #[clap(long, short)]
        beacon_api: String,
    },
}
