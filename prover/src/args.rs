use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use strum::EnumString;

#[derive(Clone, clap::Parser)]
#[command(name = "spectre-prover")]
#[command(about = "Spectre prover", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: BaseCmd,

    #[clap(flatten)]
    pub args: BaseArgs,
}

#[derive(Clone, clap::Args)]
pub struct BaseArgs {
    #[clap(long, short, default_value = "./lightclient-circuits/config")]
    pub config_dir: PathBuf,
}

#[derive(Clone, clap::Parser)]
#[allow(clippy::large_enum_variant)]
pub enum BaseCmd {
    Rpc(RpcOptions),
    Circuit(CircuitOptions),
}
#[derive(Clone, clap::Parser)]
pub struct RpcOptions {
    #[clap(long, short, default_value = "3000")]
    pub port: String,
}

#[derive(Clone, clap::Parser)]
pub struct CircuitOptions {
    #[command(subcommand)]
    pub proof: ProofCmd,

    #[clap(long, short, default_value = "mainnet")]
    pub spec: Spec,
}

#[derive(Clone, clap::Subcommand)]
pub enum ProofCmd {
    InputCommittee {
        #[clap(long, short)]
        beacon_api: String,
    },
    SyncStep {
        #[command(subcommand)]
        operation: OperationCmd,

        #[clap(long, short, default_value = "22")]
        k: u32,

        #[clap(long, short)]
        pk_path: PathBuf,
    },
    CommitteeUpdate {
        #[command(subcommand)]
        operation: OperationCmd,

        #[clap(long, short, default_value = "18")]
        k: u32,

        #[clap(long, short)]
        pk_path: PathBuf,

        #[clap(long, default_value = "25")]
        verifier_k: u32,

        #[clap(long)]
        verifier_pk_path: PathBuf,
    },
}

#[derive(Clone, clap::Subcommand)]
pub enum OperationCmd {
    Setup,
    GenVerifier {
        #[clap(long, short = 'o')]
        solidity_out: PathBuf,

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
