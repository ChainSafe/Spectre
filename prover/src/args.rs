use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use strum::EnumString;

#[derive(Clone, clap::Parser)]
#[command(name = "spectre-prover")]
#[command(about = "Spectre prover", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Subcommands,
}
#[derive(Clone, clap::Parser)]
#[allow(clippy::large_enum_variant)]
pub enum Subcommands {
    Rpc,
    Circuit(CircuitOptions),
}

#[derive(Clone, clap::Parser)]
pub struct CircuitOptions {
    #[command(subcommand)]
    pub proof: Proof,

    #[clap(long, short, default_value = "mainnet")]
    pub spec: Spec,
}

#[derive(Clone, clap::Subcommand)]
pub enum Proof {
    CommitteeUpdate(Args),
    SyncStep(Args),
    Aggregation(AggregationArgs),
}

#[derive(Clone, clap::Args)]
pub struct Args {
    #[clap(long, short, default_value = "snark")]
    pub out: Out,

    #[clap(long, short)]
    pub k: Option<u32>,

    #[clap(
        long,
        short,
        default_value = "./lightclient-circuits/config/sync_step.json"
    )]
    pub config_path: PathBuf,

    #[clap(long, short, default_value = "./build")]
    pub build_dir: PathBuf,

    #[clap(long, short)]
    pub input_path: Option<PathBuf>,

    #[clap(
        long,
        short = 'n',
        help = "Beacon node URL",
        default_value = "http://127.0.0.1:5052"
    )]
    pub beacon_api_url: String,

    #[clap(
        long,
        short,
        help = "Ethereum RPC",
        default_value = "http://127.0.0.1:8545"
    )]
    pub ethereum_rpc: String,

    #[clap(long, short)]
    pub verifier_address: Option<String>,

    #[clap(index = 1, help = "path to output", default_value = ".")]
    pub path_out: PathBuf,
}

#[derive(Clone, clap::Args)]
pub struct AggregationArgs {
    #[clap(flatten)]
    pub aggregation: Args,

    #[clap(long)]
    pub app_pk_path: PathBuf,

    #[clap(long)]
    pub app_config_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, EnumString)]
pub enum Out {
    #[strum(serialize = "snark")]
    Snark,
    #[strum(serialize = "artifacts")]
    Artifacts,
    #[strum(serialize = "evm-verifier")]
    EvmVerifier,
    #[strum(serialize = "calldata")]
    Calldata,
    #[strum(serialize = "tx")]
    Tx,
}

#[derive(Clone, Debug, PartialEq, EnumString, Serialize, Deserialize)]
pub enum Spec {
    #[strum(serialize = "minimal")]
    Minimal,
    #[strum(serialize = "testnet")]
    Testnet,
    #[strum(serialize = "mainnet")]
    Mainnet,
}
