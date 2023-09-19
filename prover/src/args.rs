use std::path::PathBuf;

use strum::EnumString;

#[derive(Clone, clap::Parser)]
pub struct Options {
    #[command(subcommand)]
    pub proof: Proof,

    #[clap(long, short, default_value = "mainnet")]
    pub spec: Spec,
}

#[derive(Clone, clap::Subcommand)]
pub enum Proof {
    CommitteeUpdate(Args),
    SyncStep(Args),
}

#[derive(Clone, clap::Args)]
pub struct Args {
    #[clap(long, short, default_value = "proof")]
    pub out: Out,

    #[clap(
        long,
        short,
        default_value = "./lightclient-circuits/config/sync_step.json"
    )]
    pub config_path: PathBuf,

    #[clap(long, short, default_value = "./build")]
    pub build_dir: PathBuf,

    #[clap(long, short, default_value = "./sync_state.json")]
    pub input_path: PathBuf,

    #[clap(index = 1, help = "path to output", default_value = ".")]
    pub path_out: PathBuf,

    #[clap(index = 1, help = "Beacon node URL", default_value = "http://localhost::5052")]
    pub node_url: String,
}


#[derive(Clone, Debug, PartialEq, EnumString)]
pub enum Out {
    #[strum(serialize = "proof")]
    Proof,
    #[strum(serialize = "artifacts")]
    Artifacts,
    #[strum(serialize = "evm-verifier")]
    EvmVerifier,
    #[strum(serialize = "calldata")]
    Calldata,
}

#[derive(Clone, Debug, PartialEq, EnumString)]
pub enum Spec {
    #[strum(serialize = "minimal")]
    Minimal,
    #[strum(serialize = "testnet")]
    Testnet,
    #[strum(serialize = "mainnet")]
    Mainnet,
}
