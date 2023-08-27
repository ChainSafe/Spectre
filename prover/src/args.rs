use std::path::PathBuf;

use strum::EnumString;

#[derive(Clone, clap::Parser)]
pub struct Options {
    #[command(subcommand)]
    pub proof: Proof,
}

#[derive(Clone, clap::Subcommand)]
pub enum Proof {
    CommitteeUpdate(CommitteeUpdateArgs),
    SyncStep(SyncStepArgs),
}

#[derive(Clone, clap::Args)]
pub struct SyncStepArgs {
    #[clap(long, short, default_value = "proof")]
    pub out: Out,

    #[clap(long, short, default_value = "./ligthclient-circuits/config/sync_step.json")]
    pub config_path: PathBuf,

    #[clap(long, short, default_value = "./build")]
    pub build_dir: PathBuf,

    #[clap(long, short, default_value = "./sync_state.json")]
    pub input_path: PathBuf,
    
    #[clap(index = 1, help = "path to output", default_value = ".")]
    pub path_out: PathBuf, 
}


#[derive(Clone, clap::Args)]
pub struct CommitteeUpdateArgs {
    #[clap(long, short, default_value = "proof")]
    pub out: Out,

    #[clap(long, short, default_value = "./ligthclient-circuits/config/committee_update.json")]
    pub config_path: PathBuf,

    #[clap(long, short, default_value = "./build")]
    pub build_dir: PathBuf,

    #[clap(long, short, default_value = "./sync_state.json")]
    pub input_path: PathBuf,
    
    #[clap(index = 1, help = "path to output", default_value = ".")]
    pub path_out: PathBuf, 
}


#[derive(Clone, Debug, PartialEq, EnumString)]
pub enum Out {
    #[strum(serialize = "proof")]
    Proof,
    #[strum(serialize = "artifacts")]
    Artifacts,
    #[strum(serialize = "evm-verifier")]
    EvmVerifier,
}
