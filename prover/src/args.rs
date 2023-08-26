// use strum::EnumString;

#[derive(Clone, clap::Parser)]
pub struct Options {
    #[command(subcommand)]
    pub proof: Proof,
}

#[derive(Clone, clap::Subcommand)]
pub enum Proof {
    CommitteeUpdate(CommitteeUpdateArgs),
    SyncStep,
}

#[derive(Clone, clap::Args)]
pub struct CommitteeUpdateArgs {
    #[command(subcommand)]
    pub out: Option<Out>,
}

#[derive(Clone, clap::Subcommand)]
pub enum Out {
    Proof,
    EvmVerifier,
}
