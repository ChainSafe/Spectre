use args::{Options, Proof, Out};
use cli_batteries::version;

mod args;

fn main() {
    cli_batteries::run(version!(), app);
}

async fn app(options: Options) -> eyre::Result<()> {
    match options.proof {
        Proof::CommitteeUpdate(args) => {
            match args.out.unwrap_or(Out::Proof) {
                Out::Proof => {
                    println!("prove CommitteeUpdate");
                },
                Out::EvmVerifier => {
                    println!("yul CommitteeUpdate");
                },
            }
        }
        Proof::SyncStep => {
            println!("Prover");
        }
    }
    Ok(())
}


