use std::future::Future;

use args::{Args, Options, Out, Proof};
use cli_batteries::version;
use halo2curves::bn256::Fr;
use lightclient_circuits::{
    committee_update_circuit::CommitteeUpdateCircuit,
    sync_step_circuit::SyncStepCircuit,
    util::{gen_srs, AppCircuit},
};
use preprocessor::{fetch_rotation_args, fetch_step_args};

mod args;

fn main() {
    cli_batteries::run(version!(), app);
}

async fn app(options: Options) -> eyre::Result<()> {
    match options.spec {
        args::Spec::Minimal => spec_app::<eth_types::Minimal>(&options.proof).await,
        args::Spec::Testnet => spec_app::<eth_types::Testnet>(&options.proof).await,
        args::Spec::Mainnet => spec_app::<eth_types::Testnet>(&options.proof).await,
    }
}

async fn spec_app<S: eth_types::Spec>(proof: &Proof) -> eyre::Result<()> {
    match proof {
        Proof::CommitteeUpdate(args) => {
            generic_circuit_app::<CommitteeUpdateCircuit<S, Fr>, _, _>(
                args,
                fetch_rotation_args,
                "committee_update",
            )
            .await
        }
        Proof::SyncStep(args) => {
            generic_circuit_app::<SyncStepCircuit<S, Fr>, _, _>(args, fetch_step_args, "sync_step")
                .await
        }
    }
}

async fn generic_circuit_app<
    Circuit: AppCircuit,
    FnFetch: FnOnce(String) -> Fut,
    Fut: Future<Output = eyre::Result<Circuit::Args>>,
>(
    cli_args: &Args,
    fetch: FnFetch,
    name: &str,
) -> eyre::Result<()> {
    let k = cli_args
        .k
        .unwrap_or_else(|| Circuit::get_degree(&cli_args.config_path));
    let params = gen_srs(k);
    let pk_filename = format!("{}.pkey", name);

    match cli_args.out {
        Out::Proof => {
            let pk = Circuit::read_or_create_pk(
                &params,
                cli_args.build_dir.join(&pk_filename),
                &cli_args.config_path,
                true,
            );
            let witness = fetch(cli_args.node_url.clone()).await?;
            Circuit::gen_snark_shplonk(
                &params,
                &pk,
                &cli_args.config_path,
                Some(&cli_args.path_out),
                &witness,
            )
            .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))?;
        }
        Out::Artifacts => {
            Circuit::create_pk(
                &params,
                cli_args.build_dir.join(&pk_filename),
                &cli_args.config_path,
            );
        }
        Out::EvmVerifier => {
            let pk = Circuit::read_or_create_pk(
                &params,
                cli_args.build_dir.join(&pk_filename),
                &cli_args.config_path,
                true,
            );
            Circuit::gen_evm_verifier_shplonk(&params, &pk, &cli_args.path_out)
                .map_err(|e| eyre::eyre!("Failed to EVM verifier: {}", e))?;
        }
        Out::Calldata => {
            let pk = Circuit::read_or_create_pk(
                &params,
                cli_args.build_dir.join(&pk_filename),
                &cli_args.config_path,
                true,
            );
            let witness = fetch(cli_args.node_url.clone()).await?;

            let calldata = Circuit::gen_calldata(
                &params,
                &pk,
                &cli_args.config_path,
                &cli_args.path_out,
                None,
                &witness,
            )
            .map_err(|e| eyre::eyre!("Failed to generate calldata: {}", e))?;

            println!("{}", calldata)
        }
    }
    Ok(())
}
