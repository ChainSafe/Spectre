#![feature(associated_type_bounds)]
use std::{fs, future::Future, path::Path};

use args::{Args, Options, Out, Proof};
use cli_batteries::version;
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use lightclient_circuits::{
    committee_update_circuit::CommitteeUpdateCircuit,
    sync_step_circuit::SyncStepCircuit,
    util::{gen_srs, AppCircuit},
};
use preprocessor::{fetch_rotation_args, fetch_step_args};
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::halo2_proofs::{
        plonk::VerifyingKey, poly::kzg::commitment::ParamsKZG,
    },
    system::halo2::Config,
};
use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, read_instances, Snark};

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
            generic_circuit_cli::<CommitteeUpdateCircuit<S, Fr>, _, _>(
                args,
                fetch_rotation_args,
                "committee_update",
                <CommitteeUpdateCircuit<S, Fr> as AppCircuit>::Witness::default(),
            )
            .await
        }
        Proof::SyncStep(args) => {
            generic_circuit_cli::<SyncStepCircuit<S, Fr>, _, _>(
                args,
                fetch_step_args,
                "sync_step",
                <SyncStepCircuit<S, Fr> as AppCircuit>::Witness::default(),
            )
            .await
        }
        Proof::Aggregation(args) => {
            let params = gen_srs(CommitteeUpdateCircuit::<S, Fr>::get_degree(
                &args.app_config_path,
            ));

            let app_pk = CommitteeUpdateCircuit::<S, Fr>::read_pk(
                &params,
                &args.app_pk_path,
                &<CommitteeUpdateCircuit<S, Fr> as AppCircuit>::Witness::default(),
            );

            let snark = read_snark(
                &params,
                app_pk.get_vk(),
                args.aggregation
                    .input_path
                    .as_ref()
                    .expect("path to SNARK is required"),
            )?;

            generic_circuit_cli::<AggregationCircuit, _, _>(
                &args.aggregation,
                |_| async { Ok(vec![snark.clone()]) },
                "aggregation",
                vec![snark.clone()],
            )
            .await
        }
    }
}

async fn generic_circuit_cli<
    Circuit: AppCircuit,
    FnFetch: FnOnce(String) -> Fut,
    Fut: Future<Output = eyre::Result<Circuit::Witness>>,
>(
    args: &Args,
    fetch: FnFetch,
    name: &str,
    default_witness: Circuit::Witness,
) -> eyre::Result<()> {
    let k = args
        .k
        .unwrap_or_else(|| Circuit::get_degree(&args.config_path));
    let params = gen_srs(k);
    let pk_filename = format!("{}.pkey", name);

    match args.out {
        Out::Snark => {
            let pk = Circuit::read_or_create_pk(
                &params,
                args.build_dir.join(&pk_filename),
                &args.config_path,
                true,
                &default_witness,
            );
            let witness = fetch(args.node_url.clone()).await?;
            Circuit::gen_snark_shplonk(
                &params,
                &pk,
                &args.config_path,
                Some(&args.path_out),
                &witness,
            )
            .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))?;
        }
        Out::Artifacts => {
            Circuit::create_pk(
                &params,
                args.build_dir.join(&pk_filename),
                &args.config_path,
                &default_witness,
            );
        }
        Out::EvmVerifier => {
            let pk = Circuit::read_or_create_pk(
                &params,
                args.build_dir.join(&pk_filename),
                &args.config_path,
                true,
                &default_witness,
            );
            Circuit::gen_evm_verifier_shplonk(&params, &pk, Some(&args.path_out), &default_witness)
                .map_err(|e| eyre::eyre!("Failed to EVM verifier: {}", e))?;
        }
        Out::Calldata => {
            let pk = Circuit::read_or_create_pk(
                &params,
                args.build_dir.join(&pk_filename),
                &args.config_path,
                true,
                &default_witness,
            );
            let witness = fetch(args.node_url.clone()).await?;

            Circuit::gen_calldata(
                &params,
                &pk,
                &args.config_path,
                &args.path_out,
                None,
                &witness,
            )
            .map_err(|e| eyre::eyre!("Failed to generate calldata: {}", e))?;
        }
    }
    Ok(())
}

fn read_snark(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    path: &Path,
) -> eyre::Result<Snark> {
    let path_str = path.to_str().unwrap();

    let proof = fs::read(format!("{path_str}.proof"))
        .map_err(|e| eyre::eyre!("Error reading proof file: {}", e))?;
    let instances = read_instances(format!("{path_str}.instances"))
        .map_err(|e| eyre::eyre!("Error reading instances file: {}", e))?;

    let protocol = snark_verifier::system::halo2::compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(instances.iter().map(|i| i.len()).collect())
            .with_accumulator_indices(None), // FIXME: use <C: CircuitExt<Fr>>::accumulator_indices()
    );

    Ok(Snark {
        protocol,
        proof,
        instances,
    })
}
