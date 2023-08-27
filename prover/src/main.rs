use std::{env::set_var, fs, path::Path};

use args::{Options, Out, Proof};
use cli_batteries::version;
use eth_types::Test;
use halo2curves::bn256::Fr;
use lightclient_circuits::{
    committee_update_circuit::CommitteeUpdateCircuit,
    sync_step_circuit::SyncStepCircuit,
    util::{read_params, read_vkey, AppCircuitExt},
    FlexGateConfigParams,
};
use snark_verifier_sdk::evm::gen_evm_verifier_shplonk;

mod args;

fn main() {
    cli_batteries::run(version!(), app);
}

async fn app(options: Options) -> eyre::Result<()> {
    match options.proof {
        Proof::CommitteeUpdate(args) => match args.out {
            Out::Proof => todo!(),
            Out::Artifacts => setup_circuit::<CommitteeUpdateCircuit<Test, Fr>>(
                &args.config_path,
                &args.build_dir,
            ),
            Out::EvmVerifier => gen_evm_verifier::<CommitteeUpdateCircuit<Test, Fr>>(
                &args.config_path,
                &args.build_dir.join("committee_update.vkey"),
                &args.path_out,
            ),
        },
        Proof::SyncStep(args) => match args.out {
            Out::Proof => todo!(),
            Out::Artifacts => {
                setup_circuit::<SyncStepCircuit<Test, Fr>>(&args.config_path, &args.build_dir)
            }
            Out::EvmVerifier => gen_evm_verifier::<SyncStepCircuit<Test, Fr>>(
                &args.config_path,
                &args.build_dir.join("sync_step.vkey"),
                &args.path_out,
            ),
        },
    }
    Ok(())
}

fn setup_circuit<C: AppCircuitExt<Fr>>(config_path: &Path, build_dir: &Path) {
    let config: FlexGateConfigParams =
        serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();

    let _ = C::setup(config, Some(build_dir));
}

fn gen_evm_verifier<C: AppCircuitExt<Fr>>(config_path: &Path, vkey_path: &Path, path_out: &Path) {
    let config: FlexGateConfigParams =
        serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();

    set_var("LOOKUP_BITS", (config.k - 1).to_string());
    set_var(
        "FLEX_GATE_CONFIG_PARAMS",
        serde_json::to_string(&config).unwrap(),
    );

    let params = read_params(config.k as u32);

    let circuit = C::default();

    let num_instance = circuit.num_instance();

    let vk = read_vkey::<C>(vkey_path).expect("Failed to read vkey");

    let _ = gen_evm_verifier_shplonk::<C>(&params, &vk, num_instance, Some(path_out));
}
