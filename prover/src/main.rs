use std::{cell::RefCell, env::set_var, fs, path::Path};

use args::{Options, Out, Proof};
use cli_batteries::version;
use eth_types::Test;
use halo2curves::bn256::Fr;
use lightclient_circuits::{
    committee_update_circuit::CommitteeUpdateCircuit,
    sync_step_circuit::SyncStepCircuit,
    util::{read_params, read_vkey, AppCircuitExt},
    witness::SyncStateInput,
    FlexGateConfigParams,
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::gates::builder::GateThreadBuilder;
use snark_verifier_sdk::evm::{gen_evm_proof_shplonk, gen_evm_verifier_shplonk, write_calldata};

mod args;

fn main() {
    cli_batteries::run(version!(), app);
}

async fn app(options: Options) -> eyre::Result<()> {
    match options.proof {
        Proof::CommitteeUpdate(args) => match args.out {
            Out::Proof => {
                gen_evm_proof::<CommitteeUpdateCircuit<Test, Fr>>(
                    &args.config_path,
                    &args.build_dir,
                    &args.input_path,
                    Some(&args.path_out),
                    None,
                );
            }
            Out::Artifacts => setup_circuit::<CommitteeUpdateCircuit<Test, Fr>>(
                &args.config_path,
                &args.build_dir,
            ),
            Out::EvmVerifier => gen_evm_verifier::<CommitteeUpdateCircuit<Test, Fr>>(
                &args.config_path,
                &args.build_dir.join("committee_update.vkey"),
                &args.path_out,
            ),
            Out::Calldata => gen_evm_calldata::<CommitteeUpdateCircuit<Test, Fr>>(
                &args.config_path,
                &args.build_dir,
                &args.input_path,
                &args.path_out,
            ),
        },
        Proof::SyncStep(args) => match args.out {
            Out::Proof => {
                gen_evm_proof::<SyncStepCircuit<Test, Fr>>(
                    &args.config_path,
                    &args.build_dir,
                    &args.input_path,
                    Some(&args.path_out),
                    None,
                );
            }
            Out::Artifacts => {
                setup_circuit::<SyncStepCircuit<Test, Fr>>(&args.config_path, &args.build_dir)
            }
            Out::EvmVerifier => gen_evm_verifier::<SyncStepCircuit<Test, Fr>>(
                &args.config_path,
                &args.build_dir.join("sync_step.vkey"),
                &args.path_out,
            ),
            Out::Calldata => gen_evm_calldata::<SyncStepCircuit<Test, Fr>>(
                &args.config_path,
                &args.build_dir,
                &args.input_path,
                &args.path_out,
            ),
        },
    }
    Ok(())
}

fn setup_circuit<C: AppCircuitExt<Fr>>(config_path: &Path, build_dir: &Path) {
    let config: FlexGateConfigParams =
        serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();

    let _ = C::setup(&config, Some(build_dir));
}

fn gen_evm_verifier<C: AppCircuitExt<Fr>>(config_path: &Path, vkey_path: &Path, path_out: &Path) {
    let config: FlexGateConfigParams =
        serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();

    set_config(&config);

    let params = read_params(config.k as u32);

    let circuit = C::default();

    let num_instance = circuit.num_instance();

    let vk = read_vkey::<C>(vkey_path).expect("Failed to read vkey");

    let _ = gen_evm_verifier_shplonk::<C>(&params, &vk, num_instance, Some(path_out));
}

fn gen_evm_proof<C: AppCircuitExt<Fr>>(
    config_path: &Path,
    build_dir: &Path,
    path_in: &Path,
    path_out: Option<&Path>,
    instances: Option<&mut Vec<Vec<Fr>>>,
) -> Vec<u8> {
    let config: FlexGateConfigParams =
        serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();

    let (params, pk) = C::setup(&config, Some(build_dir));

    let state_input: SyncStateInput = serde_json::from_slice(&fs::read(path_in).unwrap()).unwrap();
    let state = state_input.into();

    let builder = RefCell::from(GateThreadBuilder::new(false));

    let circuit = C::new_from_state(builder, &state);

    let public_inputs = circuit.instances();

    set_config(&config);

    let proof = gen_evm_proof_shplonk(&params, &pk, circuit, public_inputs.clone());

    if let Some(path) = path_out {
        fs::write(path, proof.clone()).expect("Failed to write proof to file");
    }

    if let Some(instances) = instances {
        *instances = public_inputs;
    }

    proof
}

fn gen_evm_calldata<C: AppCircuitExt<Fr>>(
    config_path: &Path,
    build_dir: &Path,
    path_in: &Path,
    path_out: &Path,
) {
    let mut instances = vec![];
    let proof = gen_evm_proof::<C>(config_path, build_dir, path_in, None, Some(&mut instances));

    write_calldata(&instances, &proof, path_out).unwrap();
}

fn set_config(config: &FlexGateConfigParams) {
    set_var("LOOKUP_BITS", (config.k - 1).to_string());
    set_var(
        "FLEX_GATE_CONFIG_PARAMS",
        serde_json::to_string(&config).unwrap(),
    );
}
