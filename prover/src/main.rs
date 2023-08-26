use std::{fs, env::set_var};

use args::{Options, Out, Proof};
use cli_batteries::version;
use eth_types::Test;
use halo2curves::bn256::Fr;
use lightclient_circuits::{
    sync_step_circuit::SyncStepCircuit,
    util::{read_params, read_vkey},
    FlexGateConfigParams,
};
use snark_verifier_sdk::{evm::gen_evm_verifier_shplonk, CircuitExt};

mod args;

fn main() {
    cli_batteries::run(version!(), app);
}

async fn app(options: Options) -> eyre::Result<()> {
    match options.proof {
        Proof::CommitteeUpdate(args) => match args.out {
            Out::Proof => todo!(),
            Out::Artifacts => {
                let config: FlexGateConfigParams =
                    serde_json::from_slice(&fs::read(args.config_path).unwrap()).unwrap();

                let _ = SyncStepCircuit::<Test, Fr>::setup(config, Some(&args.build_dir));
            }
            Out::EvmVerifier => {
                let config: FlexGateConfigParams =
                    serde_json::from_slice(&fs::read(args.config_path).unwrap()).unwrap();

                set_var("LOOKUP_BITS", (config.k - 1).to_string());
                set_var(
                    "FLEX_GATE_CONFIG_PARAMS",
                    serde_json::to_string(&config).unwrap(),
                );

                let params = read_params(config.k as u32);

                let circuit = SyncStepCircuit::<Test, Fr>::default();

                let num_instance = circuit.num_instance();

                let vk =
                    read_vkey::<SyncStepCircuit<Test, Fr>>(&args.build_dir.join("sync_step.vkey"))
                        .expect("Failed to read vkey");

                let _ = gen_evm_verifier_shplonk::<SyncStepCircuit<Test, Fr>>(
                    &params,
                    &vk,
                    num_instance,
                    Some(&args.path_out),
                );
            }
        },
        Proof::SyncStep => {
            println!("Prover");
        }
    }
    Ok(())
}
