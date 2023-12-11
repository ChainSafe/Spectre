use crate::args::BaseArgs;
use crate::args::{OperationCmd, ProofCmd};
use ark_std::{end_timer, start_timer};
use lightclient_circuits::{
    committee_update_circuit::CommitteeUpdateCircuit,
    halo2_proofs::halo2curves::bn256::{Bn256, Fr},
    sync_step_circuit::StepCircuit,
    util::{gen_srs, AppCircuit},
};
use lightclient_circuits::{
    halo2_base::gates::circuit::CircuitBuilderStage, halo2_proofs::poly::commitment::Params,
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::CircuitExt;
use std::path::PathBuf;
use std::{fs::File, io::Write, path::Path};

#[cfg(feature = "experimental")]
use halo2_solidity_verifier_new::{
    compile_solidity, encode_calldata, BatchOpenScheme, Evm, SolidityGenerator,
};

pub(crate) async fn spec_app<S: eth_types::Spec>(
    proof: ProofCmd,
    base_args: &BaseArgs,
) -> eyre::Result<()>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::SYNC_COMMITTEE_ROOT_INDEX]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::FINALIZED_HEADER_INDEX]:,
{
    match proof {
        ProofCmd::SyncStep {
            operation,
            k,
            pk_path,
        } => {
            let cfg_path = get_config_path(&pk_path, &base_args.config_dir);

            match operation {
                OperationCmd::Setup => {
                    let params = gen_srs(k);

                    StepCircuit::<S, Fr>::create_pk(
                        &params,
                        &pk_path,
                        cfg_path,
                        &Default::default(),
                    );

                    Ok(())
                }
                OperationCmd::GenVerifier {
                    solidity_out,
                    estimate_gas,
                } => {
                    let params = gen_srs(StepCircuit::<S, Fr>::get_degree(&cfg_path));
                    gen_evm_verifier::<StepCircuit<S, Fr>>(
                        &params,
                        &pk_path,
                        &cfg_path,
                        solidity_out,
                        estimate_gas,
                        Default::default(),
                    )
                }
            }
        }
        ProofCmd::CommitteeUpdate {
            operation,
            k,
            verifier_k,
            verifier_pk_path,
            pk_path,
        } => {
            let cfg_path = get_config_path(&pk_path, &base_args.config_dir);

            let gen_dummy_snark = |k: u32| {
                let params = gen_srs(k);

                let pk = CommitteeUpdateCircuit::<S, Fr>::create_pk(
                    &params,
                    &pk_path,
                    &cfg_path,
                    &Default::default(),
                );

                CommitteeUpdateCircuit::<S, Fr>::gen_snark_shplonk(
                    &params,
                    &pk,
                    &cfg_path,
                    None::<String>,
                    &Default::default(),
                )
                .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))
            };

            match operation {
                OperationCmd::Setup => {
                    let timer = start_timer!(|| "gen committee update verifier witness");
                    let dummy_snark = gen_dummy_snark(k)?;
                    end_timer!(timer);

                    let verifier_params = gen_srs(verifier_k);
                    let verifier_cfg_path =
                        get_config_path(&verifier_pk_path, &base_args.config_dir);

                    AggregationCircuit::create_pk(
                        &verifier_params,
                        &verifier_pk_path,
                        verifier_cfg_path,
                        &vec![dummy_snark],
                    );

                    Ok(())
                }
                OperationCmd::GenVerifier {
                    solidity_out,
                    estimate_gas,
                } => {
                    let timer = start_timer!(|| "gen committee update verifier witness");
                    let dummy_snark =
                        gen_dummy_snark(CommitteeUpdateCircuit::<S, Fr>::get_degree(&cfg_path))?;
                    end_timer!(timer);

                    let verifier_cfg_path =
                        get_config_path(&verifier_pk_path, &base_args.config_dir);
                    let verifier_params =
                        gen_srs(AggregationCircuit::get_degree(&verifier_cfg_path));

                    gen_evm_verifier::<AggregationCircuit>(
                        &verifier_params,
                        &verifier_pk_path,
                        &verifier_cfg_path,
                        solidity_out,
                        estimate_gas,
                        vec![dummy_snark],
                    )
                }
            }
        }
    }
}

fn get_config_path(pk_path: &Path, config_dir: &Path) -> PathBuf {
    let circuit_configuration = pk_path
        .file_stem()
        .expect("config file is required")
        .to_str()
        .unwrap();
    config_dir.join(format!("{}.json", circuit_configuration))
}

#[cfg(not(feature = "experimental"))]
fn gen_evm_verifier<Circuit: AppCircuit>(
    params: &ParamsKZG<Bn256>,
    pk_path: &Path,
    cfg_path: &Path,
    mut path_out: PathBuf,
    estimate_gas: bool,
    default_witness: Circuit::Witness,
) -> eyre::Result<()> {
    let pk = Circuit::read_pk(params, pk_path, &default_witness);

    let num_instances = {
        let circuit = Circuit::create_circuit(
            CircuitBuilderStage::Keygen,
            None,
            &default_witness,
            params.k(),
        )
        .unwrap();
        circuit.num_instance().first().map_or(0, |x| *x as u32)
    };

    path_out.set_extension("yul");
    let deplyment_code =
        Circuit::gen_evm_verifier_shplonk(params, &pk, Some(path_out.clone()), &default_witness)
            .map_err(|e| eyre::eyre!("Failed to EVM verifier: {}", e))?;
    println!("yul size: {}", deplyment_code.len());

    let sol_contract = halo2_solidity_verifier::fix_verifier_sol(path_out.clone(), num_instances)
        .map_err(|e| eyre::eyre!("Failed to generate Solidity verifier: {}", e))?;
    path_out.set_extension("sol");
    let mut f = File::create(path_out).unwrap();
    f.write(sol_contract.as_bytes())
        .map_err(|e| eyre::eyre!("Failed to write Solidity verifier: {}", e))?;

    if estimate_gas {
        let _ = Circuit::gen_evm_proof_shplonk(
            params,
            &pk,
            cfg_path,
            Some(deplyment_code),
            &default_witness,
        )
        .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))?;
    }

    Ok(())
}

#[cfg(feature = "experimental")]
fn gen_evm_verifier<Circuit: AppCircuit>(
    params: &ParamsKZG<Bn256>,
    pk_path: &Path,
    cfg_path: &Path,
    mut path_out: PathBuf,
    estimate_gas: bool,
    default_witness: Circuit::Witness,
) -> eyre::Result<()> {
    let pk = Circuit::read_pk(params, pk_path, &default_witness);

    let num_instances = {
        let circuit = Circuit::create_circuit(
            CircuitBuilderStage::Mock,
            None,
            &default_witness,
            params.k(),
        )
        .unwrap();
        circuit.num_instance().first().map_or(0, |x| *x)
    };

    let generator =
        SolidityGenerator::new(params, pk.get_vk(), BatchOpenScheme::Bdfg21, num_instances);

    let verifier_sol = generator
        .render()
        .map_err(|e| eyre::eyre!("Failed to generate Solidity verifier: {}", e))?;

    path_out.set_extension("sol");
    let mut f = File::create(path_out).unwrap();
    f.write(verifier_sol.as_bytes())
        .map_err(|e| eyre::eyre!("Failed to write Solidity verifier: {}", e))?;

    if estimate_gas {
        let mut evm = Evm::default();
        let verifier_creation_code = compile_solidity(&verifier_sol);
        println!(
            "Verifier creation code size: {}",
            verifier_creation_code.len()
        );
        let verifier_address = evm.create(verifier_creation_code);

        let (proof, instances) =
            Circuit::gen_evm_proof_shplonk(params, &pk, cfg_path, None, &default_witness)
                .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))?;
        let calldata = encode_calldata(None, &proof, &instances[0]);
        let (gas_cost, output) = evm.call(verifier_address, calldata);
        assert_eq!(output, [vec![0; 31], vec![1]].concat());
        println!("Gas cost of verifying proof: {gas_cost}");
    }

    Ok(())
}
