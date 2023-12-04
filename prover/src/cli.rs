use crate::args::BaseArgs;
use crate::args::{OperationCmd, ProofCmd};

use lightclient_circuits::{
    committee_update_circuit::CommitteeUpdateCircuit,
    halo2_proofs::halo2curves::bn256::{Bn256, Fr},
    sync_step_circuit::StepCircuit,
    util::{gen_srs, AppCircuit},
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use std::path::PathBuf;
use std::{fs::File, future::Future, io::Write, path::Path};

ethers::contract::abigen!(
    SnarkVerifierSol,
    r#"[
        function verify(uint256[1] calldata pubInputs,bytes calldata proof) public view returns (bool)
    ]"#,
);

pub trait FetchFn<Arg>: FnOnce(Arg) -> <Self as FetchFn<Arg>>::Fut {
    type Fut: Future<Output = <Self as FetchFn<Arg>>::Output>;
    type Output;
}

impl<Arg, F, Fut> FetchFn<Arg> for F
where
    F: FnOnce(Arg) -> Fut,
    Fut: Future,
{
    type Fut = Fut;
    type Output = Fut::Output;
}

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
            let params = gen_srs(k);
            let cfg_path = get_config_path(&pk_path, &base_args.config_dir);

            match operation {
                OperationCmd::Setup => {
                    StepCircuit::<S, Fr>::create_pk(
                        &params,
                        &pk_path,
                        cfg_path,
                        &Default::default(),
                    );

                    Ok(())
                }
                OperationCmd::GenVerifier(args) => {
                    gen_evm_verifier::<StepCircuit<S, Fr>>(&params, &pk_path, args.solidity_out)
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
            let params = gen_srs(k);
            let cfg_path = get_config_path(&pk_path, &base_args.config_dir);
            match operation {
                OperationCmd::Setup => {
                    let pk = CommitteeUpdateCircuit::<S, Fr>::create_pk(
                        &params,
                        &pk_path,
                        &cfg_path,
                        &Default::default(),
                    );

                    let dummy_snark = CommitteeUpdateCircuit::<S, Fr>::gen_snark_shplonk(
                        &params,
                        &pk,
                        &cfg_path,
                        None::<String>,
                        &Default::default(),
                    )
                    .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))?;

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
                OperationCmd::GenVerifier(args) => {
                    gen_evm_verifier::<AggregationCircuit>(&params, &pk_path, args.solidity_out)
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

fn gen_evm_verifier<Circuit: AppCircuit>(
    params: &ParamsKZG<Bn256>,
    pk_path: &Path,
    mut path_out: PathBuf,
) -> eyre::Result<()>
where
    Circuit::Witness: Default,
{
    let pk = Circuit::read_pk(params, pk_path, &Default::default());

    let deplyment_code =
        Circuit::gen_evm_verifier_shplonk(params, &pk, Some(path_out.clone()), &Default::default())
            .map_err(|e| eyre::eyre!("Failed to EVM verifier: {}", e))?;
    println!("yul size: {}", deplyment_code.len());
    path_out.set_extension("yul");

    let sol_contract = halo2_solidity_verifier::fix_verifier_sol(path_out.clone(), 1)
        .map_err(|e| eyre::eyre!("Failed to generate Solidity verifier: {}", e))?;
    path_out.set_extension("sol");
    let mut f = File::create(path_out).unwrap();
    f.write(sol_contract.as_bytes())
        .map_err(|e| eyre::eyre!("Failed to write Solidity verifier: {}", e))?;

    Ok(())
}
