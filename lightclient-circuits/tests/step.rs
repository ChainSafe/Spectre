use ark_std::{end_timer, start_timer};
use eth_types::{Minimal, LIMB_BITS};
use halo2_base::gates::circuit::CircuitBuilderStage;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256;
use lightclient_circuits::committee_update_circuit::CommitteeUpdateCircuit;
use lightclient_circuits::sync_step_circuit::StepCircuit;
use lightclient_circuits::util::gen_srs;
use lightclient_circuits::util::AppCircuit;
use lightclient_circuits::util::Eth2ConfigPinning;
use lightclient_circuits::util::Halo2ConfigPinning;
use lightclient_circuits::witness::SyncStepArgs;
use rstest::rstest;
use snark_verifier_sdk::CircuitExt;
use std::path::PathBuf;

use test_utils::read_test_files_and_gen_witness;

#[rstest]
fn test_eth2_spec_mock_1(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/light_client_sync")]
    #[exclude("deneb*")]
    path: PathBuf,
) {
    run_test_eth2_spec_mock::<18, 20>(path)
}


fn run_test_eth2_spec_mock<const K_ROTATION: u32, const K_SYNC: u32>(path: PathBuf) {
    let (sync_witness, rotation_witness) = read_test_files_and_gen_witness(&path);

    let rotation_circuit = {
        let pinning: Eth2ConfigPinning =
            Eth2ConfigPinning::from_path(format!("./config/committee_update_{K_ROTATION}.json"));

        CommitteeUpdateCircuit::<Minimal, bn256::Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            Some(pinning),
            &rotation_witness,
            K_ROTATION,
        )
        .unwrap()
    };

    let timer = start_timer!(|| "committee_update mock prover run");
    let prover = MockProver::<bn256::Fr>::run(
        K_ROTATION,
        &rotation_circuit,
        CommitteeUpdateCircuit::<Minimal, bn256::Fr>::instance(&rotation_witness, LIMB_BITS),
    )
    .unwrap();
    prover.assert_satisfied_par();
    end_timer!(timer);

    let sync_circuit = {
        let pinning: Eth2ConfigPinning =
            Eth2ConfigPinning::from_path(format!("./config/sync_step_{K_SYNC}.json"));

        StepCircuit::<Minimal, bn256::Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            Some(pinning),
            &sync_witness,
            K_SYNC,
        )
        .unwrap()
    };

    let sync_pi_commit =
        StepCircuit::<Minimal, bn256::Fr>::instance_commitment(&sync_witness, LIMB_BITS);

    let timer = start_timer!(|| "sync_step mock prover run");
    let prover =
        MockProver::<bn256::Fr>::run(K_SYNC, &sync_circuit, vec![vec![sync_pi_commit]]).unwrap();
    prover.assert_satisfied_par();
    end_timer!(timer);
}

#[rstest]
fn test_eth2_spec_proofgen(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) {
    const K: u32 = 20;
    let (witness, _) = read_test_files_and_gen_witness(&path);

    let params = gen_srs(K);
    let pk = StepCircuit::<Minimal, bn256::Fr>::read_or_create_pk(
        &params,
        "../build/sync_step_20.pkey",
        "./config/sync_step_20.json",
        false,
        &SyncStepArgs::<Minimal>::default(),
    );

    let _ = StepCircuit::<Minimal, bn256::Fr>::gen_proof_shplonk(
        &params,
        &pk,
        "./config/sync_step_20.json",
        &witness,
    )
    .expect("proof generation & verification should not fail");
}

#[rstest]
fn test_eth2_spec_evm_verify(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) {
    const K: u32 = 21;
    let params = gen_srs(K);

    let pk = StepCircuit::<Minimal, bn256::Fr>::read_or_create_pk(
        &params,
        "../build/sync_step_21.pkey",
        "./config/sync_step_21.json",
        false,
        &SyncStepArgs::<Minimal>::default(),
    );

    let (witness, _) = read_test_files_and_gen_witness(&path);

    let pinning = Eth2ConfigPinning::from_path("./config/sync_step_21.json");

    let circuit = StepCircuit::<Minimal, bn256::Fr>::create_circuit(
        CircuitBuilderStage::Prover,
        Some(pinning),
        &witness,
        K,
    )
    .unwrap();

    let instances = circuit.instances();
    let proof =
        snark_verifier_sdk::evm::gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());
    println!("proof size: {}", proof.len());
    let deployment_code = StepCircuit::<Minimal, bn256::Fr>::gen_evm_verifier_shplonk(
        &params,
        &pk,
        None::<String>,
        &witness,
    )
    .unwrap();
    println!("deployment_code size: {}", deployment_code.len());
    snark_verifier_sdk::evm::evm_verify(deployment_code, instances, proof);
}
