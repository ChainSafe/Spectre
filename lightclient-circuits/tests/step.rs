// // The Licensed Work is (c) 2023 ChainSafe
// // Code: https://github.com/ChainSafe/Spectre
// // SPDX-License-Identifier: LGPL-3.0-only

// use ark_std::{end_timer, start_timer};
// use eth_types::{Minimal, LIMB_BITS};
// use eth_types::{Spec, NUM_LIMBS};
// use halo2_base::gates::circuit::CircuitBuilderStage;
// use halo2_base::halo2_proofs::dev::MockProver;
// use halo2_base::halo2_proofs::halo2curves::bn256;
// use halo2_base::utils::fs::gen_srs;
// use halo2_ecc::bls12_381::FpChip;
// use lightclient_circuits::committee_update_circuit::CommitteeUpdateCircuit;
// use lightclient_circuits::gadget::crypto::{ShaBitGateManager, ShaFlexGateManager};
// use lightclient_circuits::sync_step_circuit::StepCircuit;
// use lightclient_circuits::util::AppCircuit;
// use lightclient_circuits::util::Eth2ConfigPinning;
// use lightclient_circuits::util::Halo2ConfigPinning;
// use lightclient_circuits::witness::CommitteeUpdateArgs;
// use lightclient_circuits::witness::SyncStepArgs;
// use lightclient_circuits::Eth2CircuitBuilder;
// use rstest::rstest;
// use snark_verifier_sdk::CircuitExt;
// use std::env::var;
// use std::path::PathBuf;

// use test_utils::read_test_files_and_gen_witness;

// #[rstest]
// fn test_eth2_spec_mock_1(
//     #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/light_client_sync")]
//     #[exclude("deneb*")]
//     path: PathBuf,
// ) {
//     run_test_eth2_spec_mock::<18, 19>(path)
// }

// // Same as StepCircuit::create_circuit without loading SRS which fails CI.
// pub(crate) fn mock_step_circuit<S: Spec>(
//     args: &SyncStepArgs<S>,
//     k: u32,
//     lookup_bits: Option<usize>,
// ) -> impl lightclient_circuits::util::PinnableCircuit<bn256::Fr> {
//     let mut builder =
//         Eth2CircuitBuilder::<ShaFlexGateManager<bn256::Fr>>::from_stage(CircuitBuilderStage::Mock)
//             .use_k(k as usize)
//             .use_instance_columns(1);
//     let range = builder.range_chip(lookup_bits.unwrap_or(k as usize - 1));
//     let fp_chip = FpChip::new(&range, LIMB_BITS, NUM_LIMBS);

//     let assigned_instances =
//         StepCircuit::<S, bn256::Fr>::synthesize(&mut builder, &fp_chip, args).unwrap();
//     builder.set_instances(0, assigned_instances);

//     builder.calculate_params(Some(
//         var("MINIMUM_ROWS")
//             .unwrap_or_else(|_| "0".to_string())
//             .parse()
//             .unwrap(),
//     ));
//     builder
// }

// // Same as CommitteeUpdateCircuit::create_circuit without loading SRS which fails CI.
// pub(crate) fn mock_committee_update_circuit<S: Spec>(
//     witness: &CommitteeUpdateArgs<S>,
//     k: u32,
//     lookup_bits: Option<usize>,
// ) -> impl lightclient_circuits::util::PinnableCircuit<bn256::Fr> {
//     let mut builder =
//         Eth2CircuitBuilder::<ShaBitGateManager<bn256::Fr>>::from_stage(CircuitBuilderStage::Mock)
//             .use_k(k as usize)
//             .use_instance_columns(1);
//     let range = builder.range_chip(lookup_bits.unwrap_or(k as usize - 1));
//     let fp_chip = FpChip::new(&range, LIMB_BITS, NUM_LIMBS);

//     let assigned_instances =
//         CommitteeUpdateCircuit::<S, bn256::Fr>::synthesize(&mut builder, &fp_chip, witness)
//             .unwrap();
//     builder.set_instances(0, assigned_instances);
//     builder.calculate_params(Some(
//         var("MINIMUM_ROWS")
//             .unwrap_or_else(|_| "0".to_string())
//             .parse()
//             .unwrap(),
//     ));
//     builder
// }

// fn run_test_eth2_spec_mock<const K_ROTATION: u32, const K_SYNC: u32>(path: PathBuf) {
//     let (sync_witness, rotation_witness) = read_test_files_and_gen_witness(&path);

//     let rotation_circuit = mock_committee_update_circuit(&rotation_witness, K_ROTATION, None);

//     let rotation_instance =
//         CommitteeUpdateCircuit::<Minimal, bn256::Fr>::get_instances(&rotation_witness, LIMB_BITS);
//     let timer = start_timer!(|| "committee_update mock prover run");
//     let prover =
//         MockProver::<bn256::Fr>::run(K_ROTATION, &rotation_circuit, rotation_instance).unwrap();
//     prover.assert_satisfied_par();
//     end_timer!(timer);

//     let sync_circuit = mock_step_circuit(&sync_witness, K_SYNC, None);

//     let instance = StepCircuit::<Minimal, bn256::Fr>::get_instances(&sync_witness, LIMB_BITS);

//     let timer = start_timer!(|| "sync_step mock prover run");
//     let prover = MockProver::<bn256::Fr>::run(K_SYNC, &sync_circuit, instance).unwrap();
//     prover.assert_satisfied_par();
//     end_timer!(timer);
// }

// #[rstest]
// fn test_eth2_spec_proofgen(
//     #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
//     #[exclude("deneb*")]
//     path: PathBuf,
// ) {
//     const K: u32 = 20;
//     let (witness, _) = read_test_files_and_gen_witness(&path);

//     let params = gen_srs(K);
//     let pk = StepCircuit::<Minimal, bn256::Fr>::create_pk(
//         &params,
//         "../build/sync_step_20.pkey",
//         "./config/sync_step_20.json",
//         &SyncStepArgs::<Minimal>::default(),
//         None,
//     );

//     let _ = StepCircuit::<Minimal, bn256::Fr>::gen_proof_shplonk(
//         &params,
//         &pk,
//         "./config/sync_step_20.json",
//         &witness,
//     )
//     .expect("proof generation & verification should not fail");
// }

// #[rstest]
// fn test_eth2_spec_evm_verify(
//     #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
//     #[exclude("deneb*")]
//     path: PathBuf,
// ) {
//     const K: u32 = 21;
//     let params = gen_srs(K);

//     let pk = StepCircuit::<Minimal, bn256::Fr>::create_pk(
//         &params,
//         "../build/sync_step_21.pkey",
//         "./config/sync_step_21.json",
//         &SyncStepArgs::<Minimal>::default(),
//         None,
//     );

//     let (witness, _) = read_test_files_and_gen_witness(&path);

//     let pinning = Eth2ConfigPinning::from_path("./config/sync_step_21.json");

//     let circuit = StepCircuit::<Minimal, bn256::Fr>::mock_circuit(
//         CircuitBuilderStage::Prover,
//         Some(pinning),
//         &witness,
//         K,
//     )
//     .unwrap();

//     let instances = circuit.instances();
//     let proof =
//         snark_verifier_sdk::evm::gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());
//     println!("proof size: {}", proof.len());
//     let deployment_code = StepCircuit::<Minimal, bn256::Fr>::gen_evm_verifier_shplonk(
//         &params,
//         &pk,
//         None::<String>,
//         &witness,
//     )
//     .unwrap();
//     println!("deployment_code size: {}", deployment_code.len());
//     snark_verifier_sdk::evm::evm_verify(deployment_code, instances, proof);
// }
