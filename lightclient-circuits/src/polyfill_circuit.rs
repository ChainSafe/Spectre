// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use crate::{
    gadget::{
        crypto::{
            G1Chip, G1Point, G2Chip, HashInstructions, Sha256Chip, ShaCircuitBuilder,
            ShaFlexGateManager,
        },
        to_bytes_le,
    },
    poseidon::{fq_array_poseidon, poseidon_hash_fq_array},
    ssz_merkle::{ssz_merkleize_chunks, verify_merkle_multi_proof, verify_merkle_proof},
    util::{AppCircuit, Eth2ConfigPinning, IntoWitness},
    witness::{self, HashInput, HashInputChunk, SyncStepArgs},
    Eth2CircuitBuilder,
};
use eth_types::{Field, Spec, LIMB_BITS, NUM_LIMBS};
use halo2_base::{
    gates::{
        circuit::CircuitBuilderStage, flex_gate::threads::CommonCircuitBuilder, GateInstructions,
        RangeChip, RangeInstructions,
    },
    halo2_proofs::{
        halo2curves::bn256::{self, Bn256},
        plonk::Error,
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    utils::CurveAffineExt,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bls12_381::{bls_signature::BlsSignatureChip, pairing::PairingChip, Fp2Chip, Fp2Point, FpChip},
    ecc::{
        hash_to_curve::{ExpandMsgXmd, HashToCurveChip},
        EcPoint, EccChip,
    },
    fields::FieldChip,
};
use halo2curves::{
    bls12_381::{G1Affine, G2Affine},
    group::UncompressedEncoding,
};
use itertools::Itertools;
use num_bigint::BigUint;
use ssz_rs::Merkleized;
use std::{env::var, iter, marker::PhantomData, vec};

/// `StepCircuit` verifies that Beacon chain block header is attested by a lightclient sync committee via aggregated signature,
/// and the execution (Eth1) payload via Merkle proof against the finalized block header.
///
/// Assumes that signature is a BLS12-381 point on G2, and public keys are BLS12-381 points on G1; `finality_branch` is exactly `S::FINALIZED_HEADER_DEPTH` hashes in lenght;
/// and `execution_payload_branch` is `S::EXECUTION_PAYLOAD_DEPTH` hashes in lenght.
///
/// The circuit exposes two public inputs:
/// - `pub_inputs_commit` is SHA256(attested_slot || inalized_slot || participation_sum || finalized_header_root || execution_payload_root) truncated to 253 bits. All committed valeus are in little endian.
/// - `poseidon_commit` is a Poseidon "onion" commitment to the X coordinates of sync committee public keys. Coordinates are expressed as big-integer with two limbs of LIMB_BITS * 2 bits.
#[derive(Clone, Debug, Default)]
pub struct PolyfillCircuit<S: Spec + ?Sized, F: Field> {
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> PolyfillCircuit<S, F> {
    pub fn synthesize(
        builder: &mut ShaCircuitBuilder<F, ShaFlexGateManager<F>>,
        range: &RangeChip<F>,
        args: &witness::PolyfillArgs<S>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let sha256_chip = Sha256Chip::new(range);
        let parent_header = args.parent_header.clone();
        let verified_header = args.verified_header.clone();

        let parent_header_root = verified_header
            .parent_root
            .as_ref()
            .iter()
            .map(|v| builder.main().load_witness(F::from(*v as u64)))
            .collect_vec();

        // Verifies that the parent hash is actually in the verified (trusted) header
        let verified_block_root = ssz_merkleize_chunks(
            builder,
            &sha256_chip,
            [
                verified_header.slot.into_witness(),
                verified_header.proposer_index.into_witness(),
                parent_header_root.clone().into(),
                verified_header.state_root.as_ref().into_witness(),
                verified_header.body_root.as_ref().into_witness(),
            ],
        )?;
        let parent_body_root: HashInputChunk<_> = parent_header.body_root.as_ref().into_witness();
        let parent_slot_bytes: HashInputChunk<_> = parent_header.slot.into_witness();

        // TODO: Make gindex a constant
        // Verifies that the parent slot AND body root is the same as the one in the parent header
        verify_merkle_multi_proof(
            builder,
            &sha256_chip,
            args.parent_slot_proof
                .iter()
                .map(|w| w.clone().into_witness()),
            vec![parent_slot_bytes.clone(), parent_body_root.clone()],
            parent_header_root.as_slice(),
            vec![8, 12],
            args.helper_indices.clone(),
        )?;

        // Convert parent slot from bytes to single field element
        let parent_slot = {
            let ctx = builder.main();
            let byte_bases = (0..32)
                .map(|i| QuantumCell::Constant(range.gate().pow_of_two()[i * 8]))
                .collect_vec();

            range
                .gate()
                .inner_product(ctx, parent_slot_bytes, byte_bases)
        };

        // // Verify execution payload root against finalized block body via the Merkle "execution" proof
        // verify_merkle_proof(
        //     builder,
        //     &sha256_chip,
        //     args.execution_payload_branch
        //         .iter()
        //         .map(|w| w.clone().into_witness()),
        //     execution_payload_root.clone(),
        //     &finalized_block_body_root,
        //     S::EXECUTION_STATE_ROOT_INDEX,
        // )?;

        Ok(iter::once(parent_slot)
            .chain(parent_header_root.into_iter())
            .chain(verified_block_root.into_iter())
            .collect_vec())
    }
}

impl<S: Spec> AppCircuit for PolyfillCircuit<S, bn256::Fr> {
    type Pinning = Eth2ConfigPinning;
    type Witness = witness::PolyfillArgs<S>;

    fn create_circuit(
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        args: &Self::Witness,
        params: &ParamsKZG<Bn256>,
    ) -> Result<impl crate::util::PinnableCircuit<bn256::Fr>, Error> {
        let k = params.k() as usize;
        let lookup_bits = pinning
            .as_ref()
            .map_or(k - 1, |p| p.params.lookup_bits.unwrap_or(k - 1));
        let mut builder = Eth2CircuitBuilder::<ShaFlexGateManager<bn256::Fr>>::from_stage(stage)
            .use_k(k)
            .use_instance_columns(1);
        let range = builder.range_chip(lookup_bits);

        let assigned_instances = Self::synthesize(&mut builder, &range, args)?;
        builder.set_instances(0, assigned_instances);

        match stage {
            CircuitBuilderStage::Prover => {
                if let Some(pinning) = pinning {
                    builder.set_params(pinning.params);
                    builder.set_break_points(pinning.break_points);
                }
            }
            _ => {
                builder.calculate_params(Some(
                    var("MINIMUM_ROWS")
                        .unwrap_or_else(|_| "0".to_string())
                        .parse()
                        .unwrap(),
                ));
            }
        }

        Ok(builder)
    }
}

// #[cfg(test)]
// mod tests {
//     use std::fs;

//     use crate::{
//         aggregation_circuit::AggregationConfigPinning, util::Halo2ConfigPinning,
//         witness::SyncStepArgs,
//     };

//     use super::*;
//     use ark_std::{end_timer, start_timer};
//     use eth_types::Testnet;
//     use halo2_base::{
//         halo2_proofs::dev::MockProver, halo2_proofs::halo2curves::bn256::Fr, utils::fs::gen_srs,
//     };
//     use snark_verifier_sdk::{
//         evm::{evm_verify, gen_evm_proof_shplonk},
//         halo2::aggregation::AggregationCircuit,
//         CircuitExt,
//     };

//     fn load_circuit_args() -> SyncStepArgs<Testnet> {
//         serde_json::from_slice(&fs::read("../test_data/sync_step_512.json").unwrap()).unwrap()
//     }

//     #[test]
//     fn test_step_circuit() {
//         const K: u32 = 20;
//         let witness = load_circuit_args();

//         let circuit =
//             StepCircuit::<Testnet, Fr>::mock_circuit(CircuitBuilderStage::Mock, None, &witness, K)
//                 .unwrap();

//         let instance = StepCircuit::<Testnet, Fr>::get_instances(&witness, LIMB_BITS);

//         let timer = start_timer!(|| "sync_step mock prover");
//         let prover = MockProver::<Fr>::run(K, &circuit, instance).unwrap();
//         prover.assert_satisfied_par();
//         end_timer!(timer);
//     }

//     #[test]
//     fn test_step_proofgen() {
//         const K: u32 = 22;
//         let params = gen_srs(K);

//         let pk = StepCircuit::<Testnet, Fr>::create_pk(
//             &params,
//             "../build/sync_step_22.pkey",
//             "./config/sync_step_22.json",
//             &SyncStepArgs::<Testnet>::default(),
//             None,
//         );

//         let witness = load_circuit_args();

//         let _ = StepCircuit::<Testnet, Fr>::gen_proof_shplonk(
//             &params,
//             &pk,
//             "./config/sync_step_22.json",
//             &witness,
//         )
//         .expect("proof generation & verification should not fail");
//     }

//     #[test]
//     fn test_step_evm_verify() {
//         const K: u32 = 22;
//         let params = gen_srs(K);

//         let pk = StepCircuit::<Testnet, Fr>::create_pk(
//             &params,
//             "../build/sync_step_22.pkey",
//             "./config/sync_step_22.json",
//             &SyncStepArgs::<Testnet>::default(),
//             None,
//         );

//         let witness = load_circuit_args();

//         let pinning = Eth2ConfigPinning::from_path("./config/sync_step_22.json");

//         let circuit = StepCircuit::<Testnet, Fr>::create_circuit(
//             CircuitBuilderStage::Prover,
//             Some(pinning),
//             &witness,
//             &params,
//         )
//         .unwrap();

//         let instances = circuit.instances();
//         let proof = gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());
//         println!("proof size: {}", proof.len());
//         let deployment_code = StepCircuit::<Testnet, Fr>::gen_evm_verifier_shplonk(
//             &params,
//             &pk,
//             None::<String>,
//             &witness,
//         )
//         .unwrap();
//         println!("deployment_code size: {}", deployment_code.len());
//         evm_verify(deployment_code, instances, proof);
//     }

//     #[test]
//     fn test_step_aggregation_evm() {
//         const APP_K: u32 = 20;
//         const APP_PK_PATH: &str = "../build/sync_step_20.pkey";
//         const APP_PINNING_PATH: &str = "./config/sync_step_20.json";
//         const AGG_K: u32 = 23;
//         const AGG_PK_PATH: &str = "../build/sync_step_verifier_23.pkey";
//         const AGG_CONFIG_PATH: &str = "./config/sync_step_verifier_23.json";
//         let params_app = gen_srs(APP_K);
//         let pk_app = StepCircuit::<Testnet, Fr>::create_pk(
//             &params_app,
//             APP_PK_PATH,
//             APP_PINNING_PATH,
//             &SyncStepArgs::<Testnet>::default(),
//             None,
//         );

//         let witness = load_circuit_args();
//         let snark = StepCircuit::<Testnet, Fr>::gen_snark_shplonk(
//             &params_app,
//             &pk_app,
//             APP_PINNING_PATH,
//             None::<String>,
//             &witness,
//         )
//         .unwrap();

//         let agg_params = gen_srs(AGG_K);

//         let pk = AggregationCircuit::create_pk(
//             &agg_params,
//             AGG_PK_PATH,
//             AGG_CONFIG_PATH,
//             &vec![snark.clone()],
//             Some(AggregationConfigPinning::new(AGG_K, 19)),
//         );

//         let agg_config = AggregationConfigPinning::from_path(AGG_CONFIG_PATH);

//         let agg_circuit = AggregationCircuit::create_circuit(
//             CircuitBuilderStage::Prover,
//             Some(agg_config),
//             &vec![snark.clone()],
//             &agg_params,
//         )
//         .unwrap();

//         let instances = agg_circuit.instances();
//         let num_instances = agg_circuit.num_instance();

//         println!("num_instances: {:?}", num_instances);
//         println!("instances: {:?}", instances);

//         let proof = gen_evm_proof_shplonk(&agg_params, &pk, agg_circuit, instances.clone());
//         println!("proof size: {}", proof.len());
//         let deployment_code = AggregationCircuit::gen_evm_verifier_shplonk(
//             &agg_params,
//             &pk,
//             None::<String>,
//             &vec![snark],
//         )
//         .unwrap();
//         println!("deployment_code size: {}", deployment_code.len());
//         evm_verify(deployment_code, instances, proof);
//     }
// }
