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
    poseidon::{g1_array_poseidon, poseidon_committee_commitment_from_uncompressed},
    ssz_merkle::{ssz_merkleize_chunks, verify_merkle_proof},
    util::{AppCircuit, Eth2ConfigPinning, IntoWitness},
    witness::{self, HashInput, HashInputChunk, SyncStepArgs},
    Eth2CircuitBuilder,
};
use eth_types::{Field, Spec, LIMB_BITS, NUM_LIMBS};
use halo2_base::{
    gates::{
        circuit::CircuitBuilderStage, flex_gate::threads::CommonCircuitBuilder, GateInstructions,
        RangeInstructions,
    },
    halo2_proofs::{
        halo2curves::bn256::{self, Bn256},
        plonk::Error,
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    utils::modulus,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::big_less_than,
    bls12_381::{bls_signature::BlsSignatureChip, pairing::PairingChip, Fp2Chip, Fp2Point, FpChip},
    ecc::{
        hash_to_curve::{ExpandMsgXmd, HashToCurveChip},
        EcPoint, EccChip,
    },
    fields::FieldChip,
};
use halo2curves::bls12_381::{G1Affine, G2Affine};
use itertools::Itertools;
use num_bigint::BigUint;
use std::{env::var, marker::PhantomData, vec};
use tree_hash::TreeHash;

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
pub struct StepCircuit<S: Spec + ?Sized, F: Field> {
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> StepCircuit<S, F> {
    pub fn assign_virtual(
        builder: &mut ShaCircuitBuilder<F, ShaFlexGateManager<F>>,
        fp_chip: &FpChip<F>,
        args: &witness::SyncStepArgs<S>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert!(!args.signature_compressed.is_empty(), "signature expected");

        let range = fp_chip.range();
        let gate = range.gate();
        let sha256_chip = Sha256Chip::new(range);
        let fp2_chip = Fp2Chip::<F>::new(fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        let pairing_chip = PairingChip::new(fp_chip);
        let bls_chip = BlsSignatureChip::new(fp_chip, &pairing_chip);
        let h2c_chip = HashToCurveChip::new(&sha256_chip, &fp2_chip);

        let execution_payload_root: HashInputChunk<QuantumCell<F>> =
            args.execution_payload_root.clone().into_witness();

        let pubkey_affines = args
            .pubkeys_uncompressed
            .as_slice()
            .iter()
            .map(|bytes| {
                G1Affine::from_uncompressed_be(&bytes.as_slice().try_into().unwrap()).unwrap()
            })
            .collect_vec();

        let mut assigned_affines = vec![];
        let mut y_signs_packed = vec![];
        let (agg_pubkey, participation_sum) = Self::aggregate_pubkeys(
            builder.main(),
            fp_chip,
            &pubkey_affines,
            &args.pariticipation_bits,
            &mut assigned_affines,
            &mut y_signs_packed,
        );

        // Commit to the pubkeys using Poseidon hash. This constraints prover to use the pubkeys of the current sync committee,
        // because the same commitment is computed in `CommitteeUpdateCircuit` and stored in the contract at the begining of the period.
        let poseidon_commit = g1_array_poseidon(
            builder.main(),
            fp_chip,
            assigned_affines.into_iter().map(|p| p.x),
            y_signs_packed,
        )?;

        // Compute attested header root
        let attested_slot_bytes: HashInputChunk<_> =
            args.attested_header.slot.as_u64().into_witness();
        let attested_header_state_root = args
            .attested_header
            .state_root
            .as_ref()
            .iter()
            .map(|v| builder.main().load_witness(F::from(*v as u64)))
            .collect_vec();
        let attested_header_root = ssz_merkleize_chunks(
            builder,
            &sha256_chip,
            [
                attested_slot_bytes.clone(),
                args.attested_header.proposer_index.into_witness(),
                args.attested_header.parent_root.as_ref().into_witness(),
                attested_header_state_root.clone().into(),
                args.attested_header.body_root.as_ref().into_witness(),
            ],
        )?;

        // Compute finalized header root
        let finalized_block_body_root = args
            .finalized_header
            .body_root
            .as_ref()
            .iter()
            .map(|&b| builder.main().load_witness(F::from(b as u64)))
            .collect_vec();
        let finalized_slot_bytes: HashInputChunk<_> =
            args.finalized_header.slot.as_u64().into_witness();
        let finalized_header_root = ssz_merkleize_chunks(
            builder,
            &sha256_chip,
            [
                finalized_slot_bytes.clone(),
                args.finalized_header.proposer_index.into_witness(),
                args.finalized_header.parent_root.as_ref().into_witness(),
                args.finalized_header.state_root.as_ref().into_witness(),
                finalized_block_body_root.clone().into(),
            ],
        )?;

        let signing_root = sha256_chip.digest(
            builder,
            HashInput::TwoToOne(
                attested_header_root.into(),
                args.domain.to_vec().into_witness(), // `domain` can't be a constant because will change in next fork.
            ),
        )?;

        let signature =
            Self::assign_signature(builder.main(), &g2_chip, &args.signature_compressed);

        let msghash = h2c_chip.hash_to_curve::<ExpandMsgXmd>(
            builder,
            signing_root.into_iter().map(|av| QuantumCell::Existing(av)),
            S::DST,
        )?;

        bls_chip.assert_valid_signature(builder.main(), signature, msghash, agg_pubkey);

        // Verify finalized block header against current state root via the Merkle "finality" proof
        verify_merkle_proof(
            builder,
            &sha256_chip,
            args.finality_branch
                .iter()
                .map(|w| w.clone().into_witness()),
            finalized_header_root.clone().into(),
            &attested_header_state_root,
            S::FINALIZED_HEADER_INDEX,
        )?;

        // Verify execution payload root against finalized block body via the Merkle "execution" proof
        verify_merkle_proof(
            builder,
            &sha256_chip,
            args.execution_payload_branch
                .iter()
                .map(|w| w.clone().into_witness()),
            execution_payload_root.clone(),
            &finalized_block_body_root,
            S::EXECUTION_STATE_ROOT_INDEX,
        )?;

        // Public Input Commitment
        // See "Onion hashing vs. Input concatenation" in https://github.com/ChainSafe/Spectre/issues/17#issuecomment-1740965182
        let pub_inputs_commit = {
            let participation_sum_le =
                to_bytes_le::<_, 8>(&participation_sum, gate, builder.main());
            let pub_inputs_concat = itertools::chain![
                attested_slot_bytes.into_iter().take(8),
                finalized_slot_bytes.into_iter().take(8),
                participation_sum_le
                    .into_iter()
                    .map(|b| QuantumCell::Existing(b)),
                finalized_header_root
                    .into_iter()
                    .map(|b| QuantumCell::Existing(b)),
                execution_payload_root.into_iter(),
            ]
            .collect_vec();

            let pub_inputs_bytes = sha256_chip
                .digest(builder, pub_inputs_concat)?
                .try_into()
                .unwrap();

            truncate_sha256_into_single_elem(builder.main(), gate, pub_inputs_bytes)
        };

        Ok(vec![pub_inputs_commit, poseidon_commit])
    }

    // Computes public inputs to `StepCircuit` matching the in-circuit logic from `synthesise` method.
    // Note, this function outputes only instances of the `StepCircuit` proof, not the aggregated proof which will also include 12 accumulator limbs.
    pub fn get_instances(args: &SyncStepArgs<S>, limb_bits: usize) -> Vec<Vec<bn256::Fr>> {
        use sha2::Digest;
        const INPUT_SIZE: usize = 8 * 3 + 32 * 2;
        let mut input = [0; INPUT_SIZE];

        let mut attested_slot_le = args.attested_header.slot.as_u64().to_le_bytes().to_vec();
        attested_slot_le.resize(8, 0);
        input[..8].copy_from_slice(&attested_slot_le);

        let mut finalized_slot_le = args.finalized_header.slot.as_u64().to_le_bytes().to_vec();
        finalized_slot_le.resize(8, 0);
        input[8..16].copy_from_slice(&finalized_slot_le);

        let mut participation_le = args
            .pariticipation_bits
            .iter()
            .map(|v| *v as u64)
            .sum::<u64>()
            .to_le_bytes()
            .to_vec();
        participation_le.resize(8, 0);
        input[16..24].copy_from_slice(&participation_le);

        let finalized_header_root: [u8; 32] = args
            .finalized_header
            .tree_hash_root()
            .as_ref()
            .try_into()
            .unwrap();

        input[24..56].copy_from_slice(&finalized_header_root);

        let execution_payload_root = &args.execution_payload_root;
        input[56..88].copy_from_slice(execution_payload_root);

        let poseidon_commitment =
            poseidon_committee_commitment_from_uncompressed(&args.pubkeys_uncompressed, limb_bits);

        let mut public_input_commitment = sha2::Sha256::digest(input).to_vec();
        // Truncate to 253 bits
        public_input_commitment[31] &= 0b00011111;

        vec![vec![
            bn256::Fr::from_bytes_le(&public_input_commitment),
            poseidon_commitment,
        ]]
    }

    /// Decompresses siganure from bytes and assigns it to the circuit.
    fn assign_signature(
        ctx: &mut Context<F>,
        g2_chip: &G2Chip<F>,
        bytes_compressed: &[u8],
    ) -> EcPoint<F, Fp2Point<F>> {
        let sig_affine = G2Affine::from_compressed_be(&bytes_compressed.try_into().unwrap())
            .expect("correct signature");

        g2_chip.assign_point(ctx, sig_affine)
    }

    /// Takes a list of pubkeys and aggregates them.
    /// The outputs are the aggregated pubkey, the sum of participation bits, and a list of assigned pubkeys.
    fn aggregate_pubkeys(
        ctx: &mut Context<F>,
        fp_chip: &FpChip<'_, F>,
        pubkey_affines: &[G1Affine],
        pariticipation_bits: &[bool],
        assigned_affines: &mut Vec<G1Point<F>>,
        y_signs_packed: &mut Vec<AssignedValue<F>>,
    ) -> (G1Point<F>, AssignedValue<F>) {
        let gate = fp_chip.gate();

        let g1_chip = G1Chip::<F>::new(fp_chip);

        let mut participation_bits = vec![];
        let mut y_signs = vec![];

        assert_eq!(pubkey_affines.len(), S::SYNC_COMMITTEE_SIZE);

        for (&pk, is_attested) in
            itertools::multizip((pubkey_affines.iter(), pariticipation_bits.iter().copied()))
        {
            let participation_bit = ctx.load_witness(F::from(is_attested as u64));
            gate.assert_bit(ctx, participation_bit);

            let assigned_affine = g1_chip.assign_point(ctx, pk);

            let half_p = fp_chip.load_constant_uint(
                ctx,
                modulus::<halo2curves::bls12_381::Fq>() / BigUint::from(2u64),
            );
            // y_sign = pk.y * 2 > p
            // becasue of halo2lib doesn't allow to double without carry mod checking 2*y > p gives inconsistent results
            // so instead we perform an equivalent operation: y_sign = pk.y < p/2
            let y_sign = big_less_than::assign(
                fp_chip.range(),
                ctx,
                half_p,
                assigned_affine.y().clone(),
                fp_chip.limb_bits,
                fp_chip.limb_bases[1],
            );

            assigned_affines.push(assigned_affine);
            participation_bits.push(participation_bit);
            y_signs.push(y_sign);
        }

        let mut acc = {
            let x = fp_chip.load_constant(ctx, G1Affine::identity().x);
            let y = fp_chip.load_constant(ctx, G1Affine::identity().y);
            G1Point::new(x, y) // identity
        };
        acc = g1_chip.select(ctx, assigned_affines[0].clone(), acc, participation_bits[0]);
        for (bit, point) in participation_bits
            .iter()
            .copied()
            .zip(assigned_affines.iter_mut())
            .skip(1)
        {
            let is_equal = g1_chip.is_equal(ctx, acc.clone(), point.clone());
            let add = g1_chip.add_unequal(ctx, acc.clone(), point.clone(), true);
            let doub = g1_chip.double(ctx, acc.clone());
            let sum = g1_chip.select(ctx, doub, add, is_equal);
            acc = g1_chip.select(ctx, sum, acc, bit);
        }
        let participation_sum = gate.sum(ctx, participation_bits);

        *y_signs_packed = y_signs
            .chunks(F::CAPACITY as usize - 1)
            .map(|chunk| gate.bits_to_num(ctx, chunk))
            .collect_vec();

        (acc, participation_sum)
    }
}

// Truncate the SHA256 digest to 253 bits and convert to one field element.
pub fn truncate_sha256_into_single_elem<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    hash_bytes: [AssignedValue<F>; 32],
) -> AssignedValue<F> {
    let public_input_commitment_bytes = {
        let mut truncated_hash = hash_bytes;
        let cleared_byte = {
            let bits = gate.num_to_bits(ctx, truncated_hash[31], 8);
            gate.bits_to_num(ctx, &bits[..5])
        };
        truncated_hash[31] = cleared_byte;
        truncated_hash
    };

    let byte_bases = (0..32)
        .map(|i| QuantumCell::Constant(gate.pow_of_two()[i * 8]))
        .collect_vec();

    gate.inner_product(ctx, public_input_commitment_bytes, byte_bases)
}

impl<S: Spec> AppCircuit for StepCircuit<S, bn256::Fr> {
    type Pinning = Eth2ConfigPinning;
    type Witness = witness::SyncStepArgs<S>;

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
        let fp_chip = FpChip::new(&range, LIMB_BITS, NUM_LIMBS);

        let assigned_instances = Self::assign_virtual(&mut builder, &fp_chip, args)?;
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

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{aggregation_circuit::AggregationConfigPinning, util::Halo2ConfigPinning};

    use super::*;
    use ark_std::{end_timer, start_timer};
    use eth_types::Testnet;
    use halo2_base::{
        halo2_proofs::dev::MockProver, halo2_proofs::halo2curves::bn256::Fr, utils::fs::gen_srs,
    };
    use snark_verifier_sdk::{
        evm::{evm_verify, gen_evm_proof_shplonk},
        halo2::aggregation::AggregationCircuit,
        CircuitExt,
    };

    fn load_circuit_args() -> SyncStepArgs<Testnet> {
        serde_json::from_slice(&fs::read("../test_data/sync_step_512.json").unwrap()).unwrap()
    }

    #[test]
    fn test_step_circuit() {
        const K: u32 = 20;
        let witness = load_circuit_args();
        let params: ParamsKZG<Bn256> = gen_srs(K);

        let circuit = StepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            None,
            &witness,
            &params,
        )
        .unwrap();

        let instance = StepCircuit::<Testnet, Fr>::get_instances(&witness, LIMB_BITS);

        let timer = start_timer!(|| "sync_step mock prover");
        let prover = MockProver::<Fr>::run(K, &circuit, instance).unwrap();
        prover.assert_satisfied();
        end_timer!(timer);
    }

    #[test]
    fn test_step_proofgen() {
        const K: u32 = 20;
        let params = gen_srs(K);

        let pk = StepCircuit::<Testnet, Fr>::create_pk(
            &params,
            "../build/sync_step_20.pkey",
            "./config/sync_step_20.json",
            &SyncStepArgs::<Testnet>::default(),
            None,
        );

        let witness = load_circuit_args();

        let _ = StepCircuit::<Testnet, Fr>::gen_proof_shplonk(
            &params,
            &pk,
            "./config/sync_step_20.json",
            &witness,
        )
        .expect("proof generation & verification should not fail");
    }

    #[test]
    fn test_step_evm_verify() {
        const K: u32 = 20;
        let params = gen_srs(K);

        let pk = StepCircuit::<Testnet, Fr>::create_pk(
            &params,
            "../build/sync_step_20.pkey",
            "./config/sync_step_20.json",
            &SyncStepArgs::<Testnet>::default(),
            None,
        );

        let witness = load_circuit_args();

        let pinning = Eth2ConfigPinning::from_path("./config/sync_step_20.json");

        let circuit = StepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Prover,
            Some(pinning),
            &witness,
            &params,
        )
        .unwrap();

        let instances = circuit.instances();
        let proof = gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());
        println!("proof size: {}", proof.len());
        let deployment_code = StepCircuit::<Testnet, Fr>::gen_evm_verifier_shplonk(
            &params,
            &pk,
            None::<String>,
            &witness,
        )
        .unwrap();
        println!("deployment_code size: {}", deployment_code.len());
        evm_verify(deployment_code, instances, proof);
    }

    #[test]
    fn test_step_aggregation_evm() {
        const APP_K: u32 = 20;
        const APP_PK_PATH: &str = "../build/sync_step_20.pkey";
        const APP_PINNING_PATH: &str = "./config/sync_step_20.json";
        const AGG_K: u32 = 23;
        const AGG_PK_PATH: &str = "../build/sync_step_verifier_23.pkey";
        const AGG_CONFIG_PATH: &str = "./config/sync_step_verifier_23.json";
        let params_app = gen_srs(APP_K);
        let pk_app = StepCircuit::<Testnet, Fr>::create_pk(
            &params_app,
            APP_PK_PATH,
            APP_PINNING_PATH,
            &SyncStepArgs::<Testnet>::default(),
            None,
        );

        let witness = load_circuit_args();
        let snark = vec![StepCircuit::<Testnet, Fr>::gen_snark_shplonk(
            &params_app,
            &pk_app,
            APP_PINNING_PATH,
            None::<String>,
            &witness,
        )
        .unwrap()];

        let agg_params = gen_srs(AGG_K);

        let pk = AggregationCircuit::create_pk(
            &agg_params,
            AGG_PK_PATH,
            AGG_CONFIG_PATH,
            &snark.clone(),
            Some(AggregationConfigPinning::new(AGG_K, 19)),
        );

        let agg_config = AggregationConfigPinning::from_path(AGG_CONFIG_PATH);

        let agg_circuit = AggregationCircuit::create_circuit(
            CircuitBuilderStage::Prover,
            Some(agg_config),
            &snark,
            &agg_params,
        )
        .unwrap();

        let instances = agg_circuit.instances();
        let num_instances = agg_circuit.num_instance();

        println!("num_instances: {:?}", num_instances);
        println!("instances: {:?}", instances);

        let proof = gen_evm_proof_shplonk(&agg_params, &pk, agg_circuit, instances.clone());
        println!("proof size: {}", proof.len());
        let deployment_code =
            AggregationCircuit::gen_evm_verifier_shplonk(&agg_params, &pk, None::<String>, &snark)
                .unwrap();
        println!("deployment_code size: {}", deployment_code.len());
        evm_verify(deployment_code, instances, proof);
    }
}
