use std::{
    cell::RefCell,
    collections::HashMap,
    env::{set_var, var},
    fs,
    io::Read,
    iter,
    marker::PhantomData,
    ops::Neg,
    path::Path,
    rc::Rc,
    vec,
};

use crate::{
    builder::Eth2CircuitBuilder,
    gadget::crypto::{
        calculate_ysquared, Fp2Point, FpPoint, G1Chip, G1Point, G2Chip, G2Point, HashInstructions,
        HashToCurveCache, HashToCurveChip, Sha256Chip, ShaCircuitBuilder, ShaThreadBuilder,
    },
    poseidon::{fq_array_poseidon, fq_array_poseidon_native, poseidon_sponge},
    ssz_merkle::{ssz_merkleize_chunks, verify_merkle_proof},
    util::{
        decode_into_field, gen_pkey, AppCircuit, AssignedValueCell, Challenges, Eth2ConfigPinning,
        IntoWitness, ThreadBuilderBase,
    },
    witness::{self, HashInput, HashInputChunk, SyncStepArgs},
};
use eth_types::{AppCurveExt, Field, Spec};
use ff::PrimeField;
use group::UncompressedEncoding;
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, FlexGateConfigParams, GateThreadBuilder,
            MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
        },
        flex_gate::GateStrategy,
        range::{RangeConfig, RangeStrategy},
    },
    safe_types::{GateInstructions, RangeChip, RangeInstructions},
    utils::{decompose, fe_to_bigint, fe_to_biguint, fs::gen_srs, CurveAffineExt, ScalarField},
    AssignedValue, Context,
    QuantumCell::{self, Witness},
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bls12_381::{bls_signature, pairing::PairingChip, Fp12Chip, Fp2Chip, FpChip},
    ecc::{bls_signature::BlsSignatureChip, EcPoint, EccChip},
    fields::{fp12, vector::FieldVector, FieldChip, FieldExtConstructor},
};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance, ProvingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use halo2curves::{
    bls12_381::{Fq, Fq12, Fr, G1Affine, G2Affine, G2Prepared, G1, G2},
    bn256::{self, Bn256},
};
use itertools::Itertools;
use lazy_static::__Deref;
use num_bigint::BigUint;
use pasta_curves::group::{ff, GroupEncoding};
use poseidon::PoseidonChip;
use sha2::{Digest, Sha256};
use snark_verifier_sdk::{evm::gen_evm_verifier_shplonk, CircuitExt};
use ssz_rs::{Merkleized, Node};

#[allow(type_alias_bounds)]
#[derive(Clone, Debug, Default)]
pub struct SyncStepCircuit<S: Spec + ?Sized, F: Field> {
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> SyncStepCircuit<S, F> {
    fn synthesize(
        thread_pool: &mut ShaThreadBuilder<F>,
        range: &RangeChip<F>,
        args: &witness::SyncStepArgs<S>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert!(
            !args.signature_compressed.is_empty(),
            "no attestations supplied"
        );

        let gate = range.gate();
        let sha256_chip = Sha256Chip::new(range);
        let fp_chip = FpChip::<F>::new(range, G2::LIMB_BITS, G2::NUM_LIMBS);
        let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
        let g1_chip = EccChip::new(fp2_chip.fp_chip());
        let g2_chip = EccChip::new(&fp2_chip);
        let fp12_chip = Fp12Chip::<F>::new(fp2_chip.fp_chip());
        let pairing_chip = PairingChip::new(&fp_chip);
        let bls_chip = bls_signature::BlsSignatureChip::new(&fp_chip, pairing_chip);
        let h2c_chip = HashToCurveChip::<S, F, _>::new(&sha256_chip);

        let execution_payload_root: HashInputChunk<QuantumCell<F>> =
            args.execution_payload_root.clone().into_witness();

        let pubkey_affines = args
            .pubkeys_uncompressed
            .iter()
            .cloned()
            .map(|bytes| {
                G1Affine::from_uncompressed_unchecked(&bytes.as_slice().try_into().unwrap())
                    .unwrap()
            })
            .collect_vec();

        let mut assigned_affines = vec![];
        let (agg_pubkey, participation_sum) = Self::aggregate_pubkeys(
            thread_pool.main(),
            &fp_chip,
            &pubkey_affines,
            &args.pariticipation_bits,
            &mut assigned_affines,
        );
        let poseidon_commit = fq_array_poseidon(
            thread_pool.main(),
            range.gate(),
            assigned_affines.iter().map(|p| &p.x),
        )?;

        let fp12_one = {
            use ff::Field;
            fp12_chip.load_constant(thread_pool.main(), Fq12::one())
        };
        let mut h2c_cache = HashToCurveCache::<F>::default();

        // Verify attestted header
        let attested_slot_bytes: HashInputChunk<_> = args.attested_header.slot.into_witness();
        let attested_header_state_root = args
            .attested_header
            .state_root
            .as_ref()
            .iter()
            .map(|v| thread_pool.main().load_witness(F::from(*v as u64)))
            .collect_vec();
        let attested_header = ssz_merkleize_chunks(
            thread_pool,
            &sha256_chip,
            [
                attested_slot_bytes.clone(),
                args.attested_header.proposer_index.into_witness(),
                args.attested_header.parent_root.as_ref().into_witness(),
                attested_header_state_root.clone().into(),
                args.attested_header.body_root.as_ref().into_witness(),
            ],
        )?;
        let g1_neg = g1_chip.load_private_unchecked(
            thread_pool.main(),
            G1::generator_affine().neg().into_coordinates(),
        );

        let finalized_block_body_root = args
            .finalized_header
            .body_root
            .as_ref()
            .iter()
            .map(|&b| thread_pool.main().load_witness(F::from(b as u64)))
            .collect_vec();

        let finalized_slot_bytes: HashInputChunk<_> = args.finalized_header.slot.into_witness();
        let finalized_header_root = ssz_merkleize_chunks(
            thread_pool,
            &sha256_chip,
            [
                finalized_slot_bytes.clone(),
                args.finalized_header.proposer_index.into_witness(),
                args.finalized_header.parent_root.as_ref().into_witness(),
                args.finalized_header.state_root.as_ref().into_witness(),
                finalized_block_body_root.clone().into(),
            ],
        )?;

        let signing_root = sha256_chip
            .digest::<64>(
                thread_pool,
                HashInput::TwoToOne(attested_header.into(), args.domain.to_vec().into_witness()),
                false,
            )?
            .output_bytes;

        let g1_neg = g1_chip.load_private_unchecked(
            thread_pool.main(),
            G1::generator_affine().neg().into_coordinates(),
        );

        let signature =
            Self::assign_signature(thread_pool.main(), &g2_chip, &args.signature_compressed);

        let msghash = h2c_chip.hash_to_curve::<G2>(
            thread_pool,
            &fp_chip,
            signing_root.into(),
            &mut h2c_cache,
        )?;

        let res =
            bls_chip.verify_pairing(thread_pool.main(), signature, msghash, agg_pubkey, g1_neg);
        fp12_chip.assert_equal(thread_pool.main(), res, fp12_one);

        // verify finalized block header against current beacon state merkle proof
        verify_merkle_proof(
            thread_pool,
            &sha256_chip,
            args.finality_branch
                .iter()
                .map(|w| w.clone().into_witness()),
            finalized_header_root.clone().into(),
            &attested_header_state_root,
            S::FINALIZED_HEADER_INDEX,
        )?;

        // verify execution state root against finilized block body merkle proof
        verify_merkle_proof(
            thread_pool,
            &sha256_chip,
            args.execution_payload_branch
                .iter()
                .map(|w| w.clone().into_witness()),
            execution_payload_root.clone(),
            &finalized_block_body_root,
            S::EXECUTION_STATE_ROOT_INDEX,
        )?;

        // Public Input Commitment
        let participation_sum_le =
            to_bytes_le::<_, 8>(thread_pool.main(), gate, &participation_sum);

        let poseidon_commit_le = to_bytes_le::<_, 32>(thread_pool.main(), gate, &poseidon_commit);

        // See "Onion hashing vs. Input concatenation" in https://github.com/ChainSafe/Spectre/issues/17#issuecomment-1740965182
        let public_inputs_concat = itertools::chain![
            attested_slot_bytes.bytes.into_iter().take(8),
            finalized_slot_bytes.bytes.into_iter().take(8),
            participation_sum_le
                .into_iter()
                .map(|b| QuantumCell::Existing(b)),
            finalized_header_root
                .into_iter()
                .map(|b| QuantumCell::Existing(b)),
            execution_payload_root.bytes.into_iter(),
            poseidon_commit_le
                .into_iter()
                .map(|b| QuantumCell::Existing(b)),
        ]
        .collect_vec();

        let pi_hash_bytes = sha256_chip
            .digest::<{ 8 * 3 + 32 * 3 }>(
                thread_pool,
                HashInputChunk::new(public_inputs_concat).into(),
                false,
            )?
            .output_bytes;

        let pi_commit = truncate_sha256_into_single_elem(thread_pool.main(), range, pi_hash_bytes);

        Ok(vec![pi_commit])
    }

    pub fn instance_commitment(args: &SyncStepArgs<S>) -> bn256::Fr {
        const INPUT_SIZE: usize = 8 * 3 + 32 * 3;
        let mut input = [0; INPUT_SIZE];

        let mut attested_slot_le = args.attested_header.slot.to_le_bytes().to_vec();
        attested_slot_le.resize(8, 0);
        input[..8].copy_from_slice(&attested_slot_le);

        let mut finalized_slot_le = args.finalized_header.slot.to_le_bytes().to_vec();
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
            .clone()
            .hash_tree_root()
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();

        input[24..56].copy_from_slice(&finalized_header_root);

        let execution_payload_root = &args.execution_payload_root;
        input[56..88].copy_from_slice(execution_payload_root);

        let pubkey_affines = args
            .pubkeys_uncompressed
            .iter()
            .cloned()
            .map(|bytes| {
                G1Affine::from_uncompressed_unchecked(&bytes.as_slice().try_into().unwrap())
                    .unwrap()
            })
            .collect_vec();
        let poseidon_commitment =
            fq_array_poseidon_native::<bn256::Fr>(pubkey_affines.iter().map(|p| p.x)).unwrap();
        let poseidon_commitment_le = poseidon_commitment.to_bytes_le();
        input[88..].copy_from_slice(&poseidon_commitment_le);

        let mut public_input_commitment = sha2::Sha256::digest(input).to_vec();
        // Truncate to 253 bits
        public_input_commitment[31] &= 0b00011111;
        bn256::Fr::from_bytes_le(&public_input_commitment)
    }
}

// Truncate the SHA256 digest to 253 bits and convert to one field element.
pub fn truncate_sha256_into_single_elem<F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    hash_bytes: [AssignedValue<F>; 32],
) -> AssignedValue<F> {
    let public_input_commitment_bytes = {
        let mut truncated_hash = hash_bytes;
        let cleared_byte = clear_3_bits(ctx, range, &truncated_hash[31]);
        truncated_hash[31] = cleared_byte;
        truncated_hash
    };

    let byte_bases = (0..32)
        .map(|i| QuantumCell::Constant(range.gate().pow_of_two()[i * 8]))
        .collect_vec();

    range
        .gate()
        .inner_product(ctx, public_input_commitment_bytes, byte_bases)
}

/// Clears the 3 first least significat bits.
/// This function emulates bitwise and on 00011111 (0x1F): `b & 0b00011111` = c
pub fn clear_3_bits<F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    b: &AssignedValue<F>,
) -> AssignedValue<F> {
    let gate = range.gate();
    // Shift `a` three bits to the left (equivalent to a << 3 mod 256)
    let b_shifted = gate.mul(ctx, *b, QuantumCell::Constant(F::from(8)));
    // since b_shifted can at max be 255*8=2^4 we use 16 bits for modulo division.
    let b_shifted = range.div_mod(ctx, b_shifted, BigUint::from(256u64), 16).1;

    // Shift `s` three bits to the right (equivalent to s >> 3) to zeroing the first three bits (MSB) of `a`.
    range.div_mod(ctx, b_shifted, BigUint::from(8u64), 8).0
}

pub fn to_bytes_le<F: Field, const MAX_BYTES: usize>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    a: &AssignedValue<F>,
) -> Vec<AssignedValue<F>> {
    let byte_bases = (0..MAX_BYTES)
        .map(|i| QuantumCell::Constant(gate.pow_of_two()[i * 8]))
        .collect_vec();

    let assigned_bytes = a
        .value()
        .to_bytes_le()
        .into_iter()
        .take(MAX_BYTES)
        .map(|v| ctx.load_witness(F::from(v as u64)))
        .collect_vec();

    // Constrain poseidon bytes to be equal to the recovered checksum
    let checksum = gate.inner_product(ctx, assigned_bytes.clone(), byte_bases);
    ctx.constrain_equal(&checksum, &checksum);

    assigned_bytes
}

impl<S: Spec, F: Field> SyncStepCircuit<S, F> {
    fn assign_signature(
        ctx: &mut Context<F>,
        g2_chip: &G2Chip<F>,
        bytes_compressed: &[u8],
    ) -> EcPoint<F, Fp2Point<F>> {
        let sig_affine = G2Affine::from_bytes(&bytes_compressed.to_vec().try_into().unwrap())
            .expect("correct signature");

        g2_chip.load_private_unchecked(ctx, sig_affine.into_coordinates())
    }

    /// Takes a list of pubkeys and aggregates them.
    fn aggregate_pubkeys(
        ctx: &mut Context<F>,
        fp_chip: &FpChip<'_, F>,
        pubkey_affines: &[G1Affine],
        pariticipation_bits: &[bool],
        assigned_affines: &mut Vec<G1Point<F>>,
    ) -> (G1Point<F>, AssignedValue<F>) {
        let range = fp_chip.range();
        let gate = fp_chip.gate();

        let g1_chip = G1Chip::<F>::new(fp_chip);

        let pubkey_compressed_len = G1::BYTES_COMPRESSED;

        let mut participation_bits = vec![];

        assert_eq!(pubkey_affines.len(), S::SYNC_COMMITTEE_SIZE);

        for (&pk, is_attested) in
            itertools::multizip((pubkey_affines.iter(), pariticipation_bits.iter().copied()))
        {
            let participation_bit = ctx.load_witness(F::from(is_attested as u64));
            gate.assert_bit(ctx, participation_bit);

            let assigned_pk = g1_chip.assign_point_unchecked(ctx, pk);

            // Square y coordinate
            let ysq = fp_chip.mul(ctx, assigned_pk.y.clone(), assigned_pk.y.clone());
            // Calculate y^2 using the elliptic curve equation
            let ysq_calc = calculate_ysquared::<F, G1>(ctx, fp_chip, assigned_pk.x.clone());
            // Constrain witness y^2 to be equal to calculated y^2
            fp_chip.assert_equal(ctx, ysq, ysq_calc);

            // *Note:* normally, we would need to take into account the sign of the y coordinate, but
            // because we are concerned only with signature forgery, if this is the wrong
            // sign, the signature will be invalid anyway and thus verification fails.

            assigned_affines.push(assigned_pk);
            participation_bits.push(participation_bit);
        }

        let rand_point = g1_chip.load_random_point::<G1Affine>(ctx);
        let mut acc = rand_point.clone();
        for (bit, point) in participation_bits
            .iter()
            .copied()
            .zip(assigned_affines.iter_mut())
        {
            let sum = g1_chip.add_unequal(ctx, acc.clone(), point.clone(), true);
            acc = g1_chip.select(ctx, sum, acc, bit);
        }
        let agg_pubkey = g1_chip.sub_unequal(ctx, acc, rand_point, false);
        let participation_sum = gate.sum(ctx, participation_bits);

        (agg_pubkey, participation_sum)
    }
}

impl<S: Spec> AppCircuit for SyncStepCircuit<S, bn256::Fr> {
    type Pinning = Eth2ConfigPinning;
    type Witness = witness::SyncStepArgs<S>;

    fn create_circuit(
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
        args: &Self::Witness,
    ) -> Result<impl crate::util::PinnableCircuit<bn256::Fr>, Error> {
        let mut thread_pool = ShaThreadBuilder::from_stage(stage);
        let range = RangeChip::<bn256::Fr>::new(RangeStrategy::Vertical, 8);

        let assigned_instances = Self::synthesize(&mut thread_pool, &range, args)?;

        match stage {
            CircuitBuilderStage::Prover => {}
            _ => {
                thread_pool.config(
                    params.k() as usize,
                    Some(
                        var("MINIMUM_ROWS")
                            .unwrap_or_else(|_| "0".to_string())
                            .parse()
                            .unwrap(),
                    ),
                );
            }
        }

        Ok(Eth2CircuitBuilder::from_stage(
            assigned_instances,
            thread_pool,
            pinning.map(|p| p.break_points),
            stage,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env::{set_var, var},
        fs,
        os::unix::thread,
    };

    use crate::{
        builder::Eth2CircuitBuilder,
        util::{full_prover, full_verifier, gen_pkey, Halo2ConfigPinning},
        witness::SyncStepArgs,
    };

    use super::*;
    use ark_std::{end_timer, start_timer};
    use eth_types::Testnet;
    use group::Group;
    use halo2_base::{
        gates::{
            builder::{CircuitBuilderStage, FlexGateConfigParams},
            flex_gate::GateStrategy,
            range::RangeStrategy,
        },
        utils::{decompose, fs::gen_srs},
    };
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{keygen_pk, keygen_vk, Circuit, FloorPlanner},
        poly::kzg::commitment::ParamsKZG,
    };
    use halo2curves::{bls12_381::G1Affine, bn256::Bn256};
    use pasta_curves::group::UncompressedEncoding;
    use rand::{rngs::OsRng, thread_rng};
    use rayon::iter::ParallelIterator;
    use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator};
    use snark_verifier_sdk::{
        evm::{encode_calldata, evm_verify, gen_evm_proof_shplonk},
        halo2::{aggregation::AggregationCircuit, gen_proof_shplonk, gen_snark_shplonk},
        CircuitExt, SHPLONK,
    };

    fn load_circuit_args() -> SyncStepArgs<Testnet> {
        serde_json::from_slice(&fs::read("../test_data/sync_step_512.json").unwrap()).unwrap()
    }

    #[test]
    fn test_sync_circuit() {
        const K: u32 = 21;
        let params = gen_srs(K);

        let witness = load_circuit_args();

        let pinning = Eth2ConfigPinning::from_path("./config/sync_step.json");

        let circuit = SyncStepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            Some(pinning),
            &params,
            &witness,
        )
        .unwrap();

        let sync_pi_commit = SyncStepCircuit::<Testnet, Fr>::instance_commitment(&witness);

        let timer = start_timer!(|| "sync_step mock prover");
        let prover = MockProver::<Fr>::run(K, &circuit, vec![vec![sync_pi_commit]]).unwrap();
        prover.assert_satisfied_par();
        end_timer!(timer);
    }

    #[test]
    fn test_sync_proofgen() {
        const K: u32 = 22;
        let params = gen_srs(K);

        let pk = SyncStepCircuit::<Testnet, Fr>::read_or_create_pk(
            &params,
            "../build/sync_step.pkey",
            "./config/sync_step.json",
            false,
            &SyncStepArgs::<Testnet>::default(),
        );

        let witness = load_circuit_args();

        let pinning = Eth2ConfigPinning::from_path("./config/sync_step.json");

        let circuit = SyncStepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Prover,
            Some(pinning),
            &params,
            &witness,
        )
        .unwrap();

        let instances = circuit.instances();
        let proof = full_prover(&params, &pk, circuit, instances.clone());

        assert!(full_verifier(&params, pk.get_vk(), proof, instances))
    }

    #[test]
    fn test_sync_evm_verify() {
        const K: u32 = 22;
        let params = gen_srs(K);

        let pk = SyncStepCircuit::<Testnet, Fr>::read_or_create_pk(
            &params,
            "../build/sync_step.pkey",
            "./config/sync_step.json",
            false,
            &SyncStepArgs::<Testnet>::default(),
        );

        let witness = load_circuit_args();

        let pinning = Eth2ConfigPinning::from_path("./config/sync_step.json");

        let circuit = SyncStepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Prover,
            Some(pinning),
            &params,
            &witness,
        )
        .unwrap();

        let num_instances = circuit.num_instance();
        let instances = circuit.instances();
        let proof = gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());
        println!("proof size: {}", proof.len());
        let deployment_code = SyncStepCircuit::<Testnet, Fr>::gen_evm_verifier_shplonk(
            &params,
            &pk,
            None::<String>,
            &witness,
        )
        .unwrap();
        println!("deployment_code size: {}", deployment_code.len());
        evm_verify(deployment_code, instances, proof);
    }
}
