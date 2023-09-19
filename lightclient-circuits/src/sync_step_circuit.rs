use std::{
    cell::RefCell,
    collections::HashMap,
    env::{set_var, var},
    fs, iter,
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
    poseidon::{fq_array_poseidon, g1_array_poseidon_native, poseidon_sponge},
    ssz_merkle::{ssz_merkleize_chunks, verify_merkle_proof},
    util::{
        decode_into_field, gen_pkey, AppCircuitExt, AssignedValueCell, Challenges, IntoWitness,
        ThreadBuilderBase,
    },
    witness::{self, HashInput, HashInputChunk, SyncStepArgs},
};
use eth_types::{AppCurveExt, Field, Spec};
use ethereum_consensus::capella::{self, mainnet::*};
use ff::PrimeField;
use group::UncompressedEncoding;
use halo2_base::{
    gates::{
        builder::{
            FlexGateConfigParams, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
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
pub struct SyncStepCircuit<S: Spec, F: Field> {
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> SyncStepCircuit<S, F> {
    pub fn synthesize(
        &self,
        thread_pool: &mut ShaThreadBuilder<F>,
        range: &RangeChip<F>,
        args: &witness::SyncStepArgs<S>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert!(
            !args.signature_compressed.is_empty(),
            "no attestations supplied"
        );

        let sha256_chip = Sha256Chip::new(range);
        let fp_chip = FpChip::<F>::new(range, G2::LIMB_BITS, G2::NUM_LIMBS);
        let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
        let g1_chip = EccChip::new(fp2_chip.fp_chip());
        let g2_chip = EccChip::new(&fp2_chip);
        let fp12_chip = Fp12Chip::<F>::new(fp2_chip.fp_chip());
        let pairing_chip = PairingChip::new(&fp_chip);
        let bls_chip = bls_signature::BlsSignatureChip::new(&fp_chip, pairing_chip);
        let h2c_chip = HashToCurveChip::<S, F, _>::new(&sha256_chip);

        // let beacon_state_root = args
        //     .beacon_state_root
        //     .iter()
        //     .map(|&b| thread_pool.main().load_witness(F::from(b as u64)))
        //     .collect_vec();

        let execution_state_root: HashInputChunk<QuantumCell<F>> =
            args.execution_state_root.clone().into_witness();

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

        // Verify attested header
        let attested_header = ssz_merkleize_chunks(
            thread_pool,
            &sha256_chip,
            [
                args.attested_block.slot.into_witness(),
                args.attested_block.proposer_index.into_witness(),
                args.attested_block.parent_root.as_ref().into_witness(),
                args.attested_block.state_root.as_ref().into_witness(),
                args.attested_block.body_root.as_ref().into_witness(),
            ],
        )?;

        let finalized_block_body_root = args
            .finalized_block
            .body_root
            .as_ref()
            .iter()
            .map(|&b| thread_pool.main().load_witness(F::from(b as u64)))
            .collect_vec();

        let finalized_header = ssz_merkleize_chunks(
            thread_pool,
            &sha256_chip,
            [
                args.finalized_block.slot.into_witness(),
                args.finalized_block.proposer_index.into_witness(),
                args.finalized_block.parent_root.as_ref().into_witness(),
                args.finalized_block.state_root.as_ref().into_witness(),
                args.finalized_block.body_root.as_ref().into_witness(),
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

        println!(
            "circuit finalized_header: {:?}",
            hex::encode(
                &finalized_header
                    .iter()
                    .map(|v| v.value().get_lower_32() as u8)
                    .collect_vec()
            )
        );

        let bs_root = args
            .attested_block
            .state_root
            .as_ref()
            .iter()
            .map(|v| thread_pool.main().load_witness(F::from(*v as u64)))
            .collect_vec();

        // verify finalized block header against current beacon state merkle proof
        verify_merkle_proof(
            thread_pool,
            &sha256_chip,
            args.finality_merkle_branch
                .iter()
                .map(|w| w.clone().into_witness()),
            finalized_header.clone().into(),
            &bs_root,
            S::FINALIZED_HEADER_INDEX,
        )?;

        // verify execution state root against finilized block body merkle proof
        verify_merkle_proof(
            thread_pool,
            &sha256_chip,
            args.execution_merkle_branch
                .iter()
                .map(|w| w.clone().into_witness()),
            execution_state_root.clone(),
            &finalized_block_body_root,
            S::EXECUTION_STATE_ROOT_INDEX,
        )?;

        // Public Input Commitment
        let gate = range.gate();

        let attested_slot = args.attested_block.slot.into_witness();
        let finalized_slot = args.finalized_block.slot.into_witness();
        let h = sha256_chip.digest::<64>(
            thread_pool,
            HashInput::TwoToOne(attested_slot, finalized_slot),
            false,
        )?;
        // TODO: Investigate if we should hash it all concatinated in one go
        let h = sha256_chip.digest::<64>(
            thread_pool,
            HashInput::TwoToOne(h.output_bytes.into(), finalized_header.into()),
            false,
        )?;

        let byte_base = (0..32)
            .map(|i| QuantumCell::Constant(gate.pow_of_two()[i * 8]))
            .collect_vec();

        let participation_sum_bytes = participation_sum
            .value()
            .to_bytes_le()
            .into_iter()
            .map(|v| thread_pool.main().load_witness(F::from(v as u64)))
            .collect_vec();

        let h = sha256_chip.digest::<64>(
            thread_pool,
            HashInput::TwoToOne(
                h.output_bytes.into(),
                participation_sum_bytes.clone().into(),
            ),
            false,
        )?;
        // Constrain the participation sum bytes to be equal to the participation_sum
        let sum_field = gate.inner_product(
            thread_pool.main(),
            participation_sum_bytes,
            byte_base.clone(),
        );
        thread_pool
            .main()
            .constrain_equal(&sum_field, &participation_sum);

        // let h = sha256_chip.digest::<64>(
        //     thread_pool,
        //     HashInput::TwoToOne(h.output_bytes.into(), execution_state_root),
        //     false,
        // )?;

        let poseidon_commit_bytes = poseidon_commit
            .value()
            .to_bytes_le()
            .into_iter()
            .map(|v| thread_pool.main().load_witness(F::from(v as u64)))
            .collect_vec();
        // Constrain poseidon bytes to be equal to the poseidon_commit_value
        let poseidon_commit_field = gate.inner_product(
            thread_pool.main(),
            poseidon_commit_bytes.clone(),
            byte_base.clone(),
        );
        thread_pool
            .main()
            .constrain_equal(&poseidon_commit_field, &poseidon_commit);

        let public_input_commitment = sha256_chip.digest::<64>(
            thread_pool,
            HashInput::TwoToOne(h.output_bytes.into(), poseidon_commit_bytes.into()),
            false,
        )?;

        // Truncate the public input commitment to 253 bits and convert to one field element
        let mut public_input_commitment_bytes = public_input_commitment.output_bytes;
        let cleared_byte = clear_3_bits(
            range,
            &public_input_commitment_bytes[31],
            thread_pool.main(),
        );
        public_input_commitment_bytes[31] = cleared_byte;

        let pi_field =
            gate.inner_product(thread_pool.main(), public_input_commitment_bytes, byte_base);
        Ok(vec![pi_field])
    }

    pub fn instance(args: SyncStepArgs<S>) -> Vec<Vec<bn256::Fr>> {
        let mut input: [u8; 64] = [0; 64];

        let mut attested_slot = args.attested_block.slot.to_le_bytes().to_vec();
        let mut finalized_slot = args.finalized_block.slot.to_le_bytes().to_vec();
        attested_slot.resize(32, 0);
        finalized_slot.resize(32, 0);

        input[..32].copy_from_slice(&attested_slot);
        input[32..].copy_from_slice(&finalized_slot);
        let h = sha2::Sha256::digest(input).to_vec();

        let finalized_header_root: [u8; 32] = args
            .finalized_block
            .clone()
            .hash_tree_root()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();

        input[..32].copy_from_slice(&h);
        input[32..].copy_from_slice(&finalized_header_root);
        let h = sha2::Sha256::digest(input).to_vec();

        let mut participation = args
            .pariticipation_bits
            .iter()
            .map(|v| *v as u64)
            .sum::<u64>()
            .to_le_bytes()
            .to_vec();
        participation.resize(32, 0);

        input[..32].copy_from_slice(&h);
        input[32..].copy_from_slice(&participation);
        let h = sha2::Sha256::digest(input).to_vec();

        // let execution_state_root = &args.execution_state_root;
        // input[..32].copy_from_slice(&h);
        // input[32..].copy_from_slice(execution_state_root);
        // let h = sha2::Sha256::digest(input).to_vec();

        let pubkey_affines = args
            .pubkeys_uncompressed
            .iter()
            .cloned()
            .map(|bytes| {
                G1Affine::from_uncompressed_unchecked(&bytes.as_slice().try_into().unwrap())
                    .unwrap()
            })
            .collect_vec();
        let poseidon_commitment = g1_array_poseidon_native::<F>(&pubkey_affines).unwrap();
        let poseidon_commitment_bytes = poseidon_commitment.to_bytes_le();
        input[..32].copy_from_slice(&h);
        input[32..].copy_from_slice(&poseidon_commitment_bytes);

        let mut public_input_commitment = sha2::Sha256::digest(input).to_vec();
        // Truncate to 253 bits
        public_input_commitment[31] &= 0b00011111;
        let pi_field = bn256::Fr::from_bytes_le(&public_input_commitment);
        vec![vec![pi_field]]
    }
}

/// Clears the 3 first least significat bits.
/// This function emulates bitwise and on 00011111 (0x1F): `b & 0b00011111` = c
fn clear_3_bits<F: Field>(
    range: &RangeChip<F>,
    b: &AssignedValue<F>,
    ctx: &mut Context<F>,
) -> AssignedValue<F> {
    let gate = range.gate();
    // Shift `a` three bits to the left (equivalent to a << 3 mod 256)
    let b_shifted = gate.mul(ctx, *b, QuantumCell::Constant(F::from(8)));
    // since b_shifted can at max be 255*8=2^4 we use 16 bits for modulo division.
    let b_shifted = range.div_mod(ctx, b_shifted, BigUint::from(256u64), 16).1;

    // Shift `s` three bits to the right (equivalent to s >> 3) to zeroing the first three bits (MSB) of `a`.
    range.div_mod(ctx, b_shifted, BigUint::from(8u64), 8).0
}

impl<S: Spec, F: Field> SyncStepCircuit<S, F> {
    fn assign_signature(
        ctx: &mut Context<F>,
        g2_chip: &G2Chip<F>,
        bytes_compressed: &[u8],
    ) -> EcPoint<F, Fp2Point<F>> {
        let sig_affine =
            G2Affine::from_bytes(&bytes_compressed.to_vec().try_into().unwrap()).unwrap();

        g2_chip.load_private_unchecked(ctx, sig_affine.into_coordinates())
    }

    /// Takes a list of pubkeys and aggregates them.
    fn aggregate_pubkeys<'a>(
        ctx: &mut Context<F>,
        fp_chip: &FpChip<'a, F>,
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

impl<S: Spec> AppCircuitExt<bn256::Fr> for SyncStepCircuit<S, bn256::Fr> {
    fn setup(
        k: usize,
        out: Option<&Path>,
    ) -> (
        ParamsKZG<bn256::Bn256>,
        ProvingKey<bn256::G1Affine>,
        MultiPhaseThreadBreakPoints,
    ) {
        let args = witness::SyncStepArgs::<S>::default();
        let circuit = SyncStepCircuit::<S, bn256::Fr>::default();
        let range = RangeChip::<bn256::Fr>::new(RangeStrategy::Vertical, 8);
        let mut thread_pool = ShaThreadBuilder::keygen();

        let assigned_instances = circuit.synthesize(&mut thread_pool, &range, &args).unwrap();
        let config = thread_pool.config(k, Some(109));

        let params = gen_srs(k as u32);

        let circuit = Eth2CircuitBuilder::keygen(assigned_instances, thread_pool);

        let pk = gen_pkey(|| "sync_step", &params, out, &circuit).unwrap();

        let break_points = circuit.break_points();

        (params, pk, break_points)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env::{set_var, var},
        fs,
    };

    use crate::{
        builder::Eth2CircuitBuilder,
        util::{full_prover, full_verifier, gen_pkey},
        witness::{SyncStepArgs, Validator},
    };

    use super::*;
    use ark_std::{end_timer, start_timer};
    use eth_types::Test;
    use ethereum_consensus::builder;
    use halo2_base::{
        gates::{
            builder::{CircuitBuilderStage, FlexGateConfigParams},
            flex_gate::GateStrategy,
            range::RangeStrategy,
        },
        utils::{fs::gen_srs, ScalarField},
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
    use rand::rngs::OsRng;
    use rayon::iter::ParallelIterator;
    use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator};
    use snark_verifier_sdk::{
        evm::{encode_calldata, evm_verify, gen_evm_proof_shplonk},
        halo2::{aggregation::AggregationCircuit, gen_proof_shplonk, gen_snark_shplonk},
        CircuitExt, SHPLONK,
    };

    fn load_circuit_with_data(
        thread_pool: &mut ShaThreadBuilder<Fr>,
        k: usize,
    ) -> (Vec<AssignedValue<Fr>>, SyncStepArgs<Test>) {
        let args: SyncStepArgs<Test> =
            serde_json::from_slice(&fs::read("../test_data/sync_step.json").unwrap()).unwrap();
        let circuit = SyncStepCircuit::<Test, bn256::Fr>::default();
        let range = RangeChip::<bn256::Fr>::new(RangeStrategy::Vertical, 8);

        let instance = circuit.synthesize(thread_pool, &range, &args).unwrap();

        let config = thread_pool.config(k, None);
        set_var("LOOKUP_BITS", (config.k - 1).to_string());
        println!("params used: {:?}", config);

        (instance, args)
    }

    #[test]
    fn test_sync_circuit() {
        const K: usize = 20;

        let mut builder = ShaThreadBuilder::mock();
        let (assigned_instances, args) = load_circuit_with_data(&mut builder, K);

        let circuit = Eth2CircuitBuilder::mock(assigned_instances, builder);

        let timer = start_timer!(|| "sync circuit mock prover");
        let prover = MockProver::<Fr>::run(K as u32, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied_par();
        end_timer!(timer);
    }

    #[test]
    fn test_sync_proofgen() {
        const K: usize = 20;

        let (params, pk, break_points) = SyncStepCircuit::<Test, Fr>::setup(K, None);

        let mut builder = ShaThreadBuilder::prover();
        let (assigned_instances, args) = load_circuit_with_data(&mut builder, K);
        let circuit = Eth2CircuitBuilder::prover(assigned_instances, builder, break_points);

        let instances = SyncStepCircuit::<Test, bn256::Fr>::instance(args);
        let proof = full_prover(&params, &pk, circuit, instances.clone());

        assert!(full_verifier(&params, pk.get_vk(), proof, instances))
    }

    #[test]
    fn test_sync_evm_verify() {
        const K: usize = 22;

        let (params, pk, break_points) = SyncStepCircuit::<Test, Fr>::setup(K, None);

        let mut builder = ShaThreadBuilder::prover();
        let (assigned_instances, args) = load_circuit_with_data(&mut builder, K);
        let circuit = Eth2CircuitBuilder::prover(assigned_instances, builder, break_points);
        let instances = SyncStepCircuit::<Test, bn256::Fr>::instance(args);

        let num_instance = vec![instances[0].len()];
        let deployment_code = gen_evm_verifier_shplonk::<
            Eth2CircuitBuilder<Fr, ShaThreadBuilder<Fr>>,
        >(&params, pk.get_vk(), num_instance, None);

        let proof = gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());

        evm_verify(deployment_code, instances, proof);
    }
}
