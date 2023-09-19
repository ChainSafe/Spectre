use crate::{
    builder::Eth2CircuitBuilder,
    gadget::crypto::{
        calculate_ysquared, Fp2Point, FpPoint, G1Chip, G1Point, G2Chip, G2Point, HashInstructions,
        HashToCurveCache, HashToCurveChip, Sha256ChipWide, ShaBitThreadBuilder, ShaCircuitBuilder,
    },
    poseidon::{fq_array_poseidon, g1_array_poseidon_native, poseidon_sponge},
    ssz_merkle::ssz_merkleize_chunks,
    util::{
        decode_into_field, gen_pkey, AppCircuitExt, AssignedValueCell, Challenges, IntoWitness,
        ThreadBuilderBase,
    },
    witness::{self, HashInput, HashInputChunk},
};
use eth_types::{AppCurveExt, Field, Spec};
use ethereum_consensus::phase0::BeaconBlockHeader;
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
    utils::{fs::gen_srs, CurveAffineExt},
    AssignedValue, Context, QuantumCell,
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
    plonk::{Circuit, ConstraintSystem, Error, ProvingKey},
    poly::kzg::commitment::ParamsKZG,
};
use halo2curves::{
    bls12_381::{Fq, Fq12, G1Affine, G2Affine, G2Prepared, G1, G2},
    bn256,
};
use itertools::Itertools;
use lazy_static::__Deref;
use num_bigint::BigUint;
use pasta_curves::group::{ff, GroupEncoding};
use poseidon::PoseidonChip;
use snark_verifier_sdk::CircuitExt;
use ssz_rs::Merkleized;
use std::{
    cell::{Ref, RefCell},
    collections::HashMap,
    env::{set_var, var},
    fs, iter,
    marker::PhantomData,
    ops::Neg,
    path::Path,
    rc::Rc,
    vec,
};

#[allow(type_alias_bounds)]
#[derive(Clone, Debug, Default)]
pub struct CommitteeUpdateCircuit<S: Spec, F: Field> {
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> CommitteeUpdateCircuit<S, F> {
    fn synthesize(
        &self,
        thread_pool: &mut ShaBitThreadBuilder<F>,
        range: &RangeChip<F>,
        args: &witness::CommitteeRotationArgs<S, F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let fp_chip = FpChip::<F>::new(range, G2::LIMB_BITS, G2::NUM_LIMBS);
        let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
        let g1_chip = EccChip::new(fp2_chip.fp_chip());

        let sha256_chip = Sha256ChipWide::new(range, args.randomness);

        let compressed_encodings = args
            .pubkeys_compressed
            .iter()
            .map(|bytes| {
                thread_pool
                    .main()
                    .assign_witnesses(bytes.iter().map(|&b| F::from(b as u64)))
            })
            .collect_vec();

        let root =
            Self::sync_committee_root_ssz(thread_pool, &sha256_chip, compressed_encodings.clone())?;

        let pubkeys_x = Self::decode_pubkeys_x(thread_pool.main(), &fp_chip, compressed_encodings);
        let poseidon_commit = fq_array_poseidon(thread_pool.main(), range.gate(), &pubkeys_x)?;

        Ok(vec![poseidon_commit])
    }

    pub fn instance(pubkeys_uncompressed: Vec<Vec<u8>>) -> Vec<Vec<bn256::Fr>> {
        let pubkey_affines = pubkeys_uncompressed
            .iter()
            .map(|bytes| {
                G1Affine::from_compressed_unchecked(&bytes.as_slice().try_into().unwrap()).unwrap()
            })
            .collect_vec();
        let poseidon_commitment = g1_array_poseidon_native::<bn256::Fr>(&pubkey_affines).unwrap();
        vec![vec![poseidon_commitment]]
    }

    fn decode_pubkeys_x<'a, I: IntoIterator<Item = Vec<AssignedValue<F>>>>(
        ctx: &mut Context<F>,
        fp_chip: &FpChip<'a, F>,
        compressed_encodings: I,
    ) -> Vec<ProperCrtUint<F>> {
        let range = fp_chip.range();
        let gate = fp_chip.gate();

        let g1_chip = G1Chip::<F>::new(fp_chip);

        let mut pubkeys_x = vec![];

        for assigned_bytes in compressed_encodings {
            // assertion check for assigned_uncompressed vector to be equal to S::PubKeyCurve::BYTES_COMPRESSED from specification
            assert_eq!(assigned_bytes.len(), G1::BYTES_COMPRESSED);

            // masked byte from compressed representation
            let masked_byte = &assigned_bytes[G1::BYTES_COMPRESSED - 1];
            // clear the sign bit from masked byte
            let cleared_byte = Self::clear_flag_bits(range, masked_byte, ctx);
            // Use the cleared byte to construct the x coordinate
            let assigned_x_bytes_cleared = [
                &assigned_bytes.as_slice()[..G1::BYTES_COMPRESSED - 1],
                &[cleared_byte],
            ]
            .concat();
            let x_crt = decode_into_field::<F, G1>(
                assigned_x_bytes_cleared,
                &fp_chip.limb_bases,
                gate,
                ctx,
            );

            pubkeys_x.push(x_crt);
        }

        pubkeys_x
    }

    /// Clears the 3 first least significat bits used for flags from a last byte of compressed pubkey.
    /// This function emulates bitwise and on 00011111 (0x1F): `b & 0b00011111` = c
    fn clear_flag_bits(
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

    fn sync_committee_root_ssz<
        ThreadBuilder: ThreadBuilderBase<F>,
        I: IntoIterator<Item = Vec<AssignedValue<F>>>,
    >(
        thread_pool: &mut ThreadBuilder,
        hasher: &impl HashInstructions<F, ThreadBuilder>,
        compressed_encodings: I,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mut pubkeys_hashes: Vec<HashInputChunk<QuantumCell<F>>> = compressed_encodings
            .into_iter()
            .take(1)
            .map(|bytes| {
                let input = bytes
                    .into_iter()
                    .pad_using(64, |_| thread_pool.main().load_zero())
                    .into();
                hasher
                    .digest::<64>(thread_pool, HashInput::Single(input), false)
                    .map(|r| r.output_bytes.into())
            })
            .collect::<Result<Vec<_>, _>>()?;

        ssz_merkleize_chunks(thread_pool, hasher, pubkeys_hashes)
    }
}

impl<S: Spec> AppCircuitExt<bn256::Fr> for CommitteeUpdateCircuit<S, bn256::Fr> {
    fn setup(
        k: usize,
        out: Option<&Path>,
    ) -> (
        ParamsKZG<bn256::Bn256>,
        ProvingKey<bn256::G1Affine>,
        MultiPhaseThreadBreakPoints,
    ) {
        let args = witness::CommitteeRotationArgs::<S, bn256::Fr>::default();
        let circuit = CommitteeUpdateCircuit::<S, bn256::Fr>::default();
        let range = RangeChip::<bn256::Fr>::new(RangeStrategy::Vertical, 8);
        let mut thread_pool = ShaBitThreadBuilder::keygen();

        let assigned_instances = circuit.synthesize(&mut thread_pool, &range, &args).unwrap();

        let params = gen_srs(k as u32);

        let circuit = Eth2CircuitBuilder::keygen(assigned_instances, thread_pool);

        circuit.config(k, None);

        let pk = gen_pkey(|| "committee_update", &params, out, &circuit).unwrap();

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
        gadget::crypto::constant_randomness,
        util::{full_prover, full_verifier, gen_pkey},
        witness::{CommitteeRotationArgs, SyncStepArgs, Validator},
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
        utils::fs::gen_srs,
    };
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{keygen_pk, keygen_vk, Circuit, FloorPlanner},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    };
    use halo2curves::{bls12_381::G1Affine, bn256::Bn256};
    use pasta_curves::group::UncompressedEncoding;
    use rand::rngs::OsRng;
    use rayon::iter::ParallelIterator;
    use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator};
    use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
    use snark_verifier_sdk::{
        gen_pk,
        halo2::{
            aggregation::{AggregationCircuit, AggregationConfigParams},
            gen_proof_shplonk, gen_snark_shplonk,
        },
        CircuitExt, Snark, SHPLONK,
    };

    fn load_circuit_with_data(
        thread_pool: &mut ShaBitThreadBuilder<Fr>,
        k: usize,
    ) -> (
        Vec<AssignedValue<Fr>>,
        CommitteeRotationArgs<Test, bn256::Fr>,
    ) {
        let args = {
            let pubkeys_compressed: Vec<Vec<u8>> =
                serde_json::from_slice(&fs::read("../test_data/committee_pubkeys.json").unwrap())
                    .unwrap();
            CommitteeRotationArgs {
                pubkeys_compressed,
                randomness: constant_randomness(),
                _spec: PhantomData,
            }
        };

        let circuit = CommitteeUpdateCircuit::<Test, bn256::Fr>::default();
        let range = RangeChip::<bn256::Fr>::new(RangeStrategy::Vertical, 8);

        let instance = circuit.synthesize(thread_pool, &range, &args).unwrap();

        let config = thread_pool.config(k, None);
        set_var("LOOKUP_BITS", (config.k - 1).to_string());
        println!("params used: {:?}", config);

        (instance, args)
    }

    fn gen_application_snark(
        k: usize,
        params: &ParamsKZG<bn256::Bn256>,
        pk: &ProvingKey<bn256::G1Affine>,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Snark {
        let mut thread_pool = ShaBitThreadBuilder::prover();

        let (assigned_instances, _args) = load_circuit_with_data(&mut thread_pool, k);

        let circuit = Eth2CircuitBuilder::prover(assigned_instances, thread_pool, break_points);

        gen_snark_shplonk(params, pk, circuit, None::<String>)
    }

    #[test]
    fn test_committee_update_circuit() {
        const K: usize = 18;
        let mut builder = ShaBitThreadBuilder::mock();
        let (assigned_instances, args) = load_circuit_with_data(&mut builder, K);

        let circuit = Eth2CircuitBuilder::mock(assigned_instances, builder);

        let timer = start_timer!(|| "committee_update mock prover");
        let prover = MockProver::<Fr>::run(K as u32, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied_par();
        end_timer!(timer);
    }

    #[test]
    fn test_committee_update_proofgen() {
        const K: usize = 18;

        let (params, pk, break_points) = CommitteeUpdateCircuit::<Test, Fr>::setup(K, None);

        let mut builder = ShaBitThreadBuilder::prover();
        let (assigned_instances, args) = load_circuit_with_data(&mut builder, K);

        let circuit = Eth2CircuitBuilder::prover(assigned_instances, builder, break_points);

        let instances =
            CommitteeUpdateCircuit::<Test, bn256::Fr>::instance(args.pubkeys_compressed);
        let proof = full_prover(&params, &pk, circuit, instances.clone());

        assert!(full_verifier(&params, pk.get_vk(), proof, instances))
    }

    #[test]
    fn circuit_agg() {
        let path = "./config/committee_update_aggregation.json";
        const K: usize = 17;
        let (params_app, pk_app, break_points) = CommitteeUpdateCircuit::<Test, Fr>::setup(K, None);

        let snark = gen_application_snark(K, &params_app, &pk_app, break_points);

        let agg_config = AggregationConfigParams::from_path(path);

        let params = gen_srs(agg_config.degree);
        println!("agg_params k: {:?}", params.k());
        let lookup_bits = params.k() as usize - 1;

        let agg_circuit = AggregationCircuit::keygen::<SHPLONK>(&params, iter::once(snark.clone()));

        let start0 = start_timer!(|| "Aggregation Circuit gen vk & pk");
        let pk = gen_pk(&params, &agg_circuit, None);
        end_timer!(start0);
        let break_points = agg_circuit.break_points();
        let agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            Some(break_points),
            lookup_bits,
            &params,
            iter::once(snark),
        );

        let num_instances = agg_circuit.num_instance();
        let instances = agg_circuit.instances();
        let proof = gen_evm_proof_shplonk(&params, &pk, agg_circuit, instances.clone());
        println!("proof size: {}", proof.len());
        let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
            &params,
            pk.get_vk(),
            num_instances,
            None,
        );
        println!("deployment_code size: {}", deployment_code.len());
        evm_verify(deployment_code, instances, proof);
    }
}
