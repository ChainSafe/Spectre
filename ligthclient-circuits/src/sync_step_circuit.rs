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
    gadget::crypto::{
        CachedHashChip, Fp2Point, FpPoint, G1Chip, G1Point, G2Chip, G2Point, HashChip,
        HashToCurveCache, HashToCurveChip, Sha256Chip, SpreadConfig,
    },
    poseidon::{g1_array_poseidon, poseidon_sponge},
    sha256_circuit::{util::NUM_ROUNDS, Sha256CircuitConfig},
    ssz_merkle::ssz_merkleize_chunks,
    table::Sha256Table,
    util::{
        decode_into_field, gen_pkey, AppCircuitExt, AssignedValueCell, Challenges, IntoWitness,
    },
    witness::{self, HashInput, HashInputChunk, SyncStateInput},
};
use eth_types::{AppCurveExt, Field, Spec};
use ethereum_consensus::phase0::BeaconBlockHeader;
use group::UncompressedEncoding;
use halo2_base::{
    gates::{
        builder::{FlexGateConfigParams, GateThreadBuilder, RangeCircuitBuilder},
        flex_gate::GateStrategy,
        range::RangeConfig,
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
use snark_verifier_sdk::{evm::gen_evm_verifier_shplonk, CircuitExt};
use ssz_rs::Merkleized;

#[derive(Clone, Debug)]
pub struct SyncStepCircuitConfig<F: Field> {
    range: RangeConfig<F>,
    sha256_config: RefCell<SpreadConfig<F>>,
    challenges: Challenges<Value<F>>,
}

#[allow(type_alias_bounds)]
#[derive(Clone, Debug)]
pub struct SyncStepCircuit<S: Spec, F: Field> {
    builder: RefCell<GateThreadBuilder<F>>,
    signature: Vec<u8>,
    sha256_offset: usize,
    domain: [u8; 32],
    attested_block: BeaconBlockHeader,
    pubkeys: Vec<G1Affine>,
    pariticipation_bits: Vec<bool>,
    dry_run: bool,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> Default for SyncStepCircuit<S, F> {
    fn default() -> Self {
        let builder: GateThreadBuilder<F> = GateThreadBuilder::new(false);

        // TODO: hard code default data
        let state_input: SyncStateInput =
            serde_json::from_slice(&fs::read("./test_data/sync_state.json").unwrap()).unwrap();
        let state = state_input.into();

        Self::new_from_state(RefCell::from(builder), &state)
    }
}

impl<S: Spec, F: Field> SyncStepCircuit<S, F> {
    fn new_from_state(
        builder: RefCell<GateThreadBuilder<F>>,
        state: &witness::SyncState<F>,
    ) -> Self {
        let sha256_offset = 0; //state.sha256_inputs.len() * 144;
        assert_eq!(sha256_offset % (NUM_ROUNDS + 8), 0, "invalid sha256 offset");

        Self {
            builder,
            signature: state.sync_signature.clone(),
            domain: state.domain,
            attested_block: state.attested_block.clone(),
            pubkeys: state
                .sync_committee
                .iter()
                .cloned()
                .map(|v| {
                    G1Affine::from_uncompressed_unchecked(
                        &v.pubkey_uncompressed.as_slice().try_into().unwrap(),
                    )
                    .unwrap()
                })
                .collect_vec(),
            pariticipation_bits: state
                .sync_committee
                .iter()
                .cloned()
                .map(|v| v.is_attested)
                .collect_vec(),
            sha256_offset,
            dry_run: false,
            _spec: PhantomData,
        }
    }

    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    fn assign_signature(
        bytes_compressed: &[u8],
        g2_chip: &G2Chip<F>,
        ctx: &mut Context<F>,
    ) -> EcPoint<F, Fp2Point<F>> {
        let sig_affine =
            G2Affine::from_bytes(&bytes_compressed.to_vec().try_into().unwrap()).unwrap();

        g2_chip.load_private_unchecked(ctx, sig_affine.into_coordinates())
    }

    /// Takes a list of pubkeys and aggregates them.
    fn aggregate_pubkeys<'a>(
        &self,
        ctx: &mut Context<F>,
        fp_chip: &FpChip<'a, F>,
        committee_pubkeys: &mut Vec<G1Point<F>>,
    ) -> (G1Point<F>, AssignedValue<F>) {
        let range = fp_chip.range();
        let gate = fp_chip.gate();

        let g1_chip = G1Chip::<F>::new(fp_chip);

        let pubkey_compressed_len = G1::BYTES_COMPRESSED;

        let mut participation_bits = vec![];

        assert_eq!(self.pubkeys.len(), S::SYNC_COMMITTEE_SIZE);

        for (&pk, is_attested) in itertools::multizip((
            self.pubkeys.iter(),
            self.pariticipation_bits.iter().copied(),
        )) {
            let participation_bit = ctx.load_witness(F::from(is_attested as u64));
            gate.assert_bit(ctx, participation_bit);

            let assigned_pk = g1_chip.assign_point_unchecked(ctx, pk);

            // Square y coordinate
            let ysq = fp_chip.mul(ctx, assigned_pk.y.clone(), assigned_pk.y.clone());
            // Calculate y^2 using the elliptic curve equation
            let ysq_calc = Self::calculate_ysquared::<G1>(ctx, fp_chip, assigned_pk.x.clone());
            // Constrain witness y^2 to be equal to calculated y^2
            fp_chip.assert_equal(ctx, ysq, ysq_calc);

            // *Note:* normally, we would need to take into account the sign of the y coordinate, but
            // because we are concerned only with signature forgery, if this is the wrong
            // sign, the signature will be invalid anyway and thus verification fails.

            committee_pubkeys.push(assigned_pk);
            participation_bits.push(participation_bit);

            // accumulate bits into current commit
            // let current_digit = committee_idx / F::NUM_BITS as usize;
            // attest_digits_thread[current_digit] = gate.mul_add(
            //     ctx,
            //     attest_digits_thread[current_digit],
            //     QuantumCell::Constant(F::from(2u64)),
            //     participation_bit,
            // );
        }

        let rand_point = g1_chip.load_random_point::<G1Affine>(ctx);
        let mut acc = rand_point.clone();
        for (bit, point) in participation_bits
            .iter()
            .copied()
            .zip(committee_pubkeys.iter_mut())
        {
            let sum = g1_chip.add_unequal(ctx, acc.clone(), point.clone(), true);
            acc = g1_chip.select(ctx, sum, acc, bit);
        }
        let agg_pubkey = g1_chip.sub_unequal(ctx, acc, rand_point, false);
        let participation_sum = gate.sum(ctx, participation_bits);

        (agg_pubkey, participation_sum)
    }

    // Calculates y^2 = x^3 + 4 (the curve equation)
    fn calculate_ysquared<C: AppCurveExt>(
        ctx: &mut Context<F>,
        field_chip: &FpChip<'_, F>,
        x: ProperCrtUint<F>,
    ) -> ProperCrtUint<F> {
        let x_squared = field_chip.mul(ctx, x.clone(), x.clone());
        let x_cubed = field_chip.mul(ctx, x_squared, x);

        let plus_b = field_chip.add_constant_no_carry(ctx, x_cubed, C::B.into());
        field_chip.carry_mod(ctx, plus_b)
    }
}

impl<S: Spec, F: Field> Circuit<F> for SyncStepCircuit<S, F> {
    type Config = SyncStepCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let range = RangeCircuitBuilder::configure(meta);
        let sha256_config = SpreadConfig::<F>::configure(meta, 8, 1);

        SyncStepCircuitConfig {
            range,
            sha256_config: RefCell::new(sha256_config),
            challenges: Challenges::mock(Value::known(Sha256CircuitConfig::fixed_challenge())),
        }
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config
            .range
            .load_lookup_table(&mut layouter)
            .expect("load range lookup table");

        assert!(!self.signature.is_empty(), "no attestations supplied");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        let range = RangeChip::default(config.range.lookup_bits());
        let fp_chip = FpChip::<F>::new(&range, G2::LIMB_BITS, G2::NUM_LIMBS);
        let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
        let g1_chip = EccChip::new(fp2_chip.fp_chip());
        let g2_chip = EccChip::new(&fp2_chip);
        let fp12_chip = Fp12Chip::<F>::new(fp2_chip.fp_chip());
        let pairing_chip = PairingChip::new(&fp_chip);
        let bls_chip = bls_signature::BlsSignatureChip::new(&fp_chip, pairing_chip);
        let sha256_chip = Sha256Chip::new(
            config.sha256_config,
            &range,
            None,
        );
        let h2c_chip = HashToCurveChip::<S, F, _>::new(&sha256_chip);

        let builder_clone = RefCell::from(self.builder.borrow().deref().clone());
        let mut builder = if self.dry_run {
            self.builder.borrow_mut()
        } else {
            builder_clone.borrow_mut()
        };

        layouter.assign_region(
            || "AggregationCircuitBuilder generated circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let ctx = builder.main(0);

                let mut pubkey_points = vec![];
                let (agg_pubkey, participation_sum) =
                    self.aggregate_pubkeys(ctx, &fp_chip, &mut pubkey_points);
                let poseidon_commit = g1_array_poseidon(ctx, range.gate(), pubkey_points)?;

                let fp12_one = {
                    use ff::Field;
                    fp12_chip.load_constant(ctx, Fq12::one())
                };
                let hasher = CachedHashChip::new(&sha256_chip);
                let mut h2c_cache = HashToCurveCache::<F>::default();

                // Verify attestted header
                let chunks = [
                    self.attested_block.slot.into_witness(),
                    self.attested_block.proposer_index.into_witness(),
                    self.attested_block.parent_root.as_ref().into_witness(),
                    self.attested_block.state_root.as_ref().into_witness(),
                    self.attested_block.body_root.as_ref().into_witness(),
                ];

                let attested_header = ssz_merkleize_chunks(ctx, &mut region, &hasher, chunks)?;

                let signing_root = hasher
                    .digest::<64>(
                        HashInput::TwoToOne(
                            attested_header.into(),
                            self.domain.to_vec().into_witness(),
                        ),
                        ctx,
                        &mut region,
                    )?
                    .output_bytes;

                let g1_neg = g1_chip
                    .load_private_unchecked(ctx, G1::generator_affine().neg().into_coordinates());

                let signature = Self::assign_signature(&self.signature, &g2_chip, ctx);

                let msghash = h2c_chip.hash_to_curve::<G2>(
                    signing_root.into(),
                    &fp_chip,
                    ctx,
                    &mut region,
                    &mut h2c_cache,
                )?;

                let res = bls_chip.verify_pairing(signature, msghash, agg_pubkey, g1_neg, ctx);
                fp12_chip.assert_equal(ctx, res, fp12_one);

                let extra_assignments = sha256_chip.take_extra_assignments();

                if self.dry_run {
                    return Ok(());
                }

                let _ = builder.assign_all(
                    &config.range.gate,
                    &config.range.lookup_advice,
                    &config.range.q_lookup,
                    &mut region,
                    extra_assignments,
                );

                // TODO: constaint source_root, target_root with instances: `layouter.constrain_instance`
                Ok(())
            },
        )
    }
}

impl<S: Spec, F: Field> CircuitExt<F> for SyncStepCircuit<S, F> {
    fn instances(&self) -> Vec<Vec<F>> {
        vec![]
    }

    fn num_instance(&self) -> Vec<usize> {
        self.instances().iter().map(|v| v.len()).collect()
    }
}

impl<S: Spec> AppCircuitExt<bn256::Fr> for SyncStepCircuit<S, bn256::Fr> {
    fn parametrize(k: usize) -> FlexGateConfigParams {
        let circuit = SyncStepCircuit::<S, bn256::Fr>::default();

        let mock_k = 17;
        // Due to the composite nature of Sync circuit (vanila + halo2-lib)
        // we have to perfrom dry run to determine best circuit config.
        let mock_params = FlexGateConfigParams {
            strategy: GateStrategy::Vertical,
            k: mock_k,
            num_advice_per_phase: vec![80],
            num_lookup_advice_per_phase: vec![15],
            num_fixed: 1,
        };

        set_var(
            "FLEX_GATE_CONFIG_PARAMS",
            serde_json::to_string(&mock_params).unwrap(),
        );
        std::env::set_var("LOOKUP_BITS", 16.to_string());

        let _ = MockProver::<bn256::Fr>::run(mock_k as u32, &circuit, vec![]);
        circuit.builder.borrow().config(k, Some(0));
        std::env::set_var("LOOKUP_BITS", (k - 1).to_string());
        let params: FlexGateConfigParams =
            serde_json::from_str(&var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
        println!("params: {:?}", params);
        params
    }

    fn setup(
        config: FlexGateConfigParams,
        out: Option<&Path>,
    ) -> (
        ParamsKZG<bn256::Bn256>,
        ProvingKey<bn256::G1Affine>,
        Vec<usize>,
    ) {
        let circuit = SyncStepCircuit::<S, bn256::Fr>::default();

        set_var("LOOKUP_BITS", (config.k - 1).to_string());
        set_var(
            "FLEX_GATE_CONFIG_PARAMS",
            serde_json::to_string(&config).unwrap(),
        );

        let params = gen_srs(config.k as u32);

        let num_instance = circuit.num_instance();

        let pk = gen_pkey(|| "sync_step", &params, out, circuit).unwrap();

        (params, pk, num_instance)
    }
}
#[cfg(test)]
mod tests {
    use std::{
        env::{set_var, var},
        fs,
    };

    use crate::{
        table::Sha256Table,
        util::{full_prover, full_verifier, gen_pkey},
        witness::{SyncState, SyncStateInput, Validator},
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
        poly::kzg::commitment::ParamsKZG,
    };
    use halo2curves::{bls12_381::G1Affine, bn256::Bn256};
    use pasta_curves::group::UncompressedEncoding;
    use rand::rngs::OsRng;
    use rayon::iter::ParallelIterator;
    use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator};
    use snark_verifier_sdk::{
        halo2::{aggregation::AggregationCircuit, gen_proof_shplonk, gen_snark_shplonk},
        CircuitExt, SHPLONK,
    };

    fn get_circuit_with_data(k: usize) -> SyncStepCircuit<Test, Fr> {
        let builder = GateThreadBuilder::new(false);
        let state_input: SyncStateInput =
            serde_json::from_slice(&fs::read("../test_data/sync_state.json").unwrap()).unwrap();
        let state = state_input.into();

        let _ = SyncStepCircuit::<Test, Fr>::parametrize(k);

        let builder = RefCell::from(builder);
        SyncStepCircuit::new_from_state(builder, &state)
    }

    #[test]
    fn test_sync_circuit() {
        let k = 17;
        let circuit = get_circuit_with_data(k);

        let timer = start_timer!(|| "sync circuit mock prover");
        let prover = MockProver::<Fr>::run(k as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        end_timer!(timer);
    }

    #[test]
    fn test_sync_proofgen() {
        let k = 17;
        let circuit = get_circuit_with_data(k);

        let params = gen_srs(k as u32);

        let pkey = gen_pkey(|| "sync", &params, None, circuit.clone()).unwrap();

        let public_inputs = circuit.instances();
        let proof = full_prover(&params, &pkey, circuit, public_inputs.clone());

        assert!(full_verifier(&params, pkey.get_vk(), proof, public_inputs))
    }
}
