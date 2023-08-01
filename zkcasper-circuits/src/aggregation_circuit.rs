use crate::{
    gadget::crypto::{FpPoint, G1Chip, G1Point},
    table::{LookupTable, ValidatorsTable},
    util::{
        decode_into_field, print_fq_dev, Challenges, SubCircuit, SubCircuitBuilder,
        SubCircuitConfig,
    },
    validators_circuit::ValidatorsCircuitOutput,
    witness::{self, Validator, DUMMY_VALIDATOR},
};
use eth_types::{Spec, *};
use ff::Field as FF;
use gadgets::util::rlc;
use group::prime::PrimeCurveAffine;
use halo2_base::{
    gates::{
        builder::{parallelize_in, GateThreadBuilder},
        flex_gate::GateInstructions,
        range::{RangeChip, RangeConfig, RangeInstructions},
    },
    utils::CurveAffineExt,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{ProperCrtUint, ProperUint},
    ecc::{EcPoint, EccChip},
    fields::{fp, FieldChip, Selectable},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{ConstraintSystem, Error},
};
use halo2curves::{
    group::{ff::PrimeField, GroupEncoding, UncompressedEncoding},
    CurveAffine, CurveExt,
};
use itertools::Itertools;
use num_bigint::BigUint;
use rayon::prelude::*;
use std::{
    cell::{RefCell, RefMut},
    iter,
    marker::PhantomData,
    rc::Rc,
};

#[allow(type_alias_bounds)]
type FpChip<'chip, F, C: AppCurveExt> = halo2_ecc::fields::fp::FpChip<'chip, F, C::Fq>;

#[derive(Clone, Debug)]
pub struct AggregationCircuitBuilder<'a, S: Spec + Sync, F: Field> {
    builder: Rc<RefCell<GateThreadBuilder<F>>>,
    // Witness
    validators: &'a [Validator],
    validators_y: Vec<<S::PubKeysCurve as AppCurveExt>::Fq>,
    _spec: PhantomData<S>,
}

impl<'a, F: Field, S: Spec + Sync> SubCircuitBuilder<'a, S, F>
    for AggregationCircuitBuilder<'a, S, F>
where
    [(); { S::MAX_VALIDATORS_PER_COMMITTEE }]:,
{
    type Config = RangeConfig<F>;
    type SynthesisArgs = ValidatorsCircuitOutput;
    type Output = Vec<EcPoint<F, FpPoint<F>>>;

    fn new_from_state(
        builder: Rc<RefCell<GateThreadBuilder<F>>>,
        state: &'a witness::State<S, F>,
    ) -> Self {
        let validators_y = state
            .validators
            .iter()
            .map(|v| {
                let g1_affine = <S::PubKeysCurve as AppCurveExt>::Affine::from_uncompressed(
                    &v.pubkey_uncompressed.clone().try_into().unwrap(),
                )
                .unwrap();

                g1_affine.into_coordinates().1
            })
            .collect_vec();
        Self::new(builder, &state.validators, validators_y)
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
        ValidatorsCircuitOutput {
            pubkey_cells,
            attest_digits_cells,
        }: Self::SynthesisArgs,
    ) -> Result<Self::Output, Error> {
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        let range = RangeChip::default(config.lookup_bits());
        let fp_chip = FpChip::<F, S::PubKeysCurve>::new(
            &range,
            S::PubKeysCurve::LIMB_BITS,
            S::PubKeysCurve::NUM_LIMBS,
        );

        layouter.assign_region(
            || "AggregationCircuitBuilder generated circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(vec![]);
                }

                let builder = &mut self.builder.borrow_mut();
                let mut pubkeys_compressed = vec![];
                let mut attest_digits = vec![];

                let aggregated_pubkeys = self.process_validators(
                    builder,
                    &fp_chip,
                    &mut pubkeys_compressed,
                    &mut attest_digits,
                );

                let ctx = builder.main(1);

                let randomness = QuantumCell::Constant(
                    halo2_base::utils::value_to_option(challenges.sha256_input()).unwrap(),
                );

                let pubkey_rlcs = pubkeys_compressed
                    .into_iter()
                    .map(|compressed| self.get_rlc(fp_chip.gate(), &compressed, &randomness, ctx))
                    .collect_vec();

                let halo2_base::gates::builder::KeygenAssignments::<F> {
                    assigned_advices, ..
                } = builder.assign_all(
                    &config.gate,
                    &config.lookup_advice,
                    &config.q_lookup,
                    &mut region,
                    Default::default(),
                );

                // check that the assigned compressed encoding of pubkey used for constructiong affine point
                // is consistent with bytes used in validators table
                // assumption: order of self.validators is same as in BeaconState.validators so we treat iterator index as validator id
                println!("pubkey_cells.len(): {}", pubkey_cells.len());
                for (i, assigned_rlc) in pubkey_rlcs.into_iter().enumerate() {
                    // convert halo2lib `AssignedValue` into vanilla Halo2 `Cell`
                    let cells = assigned_rlc
                        .into_iter()
                        .filter_map(|c| c.cell)
                        .filter_map(|ctx_cell| {
                            assigned_advices.get(&(ctx_cell.context_id, ctx_cell.offset))
                        })
                        .map(|&(cell, _)| cell);

                    // get the corresponding cached cells from the validators table
                    println!("i: {}", i);
                    let vs_table_cells =
                        pubkey_cells.get(i).expect("pubkey cells for validator id");

                    // enforce equality and order
                    // WARNING: the variable number of valdiators might cause issues in proof generation
                    // FIXME: pad up to max (supported) valdiators count (?)
                    for (left, &right) in cells.zip_eq(vs_table_cells) {
                        region.constrain_equal(left, right)?;
                    }
                }

                // Check that attestation bits used during pubkey aggregation are consistent validators table
                // to reduce the number of equility constraints we check digits composed from those bits.
                // There will be S::MAX_VALIDATORS_PER_COMMITTEE / 254 digits per committee
                for (i, commit) in attest_digits.into_iter().enumerate() {
                    let cells = commit
                        .into_iter()
                        .filter_map(|c| c.cell)
                        .filter_map(|ctx_cell| {
                            assigned_advices.get(&(ctx_cell.context_id, ctx_cell.offset))
                        })
                        .map(|&(cell, _)| cell);

                    let vs_table_cells = attest_digits_cells
                        .get(i)
                        .expect("attest digit cells for validator id");

                    for (left, &right) in cells.zip_eq(vs_table_cells) {
                        region.constrain_equal(left, right)?;
                    }
                }

                Ok(aggregated_pubkeys)
            },
        )
    }

    fn unusable_rows() -> usize {
        todo!()
    }

    fn min_num_rows_state(_block: &witness::State<S, F>) -> (usize, usize) {
        todo!()
    }
}

impl<'a, F: Field, S: Spec + Sync> AggregationCircuitBuilder<'a, S, F> {
    pub fn new(
        builder: Rc<RefCell<GateThreadBuilder<F>>>,
        validators: &'a [Validator],
        validators_y: Vec<<S::PubKeysCurve as AppCurveExt>::Fq>,
    ) -> Self {
        Self {
            builder,
            validators,
            validators_y,
            _spec: PhantomData,
        }
    }

    // Calculates y^2 = x^3 + 4 (the curve equation)
    fn calculate_ysquared<C: AppCurveExt>(
        ctx: &mut Context<F>,
        field_chip: &FpChip<'_, F, C>,
        x: ProperCrtUint<F>,
    ) -> ProperCrtUint<F> {
        let x_squared = field_chip.mul(ctx, x.clone(), x.clone());
        let x_cubed = field_chip.mul(ctx, x_squared, x);

        let plus_b = field_chip.add_constant_no_carry(ctx, x_cubed, C::B.into());
        field_chip.carry_mod(ctx, plus_b)
    }

    /// takes a list of validators and groups them by committees
    /// aggregates them by committee, and appends `pubkeys_compressed` with assigned pubkeys
    /// of validators in compressed byte form.
    fn process_validators(
        &self,
        builder: &mut GateThreadBuilder<F>,
        fp_chip: &FpChip<'a, F, S::PubKeysCurve>,
        pubkeys_compressed: &mut Vec<Vec<AssignedValue<F>>>,
        attest_digits: &mut Vec<Vec<AssignedValue<F>>>,
    ) -> Vec<EcPoint<F, FpPoint<F>>> {
        let witness_gen_only = builder.witness_gen_only();
        let range = fp_chip.range();
        let gate = fp_chip.gate();

        let g1_chip = G1Chip::<F, S::PubKeysCurve>::new(fp_chip);

        let pubkey_compressed_len = S::PubKeysCurve::BYTES_FQ;

        // Set y = sqrt(B) for dummy validators to sutisfy curve equation
        // Note: this only works for curves that have B exponent of 2, e.g. BLS12-381
        let dymmy_y =
            <S::PubKeysCurve as AppCurveExt>::Fq::from((S::PubKeysCurve::B as f64).sqrt() as u64);

        let grouped_validators = self
            .validators
            .iter()
            .zip(self.validators_y.iter())
            .group_by(|v| v.0.committee)
            .into_iter()
            .sorted_by_key(|(committee, _)| *committee)
            .take(S::MAX_COMMITTEES_PER_SLOT * S::SLOTS_PER_EPOCH)
            .map(|(_, g)| g.into_iter().collect_vec())
            .collect_vec();

        // NOTE: We convert the grouped validators into Rayon-provided `ParIter` so that we can use
        // parallel threads. But because of this, we can't use &mut self or any other mutable
        // types, so instead we return a vector of tuples from this `.map`, which we process later.

        parallelize_in(0, builder, grouped_validators, |ctx, validators| {
            // Note: Nothing within here can take `self`.
            let mut pubkeys_compressed_thread = vec![];
            let mut attested_pubkeys = vec![];
            let mut aggregation_bits = vec![];
            let mut attest_digits_thread = iter::repeat_with(|| ctx.load_zero())
                .take(S::attest_digits_len::<F>())
                .collect_vec();

            for (committee_idx, (validator, y_coord)) in validators
                .into_iter()
                .pad_using(S::MAX_VALIDATORS_PER_COMMITTEE, |_| {
                    (&DUMMY_VALIDATOR, &dymmy_y)
                })
                .enumerate()
            {
                let is_attested = ctx.load_witness(F::from(validator.is_attested as u64));

                let assigned_x_compressed_bytes: Vec<AssignedValue<F>> =
                    ctx.assign_witnesses(validator.pubkey.iter().map(|&b| F::from(b as u64)));

                // assertion check for assigned_uncompressed vector to be equal to S::PubKeyCurve::BYTES_UNCOMPRESSED from specification
                assert_eq!(assigned_x_compressed_bytes.len(), pubkey_compressed_len);

                // masked byte from compressed representation
                let masked_byte = &assigned_x_compressed_bytes[pubkey_compressed_len - 1];
                // clear the sign bit from masked byte
                let cleared_byte = Self::clear_flag_bits(range, masked_byte, ctx);
                // Use the cleared byte to construct the x coordinate
                let assigned_x_bytes_cleared = [
                    &assigned_x_compressed_bytes.as_slice()[..pubkey_compressed_len - 1],
                    &[cleared_byte],
                ]
                .concat();
                let x_crt = decode_into_field::<F, S::PubKeysCurve>(
                    assigned_x_bytes_cleared,
                    &fp_chip.limb_bases,
                    gate,
                    ctx,
                );

                // Load private witness y coordinate
                let y_crt = fp_chip.load_private(ctx, *y_coord);
                // Square y coordinate
                let ysq = fp_chip.mul(ctx, y_crt.clone(), y_crt.clone());
                // Calculate y^2 using the elliptic curve equation
                let ysq_calc =
                    Self::calculate_ysquared::<S::PubKeysCurve>(ctx, fp_chip, x_crt.clone());
                // Constrain witness y^2 to be equal to calculated y^2
                fp_chip.assert_equal(ctx, ysq, ysq_calc);

                // cache assigned compressed pubkey bytes where each byte is constrainted with pubkey point.
                // push this to the returnable and then use that
                pubkeys_compressed_thread.push(assigned_x_compressed_bytes);

                // *Note:* normally, we would need to take into account the sign of the y coordinate, but
                // because we are concerned only with signature forgery, if this is the wrong
                // sign, the signature will be invalid anyway and thus verification fails.

                attested_pubkeys.push(EcPoint::new(x_crt, y_crt));
                aggregation_bits.push(is_attested);

                // accumulate bits into current commit
                let current_digit = committee_idx / F::NUM_BITS as usize;
                attest_digits_thread[current_digit] = gate.mul_add(
                    ctx,
                    attest_digits_thread[current_digit],
                    QuantumCell::Constant(F::from(2u64)),
                    is_attested,
                );
            }
            (
                Self::aggregate_pubkeys(&g1_chip, ctx, attested_pubkeys, aggregation_bits),
                pubkeys_compressed_thread,
                attest_digits_thread,
            )
        })
        .into_iter()
        .map(|(agg_pk, mut encoded_pubkeys, digits)| {
            pubkeys_compressed.append(&mut encoded_pubkeys);

            attest_digits.push(digits);
            agg_pk
        })
        .collect()
    }

    pub fn aggregate_pubkeys<'b>(
        g1_chip: &G1Chip<'b, F, S::PubKeysCurve>,
        ctx: &mut Context<F>,
        pubkeys: impl IntoIterator<Item = G1Point<F>>,
        aggregation_bits: impl IntoIterator<Item = AssignedValue<F>>,
    ) -> G1Point<F> {
        let rand_point = g1_chip.load_random_point::<<S::PubKeysCurve as AppCurveExt>::Affine>(ctx);
        let mut acc = rand_point.clone();
        for (bit, point) in aggregation_bits.into_iter().zip(pubkeys.into_iter()) {
            let _acc = g1_chip.add_unequal(ctx, acc.clone(), point, true);
            acc = g1_chip.select(ctx, _acc, acc, bit);
        }
        g1_chip.sub_unequal(ctx, acc, rand_point, false)
    }

    /// Calculates RLCs (1 for each of two chacks of BLS12-381) for compresed bytes of pubkey.
    /// The resulted bigints should be equal to one used validators table.
    pub fn get_rlc(
        &self,
        gate: &impl GateInstructions<F>,
        assigned_bytes: &[AssignedValue<F>],
        randomness: &QuantumCell<F>,
        ctx: &mut Context<F>,
    ) -> [AssignedValue<F>; 2] {
        // assertion check for assigned_bytes to be equal to BASE_BYTES from specification
        assert_eq!(assigned_bytes.len(), S::PubKeysCurve::BYTES_FQ);

        // need to pad to 64 bytes becasue `rlc::assigned_value` is over LE bytes
        // see Approach 1 in https://github.com/ChainSafe/banshee-zk/issues/72
        let mut assigned_bytes = assigned_bytes.to_vec();
        assigned_bytes.resize(64, ctx.load_zero());

        assigned_bytes
            .chunks(32)
            .into_iter()
            .map(|values| rlc::assigned_value(values, randomness, gate, ctx))
            .collect_vec()
            .try_into()
            .unwrap()
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
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::sha256_circuit::Sha256CircuitConfig;

    use super::*;
    use eth_types::Test as S;
    use group::{prime::PrimeCurveAffine, Group};
    use halo2_base::gates::range::RangeStrategy;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };
    use halo2curves::bls12_381::G1Affine;

    #[derive(Debug, Clone)]
    struct TestCircuit<'a, F: Field, S: Spec + Sync> {
        inner: AggregationCircuitBuilder<'a, S, F>,
    }

    impl<'a, F: Field, S: Spec + Sync> TestCircuit<'a, F, S> {
        const NUM_ADVICE: &[usize] = &[10, 1];
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 5;
        const LOOKUP_BITS: usize = 8;
        const K: usize = 14;
    }

    impl<'a, F: Field, S: Spec + Sync> Circuit<F> for TestCircuit<'a, F, S>
    where
        [(); { S::MAX_VALIDATORS_PER_COMMITTEE }]:,
    {
        type Config = (RangeConfig<F>, ValidatorsTable, Challenges<Value<F>>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let validators_table = ValidatorsTable::construct::<S, F>(meta);
            let range = RangeConfig::configure(
                meta,
                RangeStrategy::Vertical,
                Self::NUM_ADVICE,
                &[Self::NUM_LOOKUP_ADVICE],
                Self::NUM_FIXED,
                Self::LOOKUP_BITS,
                Self::K,
            );

            (
                range,
                validators_table,
                Challenges::mock(Value::known(Sha256CircuitConfig::fixed_challenge())),
            )
        }

        fn synthesize(
            &self,
            mut config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = config.2.sha256_input();
            let args =
                config
                    .1
                    .dev_load::<S, _>(&mut layouter, self.inner.validators, challenge)?;

            config
                .0
                .load_lookup_table(&mut layouter)
                .expect("load range lookup table");
            self.inner
                .synthesize_sub(&config.0, &config.2, &mut layouter, args)?;
            Ok(())
        }
    }

    #[test]
    fn test_aggregation_circuit() {
        let k = TestCircuit::<Fr, S>::K;
        let validators: Vec<Validator> =
            serde_json::from_slice(&fs::read("../test_data/validators.json").unwrap()).unwrap();

        let validators_y = validators
            .iter()
            .map(|v| {
                let g1_affine = G1Affine::from_uncompressed(
                    &v.pubkey_uncompressed.as_slice().try_into().unwrap(),
                )
                .unwrap();

                g1_affine.y
            })
            .collect_vec();

        let builder = GateThreadBuilder::new(false);
        builder.config(k, None);
        let builder = Rc::from(RefCell::from(builder));
        let circuit = TestCircuit::<'_, Fr, S> {
            inner: AggregationCircuitBuilder::new(builder, &validators, validators_y),
        };

        let prover = MockProver::<Fr>::run(k as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
