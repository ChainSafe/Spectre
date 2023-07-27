use crate::{
    gadget::crypto::{FpPoint, G1Chip, G1Point},
    table::{LookupTable, ValidatorsTable},
    util::{decode_into_field, print_fq_dev, Challenges, SubCircuit, SubCircuitConfig},
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
};

#[allow(type_alias_bounds)]
type FpChip<'chip, F, C: AppCurveExt> = halo2_ecc::fields::fp::FpChip<'chip, F, C::Fq>;

#[derive(Clone, Debug)]
pub struct AggregationCircuitConfig<F: Field> {
    validators_table: ValidatorsTable,
    range: RangeConfig<F>,
}

pub struct AggregationCircuitArgs<F: Field> {
    pub validators_table: ValidatorsTable,
    pub range: RangeConfig<F>,
}

impl<F: Field> SubCircuitConfig<F> for AggregationCircuitConfig<F> {
    type ConfigArgs = AggregationCircuitArgs<F>;

    fn new<S: Spec>(_meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let validators_table = args.validators_table;
        let range = args.range;

        Self {
            validators_table,
            range,
        }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.validators_table.annotate_columns_in_region(region);
    }
}

#[derive(Clone, Debug)]
pub struct AggregationCircuitBuilder<'a, F: Field, S: Spec + Sync> {
    builder: RefCell<GateThreadBuilder<F>>,
    range: &'a RangeChip<F>,
    fp_chip: FpChip<'a, F, S::PubKeysCurve>,
    // Witness
    validators: &'a [Validator],
    validators_y: Vec<<S::PubKeysCurve as AppCurveExt>::Fq>,
    _spec: PhantomData<S>,
}

impl<'a, F: Field, S: Spec + Sync> AggregationCircuitBuilder<'a, F, S> {
    pub fn new(
        builder: GateThreadBuilder<F>,
        validators: &'a [Validator],
        validators_y: Vec<<S::PubKeysCurve as AppCurveExt>::Fq>,
        range: &'a RangeChip<F>,
    ) -> Self {
        let fp_chip = FpChip::<F, S::PubKeysCurve>::new(
            range,
            S::PubKeysCurve::LIMB_BITS,
            S::PubKeysCurve::NUM_LIMBS,
        );
        Self {
            builder: RefCell::new(builder),
            range,
            fp_chip,
            validators,
            validators_y,
            _spec: PhantomData,
        }
    }

    pub fn synthesize(
        &self,
        config: &AggregationCircuitConfig<F>,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<Vec<EcPoint<F, FpPoint<F>>>, Error> {
        config
            .range
            .load_lookup_table(layouter)
            .expect("load range lookup table");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        layouter.assign_region(
            || "AggregationCircuitBuilder generated circuit",
            |mut region| {
                config.annotate_columns_in_region(&mut region);
                if first_pass {
                    first_pass = false;
                    return Ok(vec![]);
                }

                let builder = &mut self.builder.borrow_mut();
                let mut pubkeys_compressed = vec![];
                let mut attest_digits = vec![];
                let aggregated_pubkeys =
                    self.process_validators(builder, &mut pubkeys_compressed, &mut attest_digits);

                let ctx = builder.main(1);

                let randomness = QuantumCell::Constant(
                    halo2_base::utils::value_to_option(challenges.sha256_input()).unwrap(),
                );

                let pubkey_rlcs = pubkeys_compressed
                    .into_iter()
                    .map(|compressed| self.get_rlc(&compressed, &randomness, ctx))
                    .collect_vec();

                let halo2_base::gates::builder::KeygenAssignments::<F> {
                    assigned_advices, ..
                } = builder.assign_all(
                    &config.range.gate,
                    &config.range.lookup_advice,
                    &config.range.q_lookup,
                    &mut region,
                    Default::default(),
                );

                // check that the assigned compressed encoding of pubkey used for constructiong affine point
                // is consistent with bytes used in validators table
                // assumption: order of self.validators is same as in BeaconState.validators so we treat iterator index as validator id
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
                    let vs_table_cells = config
                        .validators_table
                        .pubkey_cells
                        .get(i)
                        .expect("pubkey cells for validator id");

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

                    let vs_table_cells = config
                        .validators_table
                        .attest_digits_cells
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
        pubkeys_compressed: &mut Vec<Vec<AssignedValue<F>>>,
        attest_digits: &mut Vec<Vec<AssignedValue<F>>>,
    ) -> Vec<EcPoint<F, FpPoint<F>>> {
        let witness_gen_only = builder.witness_gen_only();
        let range = self.range();
        let gate = range.gate();

        let fp_chip = self.fp_chip();
        let g1_chip = self.g1_chip();

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
        assigned_bytes: &[AssignedValue<F>],
        randomness: &QuantumCell<F>,
        ctx: &mut Context<F>,
    ) -> [AssignedValue<F>; 2] {
        let gate = self.range().gate();
        // assertion check for assigned_bytes to be equal to BASE_BYTES from specification
        assert_eq!(assigned_bytes.len(), S::PubKeysCurve::BYTES_FQ);

        // TODO: remove next 2 lines after switching to bls12-381
        let mut assigned_bytes = assigned_bytes.to_vec();
        assigned_bytes.resize(48, ctx.load_zero());

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

    fn g1_chip(&'a self) -> G1Chip<F, S::PubKeysCurve> {
        G1Chip::<F, S::PubKeysCurve>::new(self.fp_chip())
    }

    fn fp_chip(&self) -> &FpChip<'a, F, S::PubKeysCurve> {
        &self.fp_chip
    }

    fn range(&self) -> &RangeChip<F> {
        self.range
    }
}

impl<'a, F: Field, S: Spec + Sync> SubCircuit<F> for AggregationCircuitBuilder<'a, F, S> {
    type Config = AggregationCircuitConfig<F>;
    type SynthesisArgs = ();

    fn new_from_block(_block: &witness::Block<F>) -> Self {
        todo!()
    }

    fn unusable_rows() -> usize {
        todo!()
    }

    fn min_num_rows_block(_block: &witness::Block<F>) -> (usize, usize) {
        todo!()
    }

    fn synthesize_sub(
        &self,
        config: &mut Self::Config,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
        _: Self::SynthesisArgs,
    ) -> Result<(), Error> {
        self.synthesize(config, challenges, layouter);

        Ok(())
    }

    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

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
        inner: AggregationCircuitBuilder<'a, F, S>,
    }

    impl<'a, F: Field, S: Spec + Sync> TestCircuit<'a, F, S> {
        const NUM_ADVICE: &[usize] = &[10, 1];
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 5;
        const LOOKUP_BITS: usize = 8;
        const K: usize = 14;
    }

    impl<'a, F: Field, S: Spec + Sync> Circuit<F> for TestCircuit<'a, F, S> {
        type Config = (AggregationCircuitConfig<F>, Challenges<F>);
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
            let config = AggregationCircuitConfig::new::<S>(
                meta,
                AggregationCircuitArgs {
                    validators_table,
                    range,
                },
            );

            (config, Challenges::construct(meta))
        }

        fn synthesize(
            &self,
            mut config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = config.1.sha256_input();
            config.0.validators_table.dev_load::<S, _>(
                &mut layouter,
                self.inner.validators,
                challenge,
            )?;
            self.inner.synthesize_sub(
                &mut config.0,
                &config.1.values(&mut layouter),
                &mut layouter,
                (),
            )?;
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

        let range = RangeChip::default(TestCircuit::<Fr, S>::LOOKUP_BITS);
        let builder = GateThreadBuilder::new(false);
        builder.config(k, None);
        let circuit = TestCircuit::<'_, Fr, S> {
            inner: AggregationCircuitBuilder::new(builder, &validators, validators_y, &range),
        };

        let prover = MockProver::<Fr>::run(k as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
