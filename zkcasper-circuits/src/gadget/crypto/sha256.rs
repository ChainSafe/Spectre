use eth_types::Field;
use gadgets::util::rlc;
use halo2_base::gates::builder::KeygenAssignments;
use halo2_proofs::circuit::Value;
use halo2curves::group::ff::PrimeField;
use itertools::Itertools;
use std::collections::HashMap;
use std::{cell::RefCell, char::MAX};

use crate::{
    sha256_circuit::{util::Sha256AssignedRows, Sha256CircuitConfig},
    witness::HashInput,
};
use halo2_base::safe_types::RangeChip;
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    AssignedValue, Context,
};
use halo2_base::{utils::value_to_option, ContextCell};
use halo2_proofs::{
    circuit::{self, AssignedCell, Region},
    plonk::{Assigned, Error},
};

const SHA256_CONTEXT_ID: usize = usize::MAX;

pub trait HashChip<F: Field> {
    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;

    fn digest<const MAX_INPUT_SIZE: usize>(
        &self,
        input: HashInput<QuantumCell<F>>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
    ) -> Result<AssignedHashResult<F>, Error>;

    fn take_extra_assignments(&self) -> KeygenAssignments<F>;

    fn range(&self) -> &RangeChip<F>;
}

#[derive(Debug, Clone)]
pub struct AssignedHashResult<F: Field> {
    pub input_len: AssignedValue<F>,
    pub input_bytes: Vec<AssignedValue<F>>,
    pub output_bytes: [AssignedValue<F>; 32],
}

#[derive(Debug)]
pub struct Sha256Chip<'a, F: Field> {
    config: &'a Sha256CircuitConfig<F>,
    range: &'a RangeChip<F>,
    randomness: F,
    extra_assignments: RefCell<KeygenAssignments<F>>,
    sha256_circuit_offset: RefCell<usize>,
}

impl<'a, F: Field> HashChip<F> for Sha256Chip<'a, F> {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 32;

    fn digest<const MAX_INPUT_SIZE: usize>(
        &self,
        input: HashInput<QuantumCell<F>>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
    ) -> Result<AssignedHashResult<F>, Error> {
        let binary_input = input.clone().into();
        let assigned_input = input.into_assigned(ctx);

        let mut extra_assignment = self.extra_assignments.borrow_mut();
        let assigned_advices = &mut extra_assignment.assigned_advices;
        let mut assigned_input_bytes = assigned_input.to_vec();
        let rnd = QuantumCell::Constant(self.randomness);
        let input_byte_size = assigned_input_bytes.len();
        let max_byte_size = MAX_INPUT_SIZE;
        assert!(input_byte_size <= max_byte_size);
        let range = &self.range;
        let gate = &range.gate;

        assert!(assigned_input_bytes.len() <= MAX_INPUT_SIZE);
        let mut circuit_offset = self.sha256_circuit_offset.borrow_mut();
        let mut assigned_rows = Sha256AssignedRows::new(*circuit_offset);
        let assigned_hash_bytes =
            self.config
                .digest_with_region(region, binary_input, &mut assigned_rows)?;
        *circuit_offset = assigned_rows.offset;
        let assigned_output =
            assigned_hash_bytes.map(|b| ctx.load_witness(*value_to_option(b.value()).unwrap()));

        let one_round_size = Self::BLOCK_SIZE;
        let num_round = 1;

        let num_round = if input_byte_size % one_round_size == 0 {
            input_byte_size / one_round_size
        } else {
            input_byte_size / one_round_size + 1
        };
        let padded_size = one_round_size * num_round;
        let zero_padding_byte_size = padded_size - input_byte_size; // - 9;
        let max_round = max_byte_size / one_round_size;

        let mut assign_byte = |byte: u8| ctx.load_witness(F::from(byte as u64));

        for _ in 0..zero_padding_byte_size {
            assigned_input_bytes.push(assign_byte(0u8));
        }

        assert_eq!(assigned_input_bytes.len(), num_round * one_round_size);

        for &assigned in assigned_input_bytes.iter() {
            range.range_check(ctx, assigned, 8);
        }

        let zero = ctx.load_zero();
        let mut full_input_len = zero;

        let mut offset = assigned_advices
            .keys()
            .filter(|(ctx_id, offset)| ctx_id == &SHA256_CONTEXT_ID)
            .map(|(ctx_id, offset)| *offset + 1)
            .max()
            .unwrap_or(0);

        let mut cur_input_rlc = zero;
        for round_idx in 0..max_round {
            let input_len = self.assigned_cell2value(ctx, &assigned_rows.input_len[round_idx]);

            let input_rlcs = {
                let input_rlc_cells =
                    assigned_rows.input_rlc[16 * round_idx..16 * (round_idx + 1)].iter();
                self.upload_assigned_cells(
                    input_rlc_cells,
                    &mut offset,
                    assigned_advices,
                    ctx.witness_gen_only(),
                )
            };

            let padding_selectors = assigned_rows.padding_selectors
                [16 * round_idx..16 * (round_idx + 1)]
                .iter()
                .map(|cells| {
                    self.upload_assigned_cells(
                        cells,
                        &mut offset,
                        assigned_advices,
                        ctx.witness_gen_only(),
                    )
                    .try_into()
                    .unwrap()
                })
                .collect::<Vec<[_; 4]>>();

            let [is_output_enabled, output_rlc]: [_; 2] = self
                .upload_assigned_cells(
                    [
                        &assigned_rows.is_final[round_idx],
                        &assigned_rows.output_rlc[0],
                    ],
                    &mut offset,
                    assigned_advices,
                    ctx.witness_gen_only(),
                )
                .try_into()
                .unwrap();

            full_input_len = {
                let muled = gate.mul(ctx, is_output_enabled, input_len);
                gate.add(ctx, full_input_len, muled)
            };

            for word_idx in 0..16 {
                let offset_in = 64 * round_idx + 4 * word_idx;
                let assigned_input_u32 = &assigned_input_bytes[offset_in..(offset_in + 4)];

                for (idx, &assigned_byte) in assigned_input_u32.iter().enumerate() {
                    let tmp = gate.mul_add(ctx, cur_input_rlc, rnd, assigned_byte);
                    cur_input_rlc =
                        gate.select(ctx, cur_input_rlc, tmp, padding_selectors[word_idx][idx]);
                }

                ctx.constrain_equal(&cur_input_rlc, &input_rlcs[word_idx]);
            }

            let hash_rlc = rlc::assigned_value(&assigned_output, &rnd, gate, ctx);
            ctx.constrain_equal(&hash_rlc, &output_rlc);
        }
        for &byte in assigned_output.iter() {
            range.range_check(ctx, byte, 8);
        }

        Ok(AssignedHashResult {
            input_len: full_input_len,
            input_bytes: assigned_input_bytes,
            output_bytes: assigned_output,
        })
    }

    /// Takes internal `KeygenAssignments` instance, leaving `Default::default()` in its place.
    /// **Warning**: In case `extra_assignments` wasn't default at the time of chip initialization,
    /// use `set_extra_assignments` to restore at the start of region declartion.
    /// Otherwise at the second synthesis run, the setted `extra_assignments` will be erased.
    fn take_extra_assignments(&self) -> KeygenAssignments<F> {
        self.extra_assignments.take()
    }

    fn range(&self) -> &RangeChip<F> {
        self.range
    }
}

impl<'a, F: Field> Sha256Chip<'a, F> {
    pub fn new(
        config: &'a Sha256CircuitConfig<F>,
        range: &'a RangeChip<F>,
        randomness: Value<F>,
        extra_assignments: Option<KeygenAssignments<F>>,
        sha256_circui_offset: usize,
    ) -> Self {
        Self {
            config,
            range,
            randomness: value_to_option(randomness).expect("randomness is not assigned"),
            extra_assignments: RefCell::new(extra_assignments.unwrap_or_default()),
            sha256_circuit_offset: RefCell::new(sha256_circui_offset),
        }
    }

    fn set_extra_assignments(&mut self, extra_assignments: KeygenAssignments<F>) {
        self.extra_assignments = RefCell::new(extra_assignments);
    }

    fn assigned_cell2value(
        &self,
        ctx: &mut Context<F>,
        assigned_cell: &AssignedCell<F, F>,
    ) -> AssignedValue<F> {
        ctx.load_witness(*value_to_option(assigned_cell.value()).unwrap())
    }

    fn upload_assigned_cells(
        &self,
        assigned_cells: impl IntoIterator<Item = &'a AssignedCell<F, F>>,
        offset: &mut usize,
        assigned_advices: &mut HashMap<(usize, usize), (circuit::Cell, usize)>,
        witness_gen_only: bool,
    ) -> Vec<AssignedValue<F>> {
        let assigned_values = assigned_cells
            .into_iter()
            .enumerate()
            .map(|(i, assigned_cell)| {
                let value = value_to_option(assigned_cell.value())
                    .map(|v| Assigned::Trivial(*v))
                    .unwrap_or_else(|| Assigned::Trivial(F::zero())); // for keygen

                let aval = AssignedValue {
                    value,
                    cell: (!witness_gen_only).then_some(ContextCell {
                        context_id: SHA256_CONTEXT_ID,
                        offset: *offset + i,
                    }),
                };
                if !witness_gen_only {
                    // we set row_offset = usize::MAX because you should never be directly using lookup on such a cell
                    assigned_advices.insert(
                        (SHA256_CONTEXT_ID, *offset + i),
                        (assigned_cell.cell(), usize::MAX),
                    );
                }
                aval
            })
            .collect_vec();
        *offset += assigned_values.len();
        assigned_values
    }
}

#[cfg(test)]
mod test {
    use std::vec;
    use std::{cell::RefCell, marker::PhantomData};

    use crate::table::SHA256Table;
    use crate::util::{Challenges, IntoWitness, SubCircuitConfig};

    use super::*;
    use eth_types::Test;
    use halo2_base::gates::range::RangeConfig;
    use halo2_base::SKIP_FIRST_PASS;
    use halo2_base::{
        gates::{builder::GateThreadBuilder, range::RangeStrategy},
        halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner},
            dev::MockProver,
            halo2curves::bn256::Fr,
            plonk::{Circuit, ConstraintSystem},
        },
    };
    use sha2::{Digest, Sha256};

    #[derive(Debug, Clone)]
    struct TestConfig<F: Field> {
        sha256_config: Sha256CircuitConfig<F>,
        pub max_byte_size: usize,
        range: RangeConfig<F>,
        challenges: Challenges<F>,
    }

    struct TestCircuit<F: Field> {
        builder: RefCell<GateThreadBuilder<F>>,
        range: RangeChip<F>,
        test_input: HashInput<QuantumCell<F>>,
        test_output: [u8; 32],
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestCircuit<F>
    where
        [(); Self::MAX_BYTE_SIZE]:,
    {
        type Config = TestConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha_table = SHA256Table::construct(meta);
            let sha256_configs = Sha256CircuitConfig::<F>::new::<Test>(meta, sha_table);
            let range = RangeConfig::configure(
                meta,
                RangeStrategy::Vertical,
                &[Self::NUM_ADVICE],
                &[Self::NUM_LOOKUP_ADVICE],
                Self::NUM_FIXED,
                Self::LOOKUP_BITS,
                Self::K,
            );
            let challenges = Challenges::construct(meta);
            Self::Config {
                sha256_config: sha256_configs,
                max_byte_size: Self::MAX_BYTE_SIZE,
                range,
                challenges,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range.load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            let sha256 = Sha256Chip::new(
                &config.sha256_config,
                &self.range,
                config.challenges.sha256_input(),
                None,
                0,
            );

            let _ = layouter.assign_region(
                || "sha2 test",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(vec![]);
                    }
                    config.sha256_config.annotate_columns_in_region(&mut region);

                    let builder = &mut self.builder.borrow_mut();
                    let ctx = builder.main(0);

                    let result = sha256.digest::<{ TestCircuit::<F>::MAX_BYTE_SIZE }>(
                        self.test_input.clone(),
                        ctx,
                        &mut region,
                    )?;
                    let assigned_hash = result.output_bytes;
                    println!(
                        "assigned hash: {:?}",
                        assigned_hash.map(|e| e.value().get_lower_32())
                    );

                    let correct_output = self
                        .test_output
                        .map(|b| ctx.load_witness(F::from(b as u64)));

                    for (hash, check) in assigned_hash.iter().zip(correct_output.iter()) {
                        ctx.constrain_equal(hash, check);
                    }

                    let extra_assignments = sha256.take_extra_assignments();

                    let _ = builder.assign_all(
                        &config.range.gate,
                        &config.range.lookup_advice,
                        &config.range.q_lookup,
                        &mut region,
                        extra_assignments,
                    );

                    Ok(assigned_hash.into_iter().map(|v| v.cell).collect())
                },
            )?;

            Ok(())
        }
    }

    impl<F: Field> TestCircuit<F> {
        const MAX_BYTE_SIZE: usize = 128;
        const NUM_ADVICE: usize = 5;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 4;
        const LOOKUP_BITS: usize = 8;
        const K: usize = 10;
    }

    #[test]
    fn test_sha256_chip_constant_size() {
        let k = TestCircuit::<Fr>::K as u32;

        let test_input = vec![0u8; 128];
        let test_output: [u8; 32] = Sha256::digest(&test_input).into();
        let range = RangeChip::default(TestCircuit::<Fr>::LOOKUP_BITS);
        let builder = GateThreadBuilder::new(false);
        let circuit = TestCircuit::<Fr> {
            builder: RefCell::new(builder),
            range,
            test_input: test_input.into_witness(),
            test_output,
            _f: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
