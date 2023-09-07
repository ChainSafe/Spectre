mod builder;
mod compression;
mod spread;
mod util;

pub use builder::SpreadThreadBuilder;
pub use spread::SpreadConfig;

use eth_types::Field;
use ff::PrimeField;
use halo2_base::gates::builder::KeygenAssignments;
use halo2_proofs::circuit::Value;
use itertools::Itertools;
use sha2::compress256;
use sha2::digest::generic_array::GenericArray;
use std::collections::HashMap;
use std::{cell::RefCell, char::MAX};

use crate::gadget::crypto::sha256::compression::{sha256_compression, INIT_STATE};
use crate::util::AssignedValueCell;
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

use self::builder::ShaContexts;
use self::spread::SpreadChip;

const SHA256_CONTEXT_ID: usize = usize::MAX;

pub trait HashInstructions<F: Field> {
    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;

    /// Digests input using hash function and returns finilized output.
    /// `MAX_INPUT_SIZE` is the maximum size of input that can be processed by the hash function.
    /// `strict` flag indicates whether to perform range check on input bytes.
    fn digest<const MAX_INPUT_SIZE: usize>(
        &self,
        ctx: ShaContexts<F>,
        input: HashInput<QuantumCell<F>>,
        strict: bool,
    ) -> Result<AssignedHashResult<F>, Error>;

    fn range(&self) -> &RangeChip<F>;
}

#[derive(Debug, Clone)]
pub struct AssignedHashResult<F: Field> {
    // pub input_len: AssignedValue<F>,
    pub input_bytes: Vec<AssignedValue<F>>,
    pub output_bytes: [AssignedValue<F>; 32],
}

#[derive(Debug, Clone)]
pub struct Sha256Chip<'a, F: Field> {
    range: &'a RangeChip<F>,
    spread: SpreadChip<'a, F>,
    // extra_assignments: RefCell<KeygenAssignments<F>>,
}

impl<'a, F: Field> HashInstructions<F> for Sha256Chip<'a, F> {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 32;

    fn digest<const MAX_INPUT_SIZE: usize>(
        &self,
        (ctx_gate, ctx_dense, ctx_spread): ShaContexts<F>,
        input: HashInput<QuantumCell<F>>,
        strict: bool,
    ) -> Result<AssignedHashResult<F>, Error> {
        let assigned_input = input.into_assigned(ctx_gate);

        let mut assigned_input_bytes = assigned_input.to_vec();
        let input_byte_size = assigned_input_bytes.len();
        let input_byte_size_with_9 = input_byte_size + 9;
        assert!(input_byte_size <= MAX_INPUT_SIZE);
        let range = self.range;
        let gate = &range.gate;

        assert!(assigned_input_bytes.len() <= MAX_INPUT_SIZE);

        let one_round_size = Self::BLOCK_SIZE;

        let num_round = if input_byte_size_with_9 % one_round_size == 0 {
            input_byte_size_with_9 / one_round_size
        } else {
            input_byte_size_with_9 / one_round_size + 1
        };
        let max_round = MAX_INPUT_SIZE / one_round_size;
        let padded_size = one_round_size * num_round;
        let zero_padding_byte_size = padded_size - input_byte_size_with_9;
        // let remaining_byte_size = MAX_INPUT_SIZE - padded_size;
        // assert_eq!(
        //     remaining_byte_size,
        //     one_round_size * (max_round - num_round)
        // );
        let mut assign_byte = |byte: u8| ctx_gate.load_witness(F::from(byte as u64));

        assigned_input_bytes.push(assign_byte(0x80));

        for _ in 0..zero_padding_byte_size {
            assigned_input_bytes.push(assign_byte(0u8));
        }

        let mut input_len_bytes = [0; 8];
        let le_size_bytes = (8 * input_byte_size).to_le_bytes();
        input_len_bytes[0..le_size_bytes.len()].copy_from_slice(&le_size_bytes);
        for byte in input_len_bytes.iter().rev() {
            assigned_input_bytes.push(assign_byte(*byte));
        }

        assert_eq!(assigned_input_bytes.len(), num_round * one_round_size);
        // for _ in 0..remaining_byte_size {
        //     assigned_input_bytes.push(assign_byte(0u8));
        // }
        assert_eq!(assigned_input_bytes.len(), MAX_INPUT_SIZE);

        if strict {
            for &assigned in assigned_input_bytes.iter() {
                range.range_check(ctx_gate, assigned, 8);
            }
        }

        let assigned_num_round = ctx_gate.load_witness(F::from(num_round as u64));

        // compute an initial state from the precomputed_input.
        let mut last_state = INIT_STATE;

        let mut assigned_last_state_vec = vec![last_state
            .iter()
            .map(|state| ctx_gate.load_witness(F::from(*state as u64)))
            .collect_vec()];

        let mut num_processed_input = 0;
        while num_processed_input < MAX_INPUT_SIZE {
            let assigned_input_word_at_round =
                &assigned_input_bytes[num_processed_input..(num_processed_input + one_round_size)];
            let new_assigned_hs_out = sha256_compression(
                (ctx_gate, ctx_dense, ctx_spread),
                &self.spread,
                assigned_input_word_at_round,
                assigned_last_state_vec.last().unwrap(),
            )?;

            assigned_last_state_vec.push(new_assigned_hs_out);
            num_processed_input += one_round_size;
        }

        let zero = ctx_gate.load_zero();
        let mut output_h_out = vec![zero; 8];
        for (n_round, assigned_state) in assigned_last_state_vec.into_iter().enumerate() {
            let selector = gate.is_equal(
                ctx_gate,
                QuantumCell::Constant(F::from(n_round as u64)),
                assigned_num_round,
            );
            for i in 0..8 {
                output_h_out[i] =
                    gate.select(ctx_gate, assigned_state[i], output_h_out[i], selector)
            }
        }
        let output_digest_bytes = output_h_out
            .into_iter()
            .flat_map(|assigned_word| {
                let be_bytes = assigned_word.value().get_lower_32().to_be_bytes().to_vec();
                let assigned_bytes = (0..4)
                    .map(|idx| {
                        let assigned = ctx_gate.load_witness(F::from(be_bytes[idx] as u64));
                        range.range_check(ctx_gate, assigned, 8);
                        assigned
                    })
                    .collect_vec();
                let mut sum = ctx_gate.load_zero();
                for (idx, assigned_byte) in assigned_bytes.iter().copied().enumerate() {
                    sum = gate.mul_add(
                        ctx_gate,
                        assigned_byte,
                        QuantumCell::Constant(F::from(1u64 << (24 - 8 * idx))),
                        sum,
                    );
                }
                ctx_gate.constrain_equal(&assigned_word, &sum);
                assigned_bytes
            })
            .collect_vec()
            .try_into()
            .unwrap();

        let result = AssignedHashResult {
            // input_len: assigned_input_byte_size,
            input_bytes: assigned_input_bytes,
            output_bytes: output_digest_bytes,
        };
        Ok(result)
    }

    /// Takes internal `KeygenAssignments` instance, leaving `Default::default()` in its place.
    /// **Warning**: In case `extra_assignments` wasn't default at the time of chip initialization,
    /// use `set_extra_assignments` to restore at the start of region declartion.
    /// Otherwise at the second synthesis run, the setted `extra_assignments` will be erased.
    // fn take_extra_assignments(&self) -> KeygenAssignments<F> {
    //     self.extra_assignments.take()
    // }

    fn range(&self) -> &RangeChip<F> {
        self.range
    }
}

impl<'a, F: Field> Sha256Chip<'a, F> {
    pub fn new(
        range: &'a RangeChip<F>,
        spread: SpreadChip<'a, F>,
        // extra_assignments: Option<KeygenAssignments<F>>,
    ) -> Self {
        Self {
            range,
            spread,
            // extra_assignments: RefCell::new(extra_assignments.unwrap_or_default()),
        }
    }

    // fn set_extra_assignments(&mut self, extra_assignments: KeygenAssignments<F>) {
    //     self.extra_assignments = RefCell::new(extra_assignments);
    // }

    fn assigned_cell2value(
        &self,
        ctx: &mut Context<F>,
        assigned_cell: &AssignedValueCell<F>,
    ) -> AssignedValue<F> {
        ctx.load_witness(assigned_cell.value())
    }

    fn upload_assigned_cells(
        &self,
        assigned_cells: impl IntoIterator<Item = &'a AssignedValueCell<F>>,
        offset: &mut usize,
        assigned_advices: &mut HashMap<(usize, usize), (circuit::Cell, usize)>,
        witness_gen_only: bool,
    ) -> Vec<AssignedValue<F>> {
        let assigned_values = assigned_cells
            .into_iter()
            .enumerate()
            .map(|(i, assigned_cell)| {
                let value = Assigned::Trivial(assigned_cell.value);

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
    use std::env::var;
    use std::vec;
    use std::{cell::RefCell, marker::PhantomData};

    use crate::builder::ShaCircuitBuilder;
    use crate::table::Sha256Table;
    use crate::util::{full_prover, full_verifier, gen_pkey, Challenges, IntoWitness};

    use super::*;
    use ark_std::{end_timer, start_timer};
    use eth_types::Test;
    use halo2_base::gates::builder::FlexGateConfigParams;
    use halo2_base::gates::range::RangeConfig;
    use halo2_base::utils::fs::gen_srs;
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
        spread_config: SpreadConfig<F>,
        range: RangeConfig<F>,
        challenges: Challenges<Value<F>>,
    }

    fn get_circuit<F: Field>(
        k: usize,
        mut builder: SpreadThreadBuilder<F>,
        input_vector: &[Vec<u8>],
    ) -> ShaCircuitBuilder<F> {
        let range = RangeChip::default(8);
        let spread = SpreadChip::new(&range);

        let sha256 = Sha256Chip::new(&range, spread);
        let (ctx_gate, ctx_dense, ctx_spread) = builder.main();

        for input in input_vector {
            let _ = sha256
                .digest::<128>(
                    (ctx_gate, ctx_dense, ctx_spread),
                    input.as_slice().into_witness(),
                    false
                )
                .unwrap();
        }

        builder.config(k, Some(0));
        ShaCircuitBuilder::new(builder, range, None)
    }

    #[test]
    fn test_sha256_chip_constant_size() {
        let k = 15;

        let test_input = vec![0u8; 64];

        let builder = SpreadThreadBuilder::<Fr>::new(false);

        let circuit = get_circuit(k, builder, &[test_input]);
        let prover = MockProver::run(k as u32, &circuit, vec![]).unwrap();

        prover.assert_satisfied_par();
    }

    // #[test]
    // fn test_sha256_params_gen() {
    //     let k = TestCircuit::<Fr>::K as u32;
    //     let test_input = vec![0u8; 128];
    //     let test_output: [u8; 32] = Sha256::digest(&test_input).into();
    //     let range = RangeChip::default(TestCircuit::<Fr>::LOOKUP_BITS);
    //     let builder = GateThreadBuilder::keygen();
    //     let circuit = TestCircuit::<Fr> {
    //         builder: RefCell::new(builder),
    //         range,
    //         test_input: test_input.into_witness(),
    //         test_output,
    //         _f: PhantomData,
    //     };
    //     let params = gen_srs(k);
    //     let pkey = gen_pkey(|| "sha256_chip", &params, None, circuit).unwrap();
    // }

    // #[test]
    // fn test_sha256_proof_gen() {
    //     let k = TestCircuit::<Fr>::K as u32;
    //     let test_input = vec![2u8; 32];
    //     let test_output: [u8; 32] = Sha256::digest(&test_input).into();
    //     let range = RangeChip::default(TestCircuit::<Fr>::LOOKUP_BITS);
    //     let builder = GateThreadBuilder::keygen();
    //     let circuit = TestCircuit::<Fr> {
    //         builder: RefCell::new(builder),
    //         range,
    //         test_input: HashInput::TwoToOne(
    //             test_input.clone().into_witness(),
    //             test_input.into_witness(),
    //         ),
    //         test_output,
    //         _f: PhantomData,
    //     };
    //     let pf_time = start_timer!(|| "mock prover");

    //     let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    //     prover.assert_satisfied();
    //     prover.verify().unwrap();
    //     end_timer!(pf_time);

    //     let params = gen_srs(k);

    //     let pkey = gen_pkey(|| "sha256_chip", &params, None, circuit.clone()).unwrap();

    //     let proof = full_prover(&params, &pkey, circuit, vec![]);

    //     let is_valid = full_verifier(&params, pkey.get_vk(), proof, vec![]);
    //     assert!(is_valid);
    // }
}
