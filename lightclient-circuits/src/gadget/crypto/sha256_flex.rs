// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

// ! This file is a modified version of the original file from https://github.com/zkemail/halo2-dynamic-sha256 (MIT license)
// ! The original implementation is made to be "dynamic" in a sense that it can handle variable-length inputs.
// ! This is not needed for our use case so those "extra" contraints are removed.

mod compression;
mod gate;
mod spread;
mod util;

use crate::gadget::crypto::sha256_flex::compression::{sha256_compression, INIT_STATE};
use eth_types::Field;
pub use gate::ShaFlexGateManager;
use halo2_base::gates::flex_gate::threads::CommonCircuitBuilder;
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::plonk::Error;
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    AssignedValue,
};
use itertools::Itertools;
pub use spread::SpreadConfig;

pub use self::gate::ShaContexts;
pub(super) use self::gate::FIRST_PHASE;
pub use self::spread::SpreadChip;

use super::{HashInstructions, ShaCircuitBuilder};

const SHA256_INPUT_LEN_PADDING_LEN: usize = 9;

/// [`Sha256Chip`] provides functions to compute SHA256 hash [`SpreadConfig`] gates.
/// This is version of SHA256 chip is flexible by allowing do distribute advice cells into multiple sets of columns (`dense`, `spread`).
/// It also heavily benefits from lookup tables (bigger `num_bits_lookup` is better).
#[derive(Debug, Clone)]
pub struct Sha256Chip<'a, F: Field> {
    spread: SpreadChip<'a, F>,
}

impl<'a, F: Field> HashInstructions<F> for Sha256Chip<'a, F> {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 32;

    type CircuitBuilder = ShaCircuitBuilder<F, ShaFlexGateManager<F>>;
    type Output = Vec<AssignedValue<F>>;

    fn digest_varlen(
        &self,
        builder: &mut Self::CircuitBuilder,
        input: impl IntoIterator<Item = QuantumCell<F>>,
        max_len: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let max_processed_bytes = {
            let mut max_bytes = max_len + SHA256_INPUT_LEN_PADDING_LEN;
            let remainder = max_bytes % 64;
            if remainder != 0 {
                max_bytes += 64 - remainder;
            }
            max_bytes
        };

        let mut assigned_input_bytes = input
            .into_iter()
            .map(|cell| match cell {
                QuantumCell::Existing(v) => v,
                QuantumCell::Witness(v) => builder.main().load_witness(v),
                QuantumCell::Constant(v) => builder.main().load_constant(v),
                _ => unreachable!(),
            })
            .collect_vec();

        let input_byte_size = assigned_input_bytes.len();
        let input_byte_size_with_9 = input_byte_size + SHA256_INPUT_LEN_PADDING_LEN;
        let range = self.spread.range();
        let gate = &range.gate;

        assert!(input_byte_size <= max_len);

        let one_round_size = Self::BLOCK_SIZE;

        let num_round = if input_byte_size_with_9 % one_round_size == 0 {
            input_byte_size_with_9 / one_round_size
        } else {
            input_byte_size_with_9 / one_round_size + 1
        };
        let padded_size = one_round_size * num_round;
        let zero_padding_byte_size = padded_size - input_byte_size_with_9;

        let mut assign_byte = |byte: u8| builder.main().load_witness(F::from(byte as u64));

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

        let assigned_num_round = builder.main().load_witness(F::from(num_round as u64));

        // compute an initial state from the precomputed_input.
        let last_state = INIT_STATE;

        let mut assigned_last_state_vec = vec![last_state
            .iter()
            .map(|state| builder.main().load_witness(F::from(*state as u64)))
            .collect_vec()];

        let mut num_processed_input = 0;
        while num_processed_input < max_processed_bytes {
            let assigned_input_word_at_round =
                &assigned_input_bytes[num_processed_input..(num_processed_input + one_round_size)];
            let new_assigned_hs_out = sha256_compression(
                builder,
                &self.spread,
                assigned_input_word_at_round,
                assigned_last_state_vec.last().unwrap(),
            )?;

            assigned_last_state_vec.push(new_assigned_hs_out);
            num_processed_input += one_round_size;
        }

        let zero = builder.main().load_zero();
        let mut output_h_out = vec![zero; 8];
        for (n_round, assigned_state) in assigned_last_state_vec.into_iter().enumerate() {
            let selector = gate.is_equal(
                builder.main(),
                QuantumCell::Constant(F::from(n_round as u64)),
                assigned_num_round,
            );
            for i in 0..8 {
                output_h_out[i] =
                    gate.select(builder.main(), assigned_state[i], output_h_out[i], selector)
            }
        }
        let output_digest_bytes = output_h_out
            .into_iter()
            .flat_map(|assigned_word| {
                let be_bytes = assigned_word.value().get_lower_32().to_be_bytes().to_vec();
                let assigned_bytes = (0..4)
                    .map(|idx| {
                        let assigned = builder.main().load_witness(F::from(be_bytes[idx] as u64));
                        range.range_check(builder.main(), assigned, 8);
                        assigned
                    })
                    .collect_vec();
                let mut sum = builder.main().load_zero();
                for (idx, assigned_byte) in assigned_bytes.iter().copied().enumerate() {
                    sum = gate.mul_add(
                        builder.main(),
                        assigned_byte,
                        QuantumCell::Constant(F::from(1u64 << (24 - 8 * idx))),
                        sum,
                    );
                }
                builder.main().constrain_equal(&assigned_word, &sum);
                assigned_bytes
            })
            .collect_vec();

        Ok(output_digest_bytes)
    }

    fn digest(
        &self,
        ctx: &mut Self::CircuitBuilder,
        input: impl IntoIterator<Item = QuantumCell<F>>,
    ) -> Result<Self::Output, Error> {
        let input = input.into_iter().collect_vec();
        let input_len = input.len();
        self.digest_varlen(ctx, input, input_len)
    }
}

impl<'a, F: Field> Sha256Chip<'a, F> {
    pub fn new(range: &'a RangeChip<F>) -> Self {
        // Spread chip requires 16 % lookup_bits == 0 so we set it to either 8 or 16 based on circuit degree.
        let lookup_bits = if range.lookup_bits() > 8 { 16 } else { 8 };

        Self {
            spread: SpreadChip::new(range, lookup_bits),
        }
    }
}
