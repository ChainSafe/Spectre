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
            let mut max_bytes = max_len + 9;
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
        let input_byte_size_with_9 = input_byte_size + 9;
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
        // let remaining_byte_size = MAX_INPUT_SIZE - padded_size;
        // assert_eq!(
        //     remaining_byte_size,
        //     one_round_size * (max_round - num_round)
        // );
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
        // for _ in 0..remaining_byte_size {
        //     assigned_input_bytes.push(assign_byte(0u8));
        // }

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
        let lookup_bits = if range.lookup_bits() > 8 { 16 } else { 8 };

        Self {
            spread: SpreadChip::new(range, lookup_bits),
        }
    }
}

#[cfg(test)]
mod test {
    // use std::env::var;
    // use std::vec;
    // use std::{cell::RefCell, marker::PhantomData};

    // use crate::gadget::crypto::ShaCircuitBuilder;
    // use crate::util::{gen_pkey, IntoWitness};
    // use super::*;
    // use ark_std::{end_timer, start_timer};
    // use eth_types::Testnet;
    // use halo2_base::gates::range::RangeConfig;
    // use halo2_base::halo2_proofs::{
    //     circuit::{Layouter, SimpleFloorPlanner},
    //     dev::MockProver,
    //     halo2curves::bn256::Fr,
    //     plonk::{Circuit, ConstraintSystem},
    // };
    // use halo2_base::utils::fs::gen_srs;
    // use halo2_base::SKIP_FIRST_PASS;
    // use sha2::{Digest, Sha256};

    // fn test_circuit<F: Field>(
    //     k: usize,
    //     mut builder: ShaThreadBuilder<F>,
    //     input_vector: &[Vec<u8>],
    // ) -> Result<ShaCircuitBuilder<F, ShaThreadBuilder<F>>, Error> {
    //     let range = RangeChip::default(8);
    //     let sha256 = Sha256Chip::new(&range);

    //     for input in input_vector {
    //         let _ = sha256.digest::<64>(&mut builder, input.as_slice().into_witness(), false)?;
    //     }

    //     builder.config(k, None);
    //     Ok(ShaCircuitBuilder::mock(builder))
    // }

    // #[test]
    // fn test_sha256_chip_constant_size() {
    //     let k = 15;

    //     let test_input = vec![0u8; 64];

    //     let builder = ShaThreadBuilder::<Fr>::mock();

    //     let circuit = test_circuit(k, builder, &[test_input]);
    //     let prover = MockProver::run(k as u32, &circuit.unwrap(), vec![]).unwrap();

    //     prover.assert_satisfied_par();
    // }

    // #[test]
    // fn test_sha256_params_gen() {
    //     let k = 15;
    //     let test_input = vec![0u8; 64];
    //     let builder = ShaThreadBuilder::<Fr>::keygen();

    //     let circuit = test_circuit(k, builder, &[test_input]).unwrap();

    //     let params = gen_srs(k as u32);
    //     let pk = gen_pkey(|| "sha256_chip", &params, None, &circuit).unwrap();
    // }

    // #[test]
    // fn test_sha256_proof_gen() {
    //     let k = 15;
    //     let test_input = vec![0u8; 64];
    //     let builder = ShaThreadBuilder::<Fr>::keygen();

    //     let circuit = test_circuit(k, builder, &[test_input.clone()]).unwrap();

    //     let params = gen_srs(k as u32);
    //     let pk = gen_pkey(|| "sha256_chip", &params, None, &circuit).unwrap();

    //     let break_points = circuit.break_points.take();

    //     let builder = ShaThreadBuilder::<Fr>::prover();

    //     let circuit = test_circuit(k, builder, &[test_input]).unwrap();

    //     let proof = full_prover(&params, &pk, circuit, vec![]);

    //     let is_valid = full_verifier(&params, pk.get_vk(), proof, vec![]);
    //     assert!(is_valid);
    // }
}
