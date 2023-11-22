mod config;
mod gate;
mod util;
mod witness;

use eth_types::Field;
use halo2_base::gates::flex_gate::threads::CommonCircuitBuilder;
use halo2_base::gates::RangeChip;
use itertools::Itertools;

use crate::gadget::crypto::sha256_wide::util::Sha256AssignedRows;
use crate::gadget::crypto::sha256_wide::witness::multi_sha256;
use crate::gadget::rlc;
use crate::witness::HashInput;

use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::plonk::Error,
    AssignedValue, QuantumCell,
};

pub use self::gate::ShaBitGateManager;
use self::util::{NUM_BYTES_FINAL_HASH, NUM_WORDS_TO_ABSORB};

use super::{HashInstructions, ShaCircuitBuilder};

#[derive(Debug)]
pub struct Sha256ChipWide<'a, F: Field> {
    range: &'a RangeChip<F>,
    randomness: F,
}

#[derive(Clone, Debug)]
pub struct AssignedSha256Round<F: Field> {
    /// Whether the row is final.
    pub is_final: AssignedValue<F>,
    /// Input length at the row.
    pub input_len: AssignedValue<F>,
    /// Input words at the row.
    pub input_rlcs: [AssignedValue<F>; NUM_WORDS_TO_ABSORB],
    /// Whether the row is padding.
    pub padding_selectors: [[AssignedValue<F>; 4]; NUM_WORDS_TO_ABSORB],
    /// Output words at the row.
    pub output_rlc: AssignedValue<F>,
}

impl<'a, F: Field> HashInstructions<F> for Sha256ChipWide<'a, F> {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 32;

    type CircuitBuilder = ShaCircuitBuilder<F, ShaBitGateManager<F>>;
    type Output = Vec<AssignedValue<F>>;

    fn digest<const MAX_INPUT_SIZE: usize>(
        &self,
        builder: &mut Self::CircuitBuilder,
        input: impl IntoIterator<Item = QuantumCell<F>>,
        _strict: bool,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let assigned_input = input
            .into_iter()
            .map(|cell| match cell {
                QuantumCell::Existing(v) => v,
                QuantumCell::Witness(v) => builder.main().load_witness(v),
                QuantumCell::Constant(v) => builder.main().load_constant(v),
                _ => unreachable!(),
            })
            .collect_vec();

        let binary_input: HashInput<u8> = HashInput::Single(
            assigned_input
                .iter()
                .map(|av| av.value().get_lower_32() as u8)
                .collect_vec()
                .into(),
        );

        let mut assigned_input_bytes = assigned_input.to_vec();
        let rnd = QuantumCell::Constant(self.randomness);
        let input_byte_size = assigned_input_bytes.len();
        let max_byte_size = MAX_INPUT_SIZE;
        assert!(input_byte_size <= max_byte_size);
        let range = &self.range;
        let gate = &range.gate;

        assert!(assigned_input_bytes.len() <= MAX_INPUT_SIZE);

        let mut assigned_rounds = vec![];
        let assigned_output =
            self.load_digest::<MAX_INPUT_SIZE>(builder, binary_input, &mut assigned_rounds)?;

        let one_round_size = Self::BLOCK_SIZE;

        let num_round = if input_byte_size % one_round_size == 0 {
            input_byte_size / one_round_size
        } else {
            input_byte_size / one_round_size + 1
        };
        let padded_size = one_round_size * num_round;
        let zero_padding_byte_size = padded_size - input_byte_size;
        let max_round = max_byte_size / one_round_size;

        let mut assign_byte = |byte: u8| builder.main().load_witness(F::from(byte as u64));

        for _ in 0..zero_padding_byte_size {
            assigned_input_bytes.push(assign_byte(0u8));
        }

        assert_eq!(assigned_input_bytes.len(), num_round * one_round_size);

        for &assigned in assigned_input_bytes.iter() {
            range.range_check(builder.main(), assigned, 8);
        }

        let zero = builder.main().load_zero();
        let mut full_input_len = zero;

        let mut cur_input_rlc = zero;
        let ctx_gate = builder.main();
        for round_idx in 0..max_round {
            full_input_len = {
                let muled = gate.mul(
                    ctx_gate,
                    assigned_rounds[round_idx].is_final,
                    assigned_rounds[round_idx].input_len,
                );
                gate.add(ctx_gate, full_input_len, muled)
            };

            for word_idx in 0..NUM_WORDS_TO_ABSORB {
                let offset_in = 64 * round_idx + 4 * word_idx;
                let assigned_input_u32 = &assigned_input_bytes[offset_in..(offset_in + 4)];

                for (idx, &assigned_byte) in assigned_input_u32.iter().enumerate() {
                    let tmp = gate.mul_add(ctx_gate, cur_input_rlc, rnd, assigned_byte);
                    cur_input_rlc = gate.select(
                        ctx_gate,
                        cur_input_rlc,
                        tmp,
                        assigned_rounds[round_idx].padding_selectors[word_idx][idx],
                    );
                }

                ctx_gate.constrain_equal(
                    &cur_input_rlc,
                    &assigned_rounds[round_idx].input_rlcs[word_idx],
                );
            }

            let hash_rlc = rlc::assigned_value(&assigned_output, &rnd, gate, ctx_gate);
            ctx_gate.constrain_equal(&hash_rlc, &assigned_rounds[round_idx].output_rlc);
        }

        Ok(assigned_output.to_vec())
    }
}

impl<'a, F: Field> Sha256ChipWide<'a, F> {
    pub fn new(range: &'a RangeChip<F>, randomness: F) -> Self {
        Self { range, randomness }
    }

    pub fn load_digest<const MAX_INPUT_SIZE: usize>(
        &self,
        builder: &mut ShaCircuitBuilder<F, ShaBitGateManager<F>>,
        input: HashInput<u8>,
        assigned_rounds: &mut Vec<AssignedSha256Round<F>>,
    ) -> Result<[AssignedValue<F>; NUM_BYTES_FINAL_HASH], Error> {
        let max_round = MAX_INPUT_SIZE / Self::BLOCK_SIZE;

        let mut assigned_rows = Sha256AssignedRows::new();
        let witness = multi_sha256(&[input], self.randomness);
        let vec_vecs = witness
            .iter()
            .map(|sha256_row| {
                builder
                    .sha
                    .sha_contexts()
                    .load_sha256_row(sha256_row, &mut assigned_rows)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let hashes: Vec<[_; NUM_BYTES_FINAL_HASH]> = vec_vecs
            .into_iter()
            .filter_map(|hash_bytes| {
                (!hash_bytes.is_empty()).then(|| hash_bytes.try_into().unwrap())
            })
            .collect();

        assert_eq!(hashes.len(), 1);

        let hash_sha = hashes[0];

        let ctx_gate = builder.main();

        let mut reassign_to_gate = |val_sha: AssignedValue<F>| -> AssignedValue<F> {
            let val_gate = ctx_gate.load_witness(*val_sha.value());
            ctx_gate.constrain_equal(&val_sha, &val_gate);
            val_gate
        };

        for round_idx in 0..max_round {
            let input_len = reassign_to_gate(assigned_rows.input_len[round_idx]);

            let input_rlcs = assigned_rows.input_rlc[16 * round_idx..16 * (round_idx + 1)]
                .iter()
                .map(|v| reassign_to_gate(*v))
                .collect_vec()
                .try_into()
                .unwrap();

            let padding_selectors = assigned_rows.padding_selectors
                [16 * round_idx..16 * (round_idx + 1)]
                .iter()
                .map(|values| values.map(&mut reassign_to_gate))
                .collect_vec()
                .try_into()
                .unwrap();

            let is_final = reassign_to_gate(assigned_rows.is_enabled[round_idx]);
            let output_rlc = reassign_to_gate(assigned_rows.output_rlc[0]);

            assigned_rounds.push(AssignedSha256Round {
                is_final,
                input_len,
                input_rlcs,
                padding_selectors,
                output_rlc,
            })
        }

        let hash_gate = hash_sha.map(reassign_to_gate);

        Ok(hash_gate)
    }
}

// #[cfg(test)]
// mod test {
//     use std::env::var;
//     use std::vec;
//     use std::{cell::RefCell, marker::PhantomData};

//     use crate::gadget::crypto::{constant_randomness, ShaCircuitBuilder};
//     use crate::util::{full_prover, full_verifier, gen_pkey, Challenges, IntoWitness};

//     use super::*;
//     use ark_std::{end_timer, start_timer};
//     use eth_types::Testnet;
//     use halo2_base::gates::builder::FlexGateConfigParams;
//     use halo2_base::gates::range::RangeConfig;
//     use halo2_base::utils::fs::gen_srs;
//     use halo2_base::SKIP_FIRST_PASS;
//     use halo2_base::{
//         gates::{builder::GateThreadBuilder, range::RangeStrategy},
//         halo2_proofs::{
//             circuit::{Layouter, SimpleFloorPlanner},
//             dev::MockProver,
//             halo2curves::bn256::Fr,
//             plonk::{Circuit, ConstraintSystem},
//         },
//     };
//     use sha2::{Digest, Sha256};

//     // fn test_circuit<F: Field>(
//     //     k: usize,
//     //     builder: &mut ShaBitThreadBuilder<F>,
//     //     input_vector: &[Vec<u8>],
//     // ) -> Result<(), Error> {
//     //     let range = RangeChip::default(8);
//     //     let sha256 = Sha256ChipWide::new(&range, constant_randomness());

//     //     for input in input_vector {
//     //         let _ = sha256.digest::<64>(builder, input.as_slice().into_witness(), false)?;
//     //     }

//     //     builder.config(k, None);

//     //     Ok(())
//     // }

//     // #[test]
//     // fn test_sha256_chip_constant_size() {
//     //     let k = 10;

//     //     let test_input = vec![0u8; 64];

//     //     let mut builder = ShaBitThreadBuilder::<Fr>::mock();

//     //     test_circuit(k, &mut builder, &[test_input]).unwrap();

//     //     let circuit = ShaCircuitBuilder::mock(builder);

//     //     let prover = MockProver::run(k as u32, &circuit, vec![]).unwrap();

//     //     prover.assert_satisfied_par();
//     // }

//     // #[test]
//     // fn test_sha256_wide_params_gen() {
//     //     let k = 10;
//     //     let test_input = vec![1u8; 64];
//     //     let mut builder = ShaBitThreadBuilder::<Fr>::keygen();

//     //     test_circuit(k, &mut builder, &[test_input]).unwrap();

//     //     let circuit = ShaCircuitBuilder::keygen(builder);

//     //     let params = gen_srs(k as u32);
//     //     let pk = gen_pkey(|| "sha256_wide_chip", &params, None, &circuit).unwrap();
//     // }
// }
