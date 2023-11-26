mod config;
mod gate;
mod util;
mod witness;

use eth_types::Field;
use halo2_base::gates::RangeChip;
use halo2_base::{gates::flex_gate::threads::CommonCircuitBuilder, Context};
use itertools::Itertools;
use zkevm_hashes::sha256::vanilla::util::get_num_sha2_blocks;
use zkevm_hashes::{
    sha256::vanilla::{
        util::to_be_bytes,
        witness::{generate_witnesses_multi_sha256, generate_witnesses_sha256},
    },
    util::word::Word,
};

use crate::witness::HashInput;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::plonk::Error,
    AssignedValue, QuantumCell,
};
use sha2::Digest;

pub use self::gate::ShaBitGateManager;
use self::util::{NUM_BYTES_FINAL_HASH, NUM_WORDS_TO_ABSORB};
use super::{HashInstructions, ShaCircuitBuilder};
use crate::gadget::common::to_bytes_le;

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

    fn digest(
        &self,
        builder: &mut Self::CircuitBuilder,
        input: impl IntoIterator<Item = QuantumCell<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let assigned_bytes = input
            .into_iter()
            .map(|cell| match cell {
                QuantumCell::Existing(v) => v,
                QuantumCell::Witness(v) => builder.main().load_witness(v),
                QuantumCell::Constant(v) => builder.main().load_constant(v),
                _ => unreachable!(),
            })
            .collect_vec();

        let binary_input: HashInput<u8> = HashInput::Single(
            assigned_bytes
                .iter()
                .map(|av| av.value().get_lower_32() as u8)
                .collect_vec()
                .into(),
        );

        let input_len = assigned_bytes.len();
        let max_byte_size = assigned_bytes.len();
        let range = &self.range;
        let gate = &range.gate;


        let mut virtual_rows = vec![];
        let input_bytes = binary_input.to_vec();

        generate_witnesses_sha256(&mut virtual_rows, &input_bytes);
        let blocks = builder.sha.load_virtual_rows(virtual_rows);

        let num_rounds = get_num_sha2_blocks(input_len);

        let num_input_words = (input_len + 3) / 4;
        let num_input_rounds = num_input_words.div_ceil(NUM_WORDS_TO_ABSORB);

        let byte_bases = (0..4)
        .map(|i| QuantumCell::Constant(gate.pow_of_two()[i * 8]))
        .collect_vec();

        for r in 0..num_input_rounds {
            for w in 0..(num_input_words - r * NUM_WORDS_TO_ABSORB) {
                let i = (r * NUM_WORDS_TO_ABSORB + w) * 4;
                let checksum = gate.inner_product(builder.main(), assigned_bytes[i..i+4].to_vec(), byte_bases.clone());
                builder.main().constrain_equal(&checksum, &blocks[r].word_values[w]);
            }
        }

        let hash_bytes = word_to_bytes_le(blocks[num_rounds-1].hash, gate, builder.main());

        Ok(hash_bytes)
    }

    fn digest_varlen(
        &self,
        ctx: &mut Self::CircuitBuilder,
        input: impl IntoIterator<Item = QuantumCell<F>>,
        max_input_len: usize,
    ) -> Result<Self::Output, Error> {
        unimplemented!()
    }
}

impl<'a, F: Field> Sha256ChipWide<'a, F> {
    pub fn new(range: &'a RangeChip<F>, randomness: F) -> Self {
        Self { range, randomness }
    }
}

pub fn word_to_bytes_le<F: Field>(
    word: Word<AssignedValue<F>>,
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
) -> Vec<AssignedValue<F>> {
    to_bytes_le::<_, 16>(&word.lo(), gate, ctx)
        .into_iter()
        .chain(to_bytes_le::<_, 16>(&word.hi(), gate, ctx))
        .collect()
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
