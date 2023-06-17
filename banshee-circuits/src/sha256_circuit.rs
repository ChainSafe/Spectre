// mod sha256_compression;
// mod util;
mod table16;
mod sha256;
mod sha256_bit;

use std::vec;

use crate::{
    table::{LookupTable, StateTable, SHA256Table},
    util::{Cell, Challenges, SubCircuit, SubCircuitConfig},
    witness::{self},
};
use eth_types::*;
use halo2_proofs::{
    circuit::{Layouter, Region, Value, Chip},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed, Instance,
        SecondPhase, Selector, VirtualCells,
    },
    poly::Rotation,
};
use halo2_base::{
    QuantumCell,
    gates::{range::RangeConfig, RangeInstructions, RangeChip},
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    // utils::{bigint_to_fe, biguint_to_fe, fe_to_bigint, fe_to_biguint, modulus},
    AssignedValue, Context, utils::{ScalarField, value_to_option}, ContextCell
};
use itertools::Itertools;
use num::Integer;
use table16::BlockWord;

use self::{sha256::{Sha256Instructions, Table16Config, Table16Chip}, table16::{AssignedBits, State, RoundWordDense}};

const BLOCK_BYTE: usize = 64;
const DIGEST_BYTE: usize = 32;

/// The size of a SHA-256 block, in 32-bit words.
pub const BLOCK_SIZE: usize = 16;
/// The size of a SHA-256 digest, in 32-bit words.
pub const DIGEST_SIZE: usize = 8;

#[derive(Clone, Debug)]
pub struct SHA256ChipConfig<F: Field> {
    table16: Table16Config<F>,
    pub max_byte_size: usize,
    range: RangeConfig<F>,
}

#[derive(Clone, Debug)]
pub struct SHA256Chip<F: Field> {
    config: SHA256ChipConfig<F>,
    table16: Table16Chip<F>,
    range: RangeChip<F>,
    state: State<F>,
}

impl<F: Field> Chip<F> for SHA256Chip<F> {
    type Config = SHA256ChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> SHA256Chip<F> {
    const ONE_ROUND_INPUT_BYTES: usize = 64;
    pub fn configure(
        table16config: Table16Config<F>,
        max_byte_size: usize,
        range: RangeConfig<F>,
    ) -> <Self as Chip<F>>::Config {
        debug_assert_eq!(max_byte_size % Self::ONE_ROUND_INPUT_BYTES, 0);
        SHA256ChipConfig {
            table16: table16config,
            max_byte_size,
            range,
        }
    }

    pub fn digest(
        &mut self,
        ctx: &mut Context<F>,
        assinged_inputs: Vec<AssignedValue<F>>,
        mut layouter: &mut impl Layouter<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let input_byte_size = assinged_inputs.len();
        let input_byte_size_with_9 = input_byte_size + 9;
        let one_round_size = Self::ONE_ROUND_INPUT_BYTES;
        let num_round = if input_byte_size_with_9 % one_round_size == 0 {
            input_byte_size_with_9 / one_round_size
        } else {
            input_byte_size_with_9 / one_round_size + 1
        };
        let padded_size = one_round_size * num_round;
        let max_byte_size = self.config.max_byte_size;
        let max_round = max_byte_size / one_round_size;
        debug_assert!(padded_size <= max_byte_size);
        let zero_padding_byte_size = padded_size - input_byte_size_with_9;
        let remaining_byte_size = max_byte_size - padded_size;
        debug_assert_eq!(
            remaining_byte_size,
            one_round_size * (max_round - num_round)
        );
        let mut padding = vec![];
        padding.push(0x80);
        for _ in 0..zero_padding_byte_size {
            padding.push(0);
        }
        let mut input_len_bytes = [0; 8];
        let le_size_bytes = (8 * input_byte_size).to_le_bytes();
        input_len_bytes[0..le_size_bytes.len()].copy_from_slice(&le_size_bytes);
        for byte in input_len_bytes.iter().rev() {
            padding.push(*byte);
        }

        assert_eq!(assinged_inputs.len() + padding.len(), num_round * one_round_size);
        // for _ in 0..remaining_byte_size {
        //     padding.push(0);
        // }
        // assert_eq!(padding.len(), max_byte_size);


        let assigned_padded_inputs = {
            let assigned_padding = padding
                .iter()
                .map(|byte| ctx.load_witness(F::from(*byte as u64)))
                .collect::<Vec<AssignedValue<F>>>();

            assinged_inputs
                .clone()
                .into_iter()
                .chain(assigned_padding)
                .collect_vec()
        };


        let range = self.range.clone();

        for assigned_byte in assigned_padded_inputs.iter().copied() {
            self.range.range_check(ctx, assigned_byte, 8);
        }


        for (i, assigned_input_block) in assigned_padded_inputs
            .chunks((32 / 8) * BLOCK_SIZE)
            .enumerate()
        {
            let input_block = assigned_input_block
                .iter()
                .map(|cell| cell.value().get_lower_32().try_into().unwrap())
                .collect::<Vec<u8>>();

            let blockword_inputs: [_; 16] = input_block
                .chunks(32 / 8)
                .map(|chunk| BlockWord(Value::known(u32::from_be_bytes(chunk.try_into().unwrap()))))
                .collect_vec()
                .try_into()
                .unwrap();

            self.state = self.compute_round(ctx, layouter, blockword_inputs)?;
        }

        Ok(vec![])
    }

    fn compute_round(
        &self,
        ctx: &mut Context<F>,
        layouter: &mut impl Layouter<F>,
        input: [BlockWord; BLOCK_SIZE],
    ) -> Result<State<F>, Error> {
        let mut base_gate = self.range().gate();

        let last_state = &self.state;
        let last_digest = self.state_to_assigned_halves(ctx, last_state);
        let (compressed_state, assigned_inputs) = self.table16.compress(layouter, last_state, input)?;

        let compressed_state_values = self.state_to_assigned_halves(ctx, &compressed_state);

        let word_sums = last_digest
            .iter()
            .copied()
            .zip(compressed_state_values)
            .map(|(digest_word, comp_word)| {
                base_gate.add(ctx, digest_word, comp_word)
            })
            .collect_vec();

        let u32_mod = 1u128 << 32;
        let lo_his = word_sums
            .iter()
            .map(|sum| {
                (
                    F::from_u128(sum.value().get_lower_128() % u32_mod),
                    F::from_u128(sum.value().get_lower_128() >> 32),
                )
            })
            .collect_vec();
        let assigned_los = lo_his
            .iter()
            .map(|(lo, hi)| ctx.load_witness(*lo))
            .collect_vec();
        let assigned_his = lo_his
            .iter()
            .map(|(lo, hi)| ctx.load_witness(*hi))
            .collect_vec();
        let u32 = ctx.load_constant(F::from(1 << 32));

        let combines = assigned_los
            .iter()
            .copied()
            .zip(assigned_his)
            .map(|(lo, hi)| {
                base_gate
                    .mul_add(ctx, hi, u32, lo)
            })
            .collect_vec();

        for (combine, word_sum) in combines.iter().zip(&word_sums) {
            ctx.constrain_equal(combine, word_sum);
        }

        let mut new_state_word_vals = [0u32; 8];
        for i in 0..8 {
            new_state_word_vals[i] = assigned_los[i].value().get_lower_128().try_into().unwrap()
        }

        let new_state = self
            .table16
            .compression_config()
            .initialize_with_iv(layouter, new_state_word_vals)?;

        Ok(new_state)
    }


    // pub fn decompose_digest_to_bytes(
    //     &self,
    //     layouter: &mut impl Layouter<F>,
    //     digest: &[AssignedValue<F>],
    // ) -> Result<[AssignedValue<F>; 4 * DIGEST_SIZE], Error> {
    //     let range = self.range();
    //     let base_gate = range.gate();
    //     let mut assigned_bytes = Vec::new();

    //     for word in digest.into_iter() {
            
    //         let mut bytes = halo2_base::utils::decompose(word.value(), 8, 32);
    //         bytes.reverse();
    //         assigned_bytes.append(&mut bytes);
    //     }
    //     Ok(assigned_bytes.try_into().unwrap())
    // }

    // fn decompose(
    //     &self,
    //     unassigned: &F,
    //     limb_bit_len: usize,
    //     bit_len: usize,
    // ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
    //     let (number_of_limbs, overflow_bit_len) = bit_len.div_rem(&limb_bit_len);
    //     let number_of_limbs = number_of_limbs + if overflow_bit_len > 0 { 1 } else { 0 };
    //     let mut decomposed_bytes = halo2_base::utils::decompose(unassigned, number_of_limbs, number_of_limbs);


    //     let mut bases = vec![F::one()];
    //     let mut bases_assigned = vec![];
    //     for i in 1..31 {
    //         bases.push(bases[i - 1].mul(&F::from(
    //             0x0000000000000000000000000000000000000000000000000000000000000100,
    //         )));
    //         bases_assigned.push(
    //             self.main_gate
    //                 .as_ref()
    //                 .borrow_mut()
    //                 .assign_constant(bases[i]),
    //         );
    //     }

    //     let terms: Vec<_> = decomposed_bytes
    //         .into_iter()
    //         .map(|e| self.main_gate.as_ref().borrow_mut().assign(e))
    //         .zip(&bases_assigned)
    //         .map(|(limb, base)| (limb, *base))
    //         .collect();

    //     let zero = self
    //         .main_gate
    //         .as_ref()
    //         .borrow_mut()
    //         .assign_constant(Fr::zero());
    //     self.decompose_terms(&terms[..], zero)
    // }

    fn state_to_assigned_halves(
        &self,
        ctx: &mut Context<F>,
        state: &State<F>,
    ) -> [AssignedValue<F>; DIGEST_SIZE] {
        let (a, b, c, d, e, f, g, h) = state.clone().split_state();

        [
            self.concat_word_halves(ctx, a.dense_halves()),
            self.concat_word_halves(ctx, b.dense_halves()),
            self.concat_word_halves(ctx, c.dense_halves()),
            self.concat_word_halves(ctx, d),
            self.concat_word_halves(ctx, e.dense_halves()),
            self.concat_word_halves(ctx, f.dense_halves()),
            self.concat_word_halves(ctx, g.dense_halves()),
            self.concat_word_halves(ctx, h),
        ]
    }

    fn concat_word_halves(
        &self,
        ctx: &mut Context<F>,
        word: RoundWordDense<F>,
    ) -> AssignedValue<F> {
        let (lo, hi) = word.halves();
        let u16 = ctx.load_constant(F::from(1 << 16));

        let val_u32 = value_to_option(word.value()).unwrap();
        let val_lo = F::from_u128((val_u32 % (1 << 16)) as u128);
        let val_hi = F::from_u128((val_u32 >> 16) as u128);
        let assigned_lo = ctx.load_witness(val_lo);
        let assigned_hi = ctx.load_witness(val_hi);

        // ctx.constrain_equal(&lo, &assigned_lo);
        // ctx.constrain_equal(&hi, &assigned_hi);

        self.range.gate().mul_add(ctx, assigned_hi, u16, assigned_lo)
    }

    pub fn range(&self) -> &RangeChip<F> {
        &self.range
    }
}



#[cfg(test)]
mod test {
    use std::marker::PhantomData;

    use super::*;
    use eth_types::Field;
    use halo2_base::halo2_proofs::{
        circuit::{Cell, Layouter, Region, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem, Instance},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};

    use num_bigint::RandomBits;
    use rand::rngs::OsRng;
    use rand::{thread_rng, Rng};
    use table16::Table16Chip;

    #[derive(Debug, Clone)]
    struct TestConfig<F: Field> {
        sha256: SHA256ChipConfig<F>,
        hash_column: Column<Instance>,
    }

    #[derive(Debug, Clone)]
    struct TestCircuit<F: Field> {
        test_input: Vec<u8>,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestCircuit<F> {
        type Config = TestConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let table16config = Table16Chip::<F>::configure(meta);
            let range_config = RangeConfig::configure(
                meta,
                Vertical,
                &[Self::NUM_ADVICE],
                &[Self::NUM_LOOKUP_ADVICE],
                Self::NUM_FIXED,
                Self::LOOKUP_BITS,
                0,
            );
            let hash_column = meta.instance_column();
            meta.enable_equality(hash_column);
            let sha256 = SHA256Chip::configure(
                table16config,
                Self::MAX_BYTE_SIZE,
                range_config,
            );
            Self::Config {
                sha256,
                hash_column,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let sha256 = config.sha256.clone();
            let range = sha256.range.clone();
            sha256.range.load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            
            Ok(())
        }
    }

    impl<F: Field> TestCircuit<F> {
        const NUM_HASHES: usize = 50;
        const MAX_BYTE_SIZE: usize = 10240;
        const NUM_ADVICE: usize = 150 / 5 * Self::NUM_HASHES;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 30 / 5 * Self::NUM_HASHES;
        const LOOKUP_BITS: usize = 12;
        const NUM_COMP: usize = 10;
    }

    const K: u32 = 14;

    #[test]
    fn test_sha256_correct1() {
        

        // Test vector: "abc"
        let test_input = vec!['a' as u8, 'b' as u8, 'c' as u8];

        let circuit = TestCircuit::<Fr> {
            test_input: [0; 64].to_vec(),
            _f: PhantomData,
        };

        let prover = MockProver::run(K, &circuit, vec![vec![]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

}
