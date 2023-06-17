// mod sha256_compression;
// mod util;
mod table16;
mod sha256;

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
    AssignedValue, Context, utils::ScalarField
};
use itertools::Itertools;

use self::sha256::Table16Config;

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
    range: RangeChip<F>,
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

    pub fn digest<'a>(
        &'a self,
        ctx: &mut Context<F>,
        input: &'a [u8],
        assinged_inputs: Vec<AssignedValue<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let input_byte_size = input.len();
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


        let assigned_input_bytes = {
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

        for assigned_byte in assigned_input_bytes.iter().copied() {
            self.range.range_check(ctx, assigned_byte, 8);
        }



        Ok(vec![])
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
