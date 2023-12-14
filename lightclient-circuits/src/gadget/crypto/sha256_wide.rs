mod gate;

use eth_types::Field;
use halo2_base::gates::RangeChip;
use halo2_base::{gates::flex_gate::threads::CommonCircuitBuilder, Context};
use itertools::Itertools;
use zkevm_hashes::sha256::vanilla::param::NUM_WORDS_TO_ABSORB;
use zkevm_hashes::sha256::vanilla::util::get_num_sha2_blocks;
use zkevm_hashes::{sha256::vanilla::witness::generate_witnesses_sha256, util::word::Word};

use crate::witness::HashInput;
use halo2_base::{gates::GateInstructions, halo2_proofs::plonk::Error, AssignedValue, QuantumCell};

pub use self::gate::ShaBitGateManager;
use super::{HashInstructions, ShaCircuitBuilder};
use crate::gadget::common::to_bytes_le;

/// [`Sha256ChipWide`] provides functions to compute SHA256 hash [`Sha256CircuitConfig`] gates.
/// This is version of SHA256 chip is wider than is possible with [`Sha256Chip`] but it takes significantly less rows.
#[derive(Debug)]
pub struct Sha256ChipWide<'a, F: Field> {
    range: &'a RangeChip<F>,
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
        let range = self.range;
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
                let checksum = gate.inner_product(
                    builder.main(),
                    assigned_bytes[i..i + 4].to_vec(),
                    byte_bases.clone(),
                );
                builder
                    .main()
                    .constrain_equal(&checksum, &blocks[r].word_values[w]);
            }
        }

        let mut hash_bytes = word_to_bytes_le(blocks[num_rounds - 1].hash, gate, builder.main());
        hash_bytes.reverse();

        Ok(hash_bytes)
    }

    fn digest_varlen(
        &self,
        _ctx: &mut Self::CircuitBuilder,
        _input: impl IntoIterator<Item = QuantumCell<F>>,
        _max_input_len: usize,
    ) -> Result<Self::Output, Error> {
        unimplemented!()
    }
}

impl<'a, F: Field> Sha256ChipWide<'a, F> {
    pub fn new(range: &'a RangeChip<F>) -> Self {
        Self { range }
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
