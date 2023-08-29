use eth_types::Field;
use halo2_base::{AssignedValue, Context, QuantumCell};
use halo2_proofs::{circuit::Region, plonk::Error};
use itertools::Itertools;

use crate::{
    gadget::crypto::HashChip,
    util::{IntoConstant, IntoWitness},
    witness::{HashInput, HashInputChunk},
};

pub const ZERO_HASHES: [[u8; 32]; 2] = [
    [0; 32],
    [
        245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35,
        32, 217, 240, 232, 234, 152, 49, 169, 39, 89, 251, 75,
    ],
];

pub fn ssz_merkleize_chunks<'a, F: Field, I: IntoIterator<Item = HashInputChunk<QuantumCell<F>>>>(
    ctx: &mut Context<F>,
    region: &mut Region<'_, F>,
    hasher: &'a impl HashChip<F>,
    chunks: I,
) -> Result<Vec<AssignedValue<F>>, Error>
where
    I::IntoIter: ExactSizeIterator,
{
    let mut chunks = chunks.into_iter().collect_vec();
    let len_even = chunks.len() + chunks.len() % 2;
    let height = (len_even as f64).log2().ceil() as usize;

    for depth in 0..height {
        // Pad to even length using 32 zero bytes assigned as constants.
        let len_even = chunks.len() + chunks.len() % 2;
        let padded_chunks = chunks
            .into_iter()
            .pad_using(len_even, |_| ZERO_HASHES[depth].as_slice().into_constant())
            .collect_vec();

        chunks = padded_chunks
            .into_iter()
            .tuples()
            .take(3)
            .map(|(left, right)| {
                hasher
                    .digest::<128>(HashInput::TwoToOne(left, right), ctx, region)
                    .map(|res| res.output_bytes.into())
            })
            .collect::<Result<Vec<_>, _>>()?;
    }

    assert_eq!(chunks.len(), 1, "merkleize_chunks: expected one chunk");

    let root = chunks.pop().unwrap().map(|cell| match cell {
        QuantumCell::Existing(av) => av,
        _ => unreachable!(),
    });

    Ok(root.bytes)
}
