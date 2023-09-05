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

pub fn ssz_merkleize_chunks<F: Field>(
    ctx: &mut Context<F>,
    region: &mut Region<'_, F>,
    hasher: &impl HashChip<F>,
    chunks: impl IntoIterator<Item = HashInputChunk<QuantumCell<F>>>,
) -> Result<Vec<AssignedValue<F>>, Error> {
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

pub fn verify_merkle_proof<F: Field>(
    ctx: &mut Context<F>,
    region: &mut Region<'_, F>,
    hasher: &impl HashChip<F>,
    proof: impl IntoIterator<Item = HashInputChunk<QuantumCell<F>>>,
    leaf: HashInputChunk<QuantumCell<F>>,
    root: &[AssignedValue<F>],
    mut gindex: usize,
) -> Result<(), Error> {
    let mut computed_hash = leaf;

    for witness in proof.into_iter() {
        computed_hash = hasher
            .digest::<128>(
                if gindex % 2 == 0 {
                    HashInput::TwoToOne(computed_hash, witness)
                } else {
                    HashInput::TwoToOne(witness, computed_hash)
                },
                ctx,
                region,
            )?
            .output_bytes
            .into();
        gindex /= 2;
    }

    let computed_root = computed_hash.bytes.into_iter().map(|b| match b {
        QuantumCell::Existing(av) => av,
        _ => unreachable!(),
    });

    computed_root.zip(root.iter()).for_each(|(a, b)| {
        ctx.constrain_equal(&a, b);
    });

    Ok(())
}
