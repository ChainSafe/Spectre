// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use crate::{
    gadget::crypto::HashInstructions,
    util::IntoConstant,
    witness::{HashInput, HashInputChunk},
};
use eth_types::Field;
use halo2_base::{
    gates::flex_gate::threads::CommonCircuitBuilder, halo2_proofs::plonk::Error, AssignedValue,
    QuantumCell,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use sha2::Digest;

// Maximum number of input leafs that are not a power of two because the zero hashes are only precomputed for the first two levels.
// In practice, the maximum number of input leafs that is not a power of two used in this project is 5.
const MAX_INPUT_LEAFS_NOT_POW2: usize = 7;

/// Computes Merkle root of a list of SSZ chunks.
///
/// Can work with numbers of chunks that are not a power of two, in which case the tree level is padded with zero hashes.
/// However, zero hashes are only precomputed for the first two levels.
pub fn ssz_merkleize_chunks<F: Field, CircuitBuilder: CommonCircuitBuilder<F>>(
    builder: &mut CircuitBuilder,
    hasher: &impl HashInstructions<F, CircuitBuilder = CircuitBuilder>,
    chunks: impl IntoIterator<Item = HashInputChunk<QuantumCell<F>>>,
) -> Result<Vec<AssignedValue<F>>, Error> {
    let mut chunks = chunks.into_iter().collect_vec();

    assert!(
        chunks.len() < MAX_INPUT_LEAFS_NOT_POW2 || chunks.len().is_power_of_two(),
        "merkleize_chunks: expected number of chunks to be a power of two or less than {}",
        MAX_INPUT_LEAFS_NOT_POW2
    );

    let height = if chunks.len() == 1 {
        1
    } else {
        chunks.len().next_power_of_two().ilog2() as usize
    };

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
            .map(|(left, right)| {
                hasher
                    .digest(builder, HashInput::TwoToOne(left, right))
                    .map(|res| res.into())
            })
            .collect::<Result<Vec<_>, _>>()?;
    }

    assert_eq!(chunks.len(), 1, "merkleize_chunks: expected one chunk");

    let root = chunks.pop().unwrap().map(|cell| match cell {
        QuantumCell::Existing(av) => av,
        _ => unreachable!(),
    });

    Ok(root.to_vec())
}

/// Verifies `leaf` against the `root` using Merkle `branch`. Requires `gindex` for deterministic traversal of the tree.
///
/// Assumes that `root` and `leaf` are 32 bytes each.
pub fn verify_merkle_proof<F: Field, CircuitBuilder: CommonCircuitBuilder<F>>(
    builder: &mut CircuitBuilder,
    hasher: &impl HashInstructions<F, CircuitBuilder = CircuitBuilder>,
    branch: impl IntoIterator<Item = HashInputChunk<QuantumCell<F>>>,
    leaf: HashInputChunk<QuantumCell<F>>,
    root: &[AssignedValue<F>],
    mut gindex: usize,
) -> Result<(), Error> {
    let mut computed_hash = leaf;

    for witness in branch.into_iter() {
        computed_hash = hasher
            .digest(
                builder,
                if gindex % 2 == 0 {
                    HashInput::TwoToOne(computed_hash, witness)
                } else {
                    HashInput::TwoToOne(witness, computed_hash)
                },
            )?
            .into();
        gindex /= 2;
    }

    let computed_root = computed_hash.into_iter().map(|b| match b {
        QuantumCell::Existing(av) => av,
        _ => unreachable!(),
    });

    computed_root.zip(root.iter()).for_each(|(a, b)| {
        builder.main().constrain_equal(&a, b);
    });

    Ok(())
}

lazy_static! {
    // Calculates padding Merkle notes for the 2 first levels of the Merkle tree.
    // Used to pad the input to a power of two. Only 2 levels are precomputed because the number of not even inputs is limited.
    static ref ZERO_HASHES: [[u8; 32]; 2] = {
        std::iter::successors(Some([0; 32]), |&prev| {
            Some(sha2::Sha256::digest([prev, prev].concat()).to_vec().try_into().unwrap())
        })
        .take(2)
        .collect_vec()
        .try_into()
        .unwrap()
    };
}
