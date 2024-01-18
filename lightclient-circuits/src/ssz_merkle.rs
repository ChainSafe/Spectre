// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::collections::HashMap;

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

// Implemented following https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md#merkle-multiproofs
pub fn verify_merkle_multi_proof<F: Field, CircuitBuilder: CommonCircuitBuilder<F>>(
    builder: &mut CircuitBuilder,
    hasher: &impl HashInstructions<F, CircuitBuilder = CircuitBuilder>,
    branch: impl IntoIterator<Item = HashInputChunk<QuantumCell<F>>>,
    leaves: impl IntoIterator<Item = HashInputChunk<QuantumCell<F>>>,
    root: &[AssignedValue<F>],
    gindices: impl IntoIterator<Item = usize>,
    helper_indices: impl IntoIterator<Item = usize>,
) -> Result<(), Error> {
    let mut objects: HashMap<usize, _> = gindices
        .into_iter()
        .zip(leaves)
        .chain(helper_indices.into_iter().zip(branch))
        .collect();
    let mut keys = objects.keys().copied().collect_vec();
    keys.sort_by(|a, b| b.cmp(a));

    let mut pos = 0;
    while pos < keys.len() {
        let k = keys[pos];
        // if the sibling exists AND the parent does NOT, we hash
        if objects.contains_key(&k)
            && objects.contains_key(&(k ^ 1))
            && !objects.contains_key(&(k / 2))
        {
            let left = objects[&((k | 1) ^ 1)].clone();
            let right = objects[&(k | 1)].clone();
            let computed_hash = hasher
                .digest(builder, HashInput::TwoToOne(left, right))?
                .into();
            objects.insert(k / 2, computed_hash);
            keys.push(k / 2);
        }
        pos += 1;
    }

    let computed_root = objects
        .get(&1)
        .unwrap()
        .clone()
        .into_iter()
        .map(|b| match b {
            QuantumCell::Existing(av) => av,
            _ => unreachable!(),
        });

    computed_root.zip(root.iter()).for_each(|(a, b)| {
        builder.main().constrain_equal(&a, b);
    });

    // Ok(())
    Ok(())
}

pub const ZERO_HASHES: [[u8; 32]; 2] = [
    [0; 32],
    [
        245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35,
        32, 217, 240, 232, 234, 152, 49, 169, 39, 89, 251, 75,
    ],
];
