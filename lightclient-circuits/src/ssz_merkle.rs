use crate::{
    gadget::crypto::HashInstructions,
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
/// Assumes that number if chunks is a power of two.
pub fn ssz_merkleize_chunks<F: Field, CircuitBuilder: CommonCircuitBuilder<F>>(
    builder: &mut CircuitBuilder,
    hasher: &impl HashInstructions<F, CircuitBuilder = CircuitBuilder>,
    chunks: impl IntoIterator<Item = HashInputChunk<QuantumCell<F>>>,
) -> Result<Vec<AssignedValue<F>>, Error> {
    let mut chunks = chunks.into_iter().collect_vec();
    assert!(chunks.len().is_power_of_two());

    let height = (chunks.len() as f64).log2() as usize;

    for _ in 0..height {
        chunks = chunks
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

    Ok(root.bytes)
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

    let computed_root = computed_hash.bytes.into_iter().map(|b| match b {
        QuantumCell::Existing(av) => av,
        _ => unreachable!(),
    });

    computed_root.zip(root.iter()).for_each(|(a, b)| {
        builder.main().constrain_equal(&a, b);
    });

    Ok(())
}
