//! Utility traits, functions used in the crate.
use eth_types::Field;
use halo2_base::{Context, gates::GateInstructions, AssignedValue, QuantumCell};
use itertools::Itertools;

pub fn to_bytes_le<F: Field, const MAX_BYTES: usize>(
    a: &AssignedValue<F>,
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
) -> Vec<AssignedValue<F>> {
    let byte_bases = (0..MAX_BYTES)
        .map(|i| QuantumCell::Constant(gate.pow_of_two()[i * 8]))
        .collect_vec();

    let assigned_bytes = a
        .value()
        .to_bytes_le()
        .into_iter()
        .take(MAX_BYTES)
        .map(|v| ctx.load_witness(F::from(v as u64)))
        .collect_vec();

    // Constrain poseidon bytes to be equal to the recovered checksum
    let checksum = gate.inner_product(ctx, assigned_bytes.clone(), byte_bases);
    ctx.constrain_equal(a, &checksum);

    assigned_bytes
}
