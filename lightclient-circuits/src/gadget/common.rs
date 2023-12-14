//! Utility traits, functions used in the crate.
use eth_types::Field;
use halo2_base::{gates::GateInstructions, AssignedValue, Context, QuantumCell};
use itertools::Itertools;

/// Constraints number `a` to have a little-endian byte representation that is returned.
/// Uses a verification trick where instead of decomposing `a` into bytes in circuit,
/// we upload LE bytes and composing them back into `checksum` via inner product.
/// This relies on the fact tha inner product is significantly more efficient than decomposing into bytes that involves a lot of scalar division.
pub fn to_bytes_le<F: Field, const MAX_BYTES: usize>(
    a: &AssignedValue<F>,
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
) -> Vec<AssignedValue<F>> {
    let byte_bases = (0..MAX_BYTES)
        .map(|i| QuantumCell::Constant(gate.pow_of_two()[i * 8]))
        .collect_vec();

    // Compute LE bytes off-circuit.
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
