use halo2_base::{
    gates::GateInstructions, safe_types::SafeByte, utils::BigPrimeField, AssignedValue, Context,
    QuantumCell,
};
use itertools::Itertools;

pub fn bytes_be_to_u128<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &[SafeByte<F>],
) -> Vec<AssignedValue<F>> {
    limbs_be_to_u128(ctx, gate, bytes, 8)
}

pub(crate) fn limbs_be_to_u128<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    limbs: &[impl AsRef<AssignedValue<F>>],
    limb_bits: usize,
) -> Vec<AssignedValue<F>> {
    assert!(!limbs.is_empty(), "limbs must not be empty");
    assert_eq!(128 % limb_bits, 0);
    limbs
        .chunks(128 / limb_bits)
        .map(|chunk| {
            gate.inner_product(
                ctx,
                chunk.iter().rev().map(|a| *a.as_ref()),
                (0..chunk.len())
                    .map(|idx| QuantumCell::Constant(gate.pow_of_two()[limb_bits * idx])),
            )
        })
        .collect_vec()
}
