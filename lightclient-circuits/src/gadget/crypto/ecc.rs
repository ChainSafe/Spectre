use eth_types::{AppCurveExt, Field};
use halo2_base::Context;
use halo2_ecc::{bigint::ProperCrtUint, bls12_381::FpChip, fields::FieldChip};

// Calculates y^2 = x^3 + 4 (the curve equation)
pub fn calculate_ysquared<F: Field, C: AppCurveExt>(
    ctx: &mut Context<F>,
    field_chip: &FpChip<'_, F>,
    x: ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let x_squared = field_chip.mul(ctx, x.clone(), x.clone());
    let x_cubed = field_chip.mul(ctx, x_squared, x);

    let plus_b = field_chip.add_constant_no_carry(ctx, x_cubed, C::B.into());
    field_chip.carry_mod(ctx, plus_b)
}
