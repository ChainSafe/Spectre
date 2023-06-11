use crate::{
    util::{query_expression, Challenges, Expr},
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;

/// Decodes a field element from its byte representation
pub(crate) mod from_bytes {
    use crate::{util::Expr, vs_circuit::MAX_N_BYTES_INTEGER};
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = 0.expr();
        let mut multiplier = F::ONE;
        for byte in bytes.iter() {
            value = value + byte.expr() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }

    pub(crate) fn value<F: Field>(bytes: &[u8]) -> F {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = F::ZERO;
        let mut multiplier = F::ONE;
        for byte in bytes.iter() {
            value += F::from(*byte as u64) * multiplier;
            multiplier *= F::from(256);
        }
        value
    }
}

/// Returns 2**by as Field
pub(crate) fn pow_of_two<F: Field>(by: usize) -> F {
    F::from(2).pow([by as u64, 0, 0, 0])
}

/// Transposes an `Value` of a [`Result`] into a [`Result`] of an `Value`.
pub(crate) fn transpose_val_ret<F, E>(value: Value<Result<F, E>>) -> Result<Value<F>, E> {
    let mut ret = Ok(Value::unknown());
    value.map(|value| {
        ret = value.map(Value::known);
    });
    ret
}
