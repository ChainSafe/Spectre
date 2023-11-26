//! Utility traits, functions used in the crate.
use eth_types::Field;
use halo2_base::{halo2_proofs::plonk::Expression, Context, gates::GateInstructions, AssignedValue, QuantumCell};
use itertools::Itertools;

/// Returns the sum of the passed in cells
pub mod sum {
    use super::{Expr, Expression, Field};

    /// Returns an expression for the sum of the list of expressions.
    pub fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs
            .into_iter()
            .fold(0.expr(), |acc, input| acc + input.expr())
    }

    /// Returns the sum of the given list of values within the field.
    pub fn value<F: Field>(values: &[u8]) -> F {
        values
            .iter()
            .fold(F::ZERO, |acc, value| acc + F::from(*value as u64))
    }
}

/// Returns `1` when `expr[0] && expr[1] && ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod and {
    use super::{Expr, Expression, Field};

    /// Returns an expression that evaluates to 1 only if all the expressions in
    /// the given list are 1, else returns 0.
    pub fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs
            .into_iter()
            .fold(1.expr(), |acc, input| acc * input.expr())
    }

    /// Returns the product of all given values.
    pub fn value<F: Field>(inputs: Vec<F>) -> F {
        inputs.iter().fold(F::ONE, |acc, input| acc * input)
    }
}

/// Returns `1` when `expr[0] || expr[1] || ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod or {
    use super::{and, not};
    use super::{Expr, Expression, Field};

    /// Returns an expression that evaluates to 1 if any expression in the given
    /// list is 1. Returns 0 if all the expressions were 0.
    pub fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        not::expr(and::expr(inputs.into_iter().map(not::expr)))
    }

    /// Returns the value after passing all given values through the OR gate.
    pub fn value<F: Field>(inputs: Vec<F>) -> F {
        not::value(and::value(inputs.into_iter().map(not::value).collect()))
    }
}

/// Returns `1` when `b == 0`, and returns `0` otherwise.
/// `b` needs to be boolean
pub mod not {
    use super::{Expr, Expression, Field};

    /// Returns an expression that represents the NOT of the given expression.
    pub fn expr<F: Field, E: Expr<F>>(b: E) -> Expression<F> {
        1.expr() - b.expr()
    }

    /// Returns a value that represents the NOT of the given value.
    pub fn value<F: Field>(b: F) -> F {
        F::ONE - b
    }
}

/// Returns `a ^ b`.
/// `a` and `b` needs to be boolean
pub mod xor {
    use super::{Expr, Expression, Field};

    /// Returns an expression that represents the XOR of the given expression.
    pub fn expr<F: Field, E: Expr<F>>(a: E, b: E) -> Expression<F> {
        a.expr() + b.expr() - 2.expr() * a.expr() * b.expr()
    }

    /// Returns a value that represents the XOR of the given value.
    pub fn value<F: Field>(a: F, b: F) -> F {
        a + b - F::from(2u64) * a * b
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when
/// `selector == 0`. `selector` needs to be boolean.
pub mod select {
    use super::{Expr, Expression, Field};

    /// Returns the `when_true` expression when the selector is true, else
    /// returns the `when_false` expression.
    pub fn expr<F: Field>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1.expr() - selector) * when_false
    }

    /// Returns the `when_true` value when the selector is true, else returns
    /// the `when_false` value.
    pub fn value<F: Field>(selector: F, when_true: F, when_false: F) -> F {
        selector * when_true + (F::ONE - selector) * when_false
    }

    /// Returns the `when_true` word when selector is true, else returns the
    /// `when_false` word.
    pub fn value_word<F: Field>(
        selector: F,
        when_true: [u8; 32],
        when_false: [u8; 32],
    ) -> [u8; 32] {
        if selector == F::ONE {
            when_true
        } else {
            when_false
        }
    }
}

/// Trait that implements functionality to get a constant expression from
/// commonly used types.
pub trait Expr<F: Field> {
    /// Returns an expression for the type.
    fn expr(&self) -> Expression<F>;
}

/// Implementation trait `Expr` for type able to be casted to u64
#[macro_export]
macro_rules! impl_expr {
    ($type:ty) => {
        impl<F: eth_types::Field> Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from(*self as u64))
            }
        }
    };
    ($type:ty, $method:path) => {
        impl<F: eth_types::Field> $super::Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from($method(self) as u64))
            }
        }
    };
}

impl_expr!(bool);
impl_expr!(u8);
impl_expr!(u64);
impl_expr!(usize);

impl<F: Field> Expr<F> for Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        self.clone()
    }
}

impl<F: Field> Expr<F> for &Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        (*self).clone()
    }
}

impl<F: Field> Expr<F> for i32 {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(
            F::from(self.unsigned_abs() as u64) * if self.is_negative() { -F::ONE } else { F::ONE },
        )
    }
}

/// Given a bytes-representation of an expression, it computes and returns the
/// single expression.
pub fn expr_from_bytes<F: Field, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
    let mut value = 0.expr();
    let mut multiplier = F::ONE;
    for byte in bytes.iter() {
        value = value + byte.expr() * multiplier;
        multiplier *= F::from(256);
    }
    value
}

/// Returns the random linear combination of the inputs.
/// Encoding is done as follows: v_0 * R^0 + v_1 * R^1 + ...
pub mod rlc {
    use std::ops::{Add, Mul};

    use super::{Expr, Expression, Field};
    use halo2_base::{gates::GateInstructions, AssignedValue, Context, QuantumCell};

    /// Returns an expression that represents the random linear combination.
    pub fn expr<F: Field, E: Expr<F>>(expressions: &[E], randomness: E) -> Expression<F> {
        if !expressions.is_empty() {
            generic(expressions.iter().map(|e| e.expr()), randomness.expr())
        } else {
            0.expr()
        }
    }

    /// Returns the random linear combination of the inputs.
    pub fn value<'a, F: Field, I>(values: I, randomness: F) -> F
    where
        I: IntoIterator<Item = &'a u8>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
    {
        let values = values
            .into_iter()
            .map(|v| F::from(*v as u64))
            .collect::<Vec<F>>();
        if !values.is_empty() {
            generic(values, randomness)
        } else {
            F::ZERO
        }
    }

    /// Returns the random linear combination of the halo2-lib assigned values.
    pub fn assigned_value<F: Field>(
        values: &[AssignedValue<F>],
        randomness: &QuantumCell<F>,
        gate: &impl GateInstructions<F>,
        ctx: &mut Context<F>,
    ) -> AssignedValue<F> {
        if !values.is_empty() {
            let mut values = values.iter();
            let init = values.next().expect("values should not be empty");

            values.fold(*init, |acc, value| {
                gate.mul_add(ctx, acc, *randomness, *value)
            })
        } else {
            ctx.load_zero()
        }
    }

    fn generic<V, I, R>(values: I, randomness: R) -> V
    where
        I: IntoIterator<Item = V>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
        V: Clone + Add<R, Output = V> + Add<Output = V> + Mul<R, Output = V>,
        R: Clone,
    {
        // we don't reverse bytes because https://github.com/ChainSafe/Banshee/issues/72
        let mut values = values.into_iter();
        let init = values.next().expect("values should not be empty");

        values.fold(init, |acc, value| acc * randomness.clone() + value)
    }
}

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
    ctx.constrain_equal(&a, &checksum);

    assigned_bytes
}
