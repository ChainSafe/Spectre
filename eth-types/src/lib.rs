#![allow(incomplete_features)]
#![feature(associated_type_bounds)]
#![feature(associated_type_defaults)]
#![feature(generic_const_exprs)]
mod spec;
pub use spec::{Mainnet, Spec, Test, Minimal};

mod curve;
pub use curve::{AppCurveExt, HashCurveExt};

use core::hash::Hash;
use halo2_proofs::{
    arithmetic::{Field as Halo2Field, FieldExt},
    halo2curves::{
        bn256::{Fq, Fr},
        group::ff::PrimeField,
    },
};

/// Trait used to reduce verbosity with the declaration of the [`PrimeField`]
/// trait and its repr.
pub trait Field:
    FieldExt + Halo2Field + PrimeField<Repr = [u8; 32]> + Hash + Ord + halo2_ecc::fields::PrimeField
{
    fn pow_const(&self, mut exp: usize) -> Self {
        if exp == 0 {
            return Self::one();
        }

        let mut base = *self;

        while exp & 1 == 0 {
            base = base.square();
            exp >>= 1;
        }

        let mut acc = base;
        while exp > 1 {
            exp >>= 1;
            base = base.square();
            if exp & 1 == 1 {
                acc *= &base;
            }
        }
        acc
    }

    /// Composes a field element from a little endian byte representation.
    /// WARNING: CAN OVERFLOW.
    fn from_bytes_le_unsecure<'a, I: IntoIterator<Item = &'a u8>>(bytes: I) -> Self {
        let two = Self::from(2);
        let mut value = Self::zero();
        for (i, byte) in bytes.into_iter().enumerate() {
            value += Self::from(*byte as u64) * two.pow_const(8 * i);
        }
        value
    }
}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

// Impl custom `Field` trait for BN256 Frq to be used and consistent with the
// rest of the workspace.
impl Field for Fq {}
