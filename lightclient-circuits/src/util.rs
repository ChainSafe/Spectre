//! Common utility traits and functions.

mod common;
pub use common::*;

use std::{cell::RefCell, path::Path, rc::Rc};

mod constraint_builder;
pub(crate) use constraint_builder::*;

mod conversion;
pub(crate) use conversion::*;

mod proof;
use halo2curves::bn256;
pub use proof::*;

mod circuit;
pub use circuit::*;

use halo2_base::{
    halo2_proofs::{
        circuit::{Layouter, Region, Value},
        plonk::{
            Challenge, ConstraintSystem, Error, Expression, FirstPhase, ProvingKey, SecondPhase,
            VirtualCells,
        },
        poly::kzg::commitment::ParamsKZG,
    },
    utils::ScalarField,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{ProperCrtUint, ProperUint},
    fields::{fp::FpChip, FieldChip},
};

use itertools::Itertools;
use num_bigint::BigUint;

use crate::{gadget::Expr, witness};
use eth_types::*;

/// Helper trait that implements functionality to represent a generic type as
/// array of N-bits.
pub trait AsBits<const N: usize> {
    /// Return the bits of self, starting from the most significant.
    fn as_bits(&self) -> [bool; N];
}

pub(crate) fn query_expression<F: Field, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(0.expr())
    });
    expr.unwrap()
}

/// Randomness used in circuits.
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    sha256_input: T,
}

impl Challenges {
    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            sha256_input: meta.challenge_usable_after(FirstPhase),
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs<F: Field>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [sha256_input] = query_expression(meta, |meta| {
            [self.sha256_input].map(|challenge| meta.query_challenge(challenge))
        });
        Challenges { sha256_input }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            sha256_input: layouter.get_challenge(self.sha256_input),
        }
    }
}

impl<T: Clone> Challenges<T> {
    pub fn sha256_input(&self) -> T {
        self.sha256_input.clone()
    }

    pub(crate) fn mock(sha256_input: T) -> Self {
        Self { sha256_input }
    }
}

/// Packs bits into bytes
pub mod to_bytes {
    use crate::gadget::Expr;
    use eth_types::Field;
    use halo2_base::halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(bits: &[Expression<F>]) -> Vec<Expression<F>> {
        debug_assert!(bits.len() % 8 == 0, "bits not a multiple of 8");
        let mut bytes = Vec::new();
        for byte_bits in bits.chunks(8) {
            let mut value = 0.expr();
            let mut multiplier = F::ONE;
            for byte in byte_bits.iter() {
                value = value + byte.expr() * multiplier;
                multiplier *= F::from(2);
            }
            bytes.push(value);
        }
        bytes
    }

    pub(crate) fn value(bits: &[u8]) -> Vec<u8> {
        debug_assert!(bits.len() % 8 == 0, "bits not a multiple of 8");
        let mut bytes = Vec::new();
        for byte_bits in bits.chunks(8) {
            let mut value = 0u8;
            for (idx, bit) in byte_bits.iter().enumerate() {
                value += *bit << idx;
            }
            bytes.push(value);
        }
        bytes
    }
}

pub fn bigint_to_le_bytes<F: Field>(
    limbs: impl IntoIterator<Item = F>,
    limb_bits: usize,
    total_bytes: usize,
) -> Vec<u8> {
    let limb_bytes = limb_bits / 8;
    limbs
        .into_iter()
        .flat_map(|x| x.to_bytes_le()[..limb_bytes].to_vec())
        .take(total_bytes)
        .collect()
}

pub fn pad_to_ssz_chunk(le_bytes: &[u8]) -> Vec<u8> {
    assert!(le_bytes.len() <= 32);
    let mut chunk = le_bytes.to_vec();
    chunk.resize(32, 0);
    chunk
}
