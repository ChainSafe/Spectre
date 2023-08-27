//! Common utility traits and functions.

mod common;
use std::{cell::RefCell, rc::Rc, path::Path};

pub use common::*;

mod constraint_builder;
pub(crate) use constraint_builder::*;

mod conversion;
pub(crate) use conversion::*;

mod proof;
use halo2curves::bn256;
pub use proof::*;

use halo2_base::{
    gates::builder::{GateThreadBuilder, FlexGateConfigParams},
    safe_types::{GateInstructions, RangeChip, RangeInstructions},
    utils::ScalarField,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{ProperCrtUint, ProperUint},
    fields::{fp::FpChip, FieldChip},
};

use itertools::Itertools;
use num_bigint::BigUint;
use snark_verifier_sdk::CircuitExt;

use crate::{
    gadget::{
        crypto::{Fp2Point, FpPoint},
        Expr,
    },
    sha256_circuit::Sha256CircuitConfig,
    witness,
};
use eth_types::*;
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{
        Challenge, ConstraintSystem, Error, Expression, FirstPhase, SecondPhase, VirtualCells, ProvingKey,
    }, poly::kzg::commitment::ParamsKZG,
};

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

pub trait AppCircuitExt<F: Field>: CircuitExt<F> + Default {
    fn parametrize(k: usize) -> FlexGateConfigParams;

    fn setup(
        config: FlexGateConfigParams,
        out: Option<&Path>,
    ) -> (
        ParamsKZG<bn256::Bn256>,
        ProvingKey<bn256::G1Affine>,
        Vec<usize>,
    );
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
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(bits: &[Expression<F>]) -> Vec<Expression<F>> {
        debug_assert!(bits.len() % 8 == 0, "bits not a multiple of 8");
        let mut bytes = Vec::new();
        for byte_bits in bits.chunks(8) {
            let mut value = 0.expr();
            let mut multiplier = F::one();
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

/// Converts assigned bytes into biginterger
/// Warning: method does not perfrom any checks on input `bytes`.
pub fn decode_into_field<F: Field, C: AppCurveExt>(
    bytes: impl IntoIterator<Item = AssignedValue<F>>,
    limb_bases: &[F],
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
) -> ProperCrtUint<F> {
    let bytes = bytes.into_iter().collect_vec();
    let limb_bytes = C::LIMB_BITS / 8;
    let bits = C::NUM_LIMBS * C::LIMB_BITS;

    let value = BigUint::from_bytes_le(
        &bytes
            .iter()
            .map(|v| v.value().get_lower_32() as u8)
            .collect_vec(),
    );

    // inputs is a bool or uint8.
    let assigned_uint = if bits == 1 || limb_bytes == 8 {
        ProperUint::new(bytes)
    } else {
        let byte_base = (0..limb_bytes)
            .map(|i| QuantumCell::Constant(gate.pow_of_two()[i * 8]))
            .collect_vec();
        let limbs = bytes
            .chunks(limb_bytes)
            .map(|chunk| gate.inner_product(ctx, chunk.to_vec(), byte_base[..chunk.len()].to_vec()))
            .collect::<Vec<_>>();
        ProperUint::new(limbs)
    };

    assigned_uint.into_crt(ctx, gate, value, limb_bases, C::LIMB_BITS)
}

pub fn decode_into_field_be<F: Field, C: AppCurveExt, I: IntoIterator<Item = AssignedValue<F>>>(
    bytes: I,
    limb_bases: &[F],
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
) -> ProperCrtUint<F>
where
    I::IntoIter: DoubleEndedIterator,
{
    let bytes = bytes.into_iter().rev().collect_vec();
    decode_into_field::<F, C>(bytes, limb_bases, gate, ctx)
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

pub fn print_fq_dev<C: AppCurveExt, F: Field>(x: &FpPoint<F>, label: &str) {
    let bytes = bigint_to_le_bytes(
        x.limbs().iter().map(|e| *e.value()),
        C::LIMB_BITS,
        C::BYTES_COMPRESSED,
    );
    let bn = BigUint::from_bytes_le(&bytes);
    println!("{label}: {}", bn);
}

pub fn print_fq2_dev<C: AppCurveExt, F: Field>(u: &Fp2Point<F>, label: &str) {
    let c0_bytes = bigint_to_le_bytes(
        u.0[0].limbs().iter().map(|e| *e.value()),
        C::LIMB_BITS,
        C::BYTES_COMPRESSED / 2,
    );
    let c1_bytes = bigint_to_le_bytes(
        u.0[1].limbs().iter().map(|e| *e.value()),
        C::LIMB_BITS,
        C::BYTES_COMPRESSED / 2,
    );
    let c0 = BigUint::from_bytes_le(&c0_bytes);
    let c1 = BigUint::from_bytes_le(&c1_bytes);
    println!("{label}: ({}, {})", c0, c1);
}

pub fn pad_to_ssz_chunk(le_bytes: &[u8]) -> Vec<u8> {
    assert!(le_bytes.len() <= 32);
    let mut chunk = le_bytes.to_vec();
    chunk.resize(32, 0);
    chunk
}
