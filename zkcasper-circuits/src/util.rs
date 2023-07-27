//! Common utility traits and functions.

mod cell_manager;
pub use cell_manager::*;

mod constraint_builder;
pub use constraint_builder::*;

mod conversion;
pub use conversion::*;
use halo2_base::{
    safe_types::{GateInstructions, RangeInstructions},
    utils::ScalarField,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{ProperCrtUint, ProperUint},
    fields::{fp::FpChip, FieldChip},
};

use itertools::Itertools;
use num_bigint::BigUint;

use crate::{
    gadget::crypto::{Fp2Point, FpPoint},
    sha256_circuit::Sha256CircuitConfig,
    witness,
};
use eth_types::*;
pub use gadgets::util::{and, not, or, rlc, select, sum, xor, Expr};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Challenge, ConstraintSystem, Error, Expression, SecondPhase, VirtualCells},
};

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

pub(crate) fn random_linear_combine_bytes<F: Field>(bytes: [u8; 32], randomness: F) -> F {
    rlc::value(&bytes, randomness)
}

/// Randomness used in circuits.
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<F: Field, T = Challenge> {
    sha256_input: Value<F>,
    lookup_input: T,
}

impl<F: Field> Challenges<F> {
    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            sha256_input: Value::known(Sha256CircuitConfig::fixed_challenge()),
            lookup_input: meta.challenge_usable_after(SecondPhase),
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs(&self, meta: &mut ConstraintSystem<F>) -> Challenges<F, Expression<F>> {
        let [lookup_input] = query_expression(meta, |meta| {
            [self.lookup_input].map(|challenge| meta.query_challenge(challenge))
        });
        Challenges {
            sha256_input: Value::known(Sha256CircuitConfig::fixed_challenge()),
            lookup_input,
        }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values(&self, layouter: &mut impl Layouter<F>) -> Challenges<F, Value<F>> {
        Challenges {
            sha256_input: Value::known(Sha256CircuitConfig::fixed_challenge()),
            lookup_input: layouter.get_challenge(self.lookup_input),
        }
    }
}

impl<F: Field, T: Clone> Challenges<F, T> {
    /// Returns challenge of `lookup_input`.
    pub fn lookup_input(&self) -> T {
        self.lookup_input.clone()
    }

    pub fn sha256_input(&self) -> Value<F> {
        self.sha256_input
    }
}

/// SubCircuit is a circuit that performs the verification of a specific part of
/// the full Casper finality verification. The SubCircuit's interact with each
/// other via lookup tables and/or shared public inputs.  This type must contain
/// all the inputs required to synthesize this circuit (and the contained
/// table(s) if any).
pub trait SubCircuit<F: Field> {
    /// Configuration of the SubCircuit.
    type Config: SubCircuitConfig<F>;

    /// Arguments for [`synthesize_sub`].
    type SynthesisArgs;

    /// Returns number of unusable rows of the SubCircuit, which should be
    /// `meta.blinding_factors() + 1`.
    fn unusable_rows() -> usize;

    /// Create a new SubCircuit from a witness Block
    fn new_from_block(block: &witness::Block<F>) -> Self;

    /// Returns the instance columns required for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
    /// Assign only the columns used by this sub-circuit.  This includes the
    /// columns that belong to the exposed lookup table contained within, if
    /// any; and excludes external tables that this sub-circuit does lookups
    /// to.
    fn synthesize_sub(
        &self,
        config: &mut Self::Config,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
        args: Self::SynthesisArgs,
    ) -> Result<(), Error>;

    /// Return the minimum number of rows required to prove the block.
    /// Row numbers without/with padding are both returned.
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize);
}

/// SubCircuit configuration
pub trait SubCircuitConfig<F: Field> {
    /// Config constructor arguments
    type ConfigArgs;

    /// Type constructor
    fn new<S: Spec>(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self;

    /// Annotates columns of a circuit embedded within a circuit region.
    fn annotate_columns_in_region(&self, region: &mut Region<F>);
}

/// Packs bits into bytes
pub mod to_bytes {
    use eth_types::Field;
    use gadgets::util::Expr;
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

/// Decodes a field element from its byte representation
pub(crate) mod from_bytes {
    use crate::{util::Expr, MAX_N_BYTES_INTEGER};
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = 0.expr();
        let mut multiplier = F::one();
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
        let mut value = F::zero();
        let mut multiplier = F::one();
        for byte in bytes.iter() {
            value += F::from(*byte as u64) * multiplier;
            multiplier *= F::from(256);
        }
        value
    }
}

/// Returns 2**by as Field
pub(crate) fn pow_of_two<F: Field>(by: usize) -> F {
    F::from(2).pow(&[by as u64, 0, 0, 0])
}

/// Transposes an `Value` of a [`Result`] into a [`Result`] of an `Value`.
pub(crate) fn transpose_val_ret<F, E>(value: Value<Result<F, E>>) -> Result<Value<F>, E> {
    let mut ret = Ok(Value::unknown());
    value.map(|value| {
        ret = value.map(Value::known);
    });
    ret
}

/// Ceiling of log_2(n)
pub fn log2_ceil(n: usize) -> u32 {
    u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32
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
        C::BYTES_FQ,
    );
    let bn = BigUint::from_bytes_le(&bytes);
    println!("{label}: {}", bn);
}

pub fn print_fq2_dev<C: AppCurveExt, F: Field>(u: &Fp2Point<F>, label: &str) {
    let c0_bytes = bigint_to_le_bytes(
        u.0[0].limbs().iter().map(|e| *e.value()),
        C::LIMB_BITS,
        C::BYTES_FQ / 2,
    );
    let c1_bytes = bigint_to_le_bytes(
        u.0[1].limbs().iter().map(|e| *e.value()),
        C::LIMB_BITS,
        C::BYTES_FQ / 2,
    );
    let c0 = BigUint::from_bytes_le(&c0_bytes);
    let c1 = BigUint::from_bytes_le(&c1_bytes);
    println!("{label}: ({}, {})", c0, c1);
}
