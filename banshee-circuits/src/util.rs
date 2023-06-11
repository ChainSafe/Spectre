//! Common utility traits and functions.
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{
        Challenge, Circuit, ConstraintSystem, Error, Expression, FirstPhase, SecondPhase,
        VirtualCells,
    },
};
use crate::{witness};
use eth_types::*;
pub use gadgets::util::{Expr, rlc};

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

/// TODO
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    lookup_input: T,
}

impl Challenges {
    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            lookup_input: meta.challenge_usable_after(SecondPhase),
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs<F: Field>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [lookup_input] = query_expression(meta, |meta| {
            [self.lookup_input]
                .map(|challenge| meta.query_challenge(challenge))
        });
        Challenges {
            lookup_input,
        }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            lookup_input: layouter.get_challenge(self.lookup_input),
        }
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
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
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
    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self;
}

/// Ceiling of log_2(n)
pub fn log2_ceil(n: usize) -> u32 {
    u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32
}
