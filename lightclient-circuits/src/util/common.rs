use crate::gadget::Expr;
use eth_types::*;
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, FlexGateConfigParams, KeygenAssignments,
            MultiPhaseThreadBreakPoints,
        },
        flex_gate::FlexGateConfig,
    },
    Context,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{
        Advice, Assigned, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells,
    },
    poly::Rotation,
};

use std::hash::Hash;

#[derive(Clone, Debug)]
pub struct Cell<F> {
    // expression for constraint
    expression: Expression<F>,
    column: Column<Advice>,
    // relative position to selector for synthesis
    rotation: usize,
    cell_column_index: usize,
}

impl<F: Field> Cell<F> {
    pub(crate) fn new(
        meta: &mut VirtualCells<F>,
        column: Column<Advice>,
        rotation: usize,
        cell_column_index: usize,
    ) -> Self {
        Self {
            expression: meta.query_advice(column, Rotation(rotation as i32)),
            column,
            rotation,
            cell_column_index,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(
            || {
                format!(
                    "Cell column: {:?} and rotation: {}",
                    self.column, self.rotation
                )
            },
            self.column,
            offset + self.rotation,
            || value,
        )
    }
}

impl<F: Field> Expr<F> for Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

impl<F: Field> Expr<F> for &Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CellType {
    StoragePhase1,
    StoragePhase2,
    StoragePermutation,
    LookupByte,
    // Lookup(Table),
}

impl CellType {
    // The phase that given `Expression` becomes evaluateable.
    fn expr_phase<F: Field>(expr: &Expression<F>) -> u8 {
        use Expression::*;
        match expr {
            Challenge(challenge) => challenge.phase() + 1,
            Advice(query) => query.phase(),
            Constant(_) | Selector(_) | Fixed(_) | Instance(_) => 0,
            Negated(a) | Expression::Scaled(a, _) => Self::expr_phase(a),
            Sum(a, b) | Product(a, b) => std::cmp::max(Self::expr_phase(a), Self::expr_phase(b)),
        }
    }

    /// Return the storage phase of phase
    pub(crate) fn storage_for_phase(phase: u8) -> CellType {
        match phase {
            0 => CellType::StoragePhase1,
            1 => CellType::StoragePhase2,
            _ => unreachable!(),
        }
    }

    /// Return the storage cell of the expression
    pub(crate) fn storage_for_expr<F: Field>(expr: &Expression<F>) -> CellType {
        Self::storage_for_phase(Self::expr_phase::<F>(expr))
    }

    /// Return the storage cell of the advice column
    pub(crate) fn storage_for_column(col: &Column<Advice>) -> CellType {
        Self::storage_for_phase(col.column_type().phase())
    }
}

#[derive(Clone, Debug)]
pub struct AssignedValueCell<F: Field> {
    pub cell: halo2_proofs::circuit::Cell,
    pub value: F,
}

impl<F: Field> AssignedValueCell<F> {
    pub fn cell(&self) -> halo2_proofs::circuit::Cell {
        self.cell
    }

    pub fn value(&self) -> F {
        self.value
    }
}

pub trait ThreadBuilderConfigBase<F: Field>: Clone + Sized {
    fn configure(meta: &mut ConstraintSystem<F>, params: FlexGateConfigParams) -> Self;

    fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;

    fn annotate_columns_in_region(&self, region: &mut Region<F>);
}

pub trait ThreadBuilderBase<F: Field>: Clone + Sized {
    type Config: ThreadBuilderConfigBase<F>;

    fn new(witness_gen_only: bool) -> Self;

    fn from_stage(stage: CircuitBuilderStage) -> Self;

    fn mock() -> Self {
        Self::new(false)
    }

    fn keygen() -> Self {
        Self::new(false).unknown(true)
    }

    fn prover() -> Self {
        println!("prver ThreadBuilderBase");
        Self::new(true)
    }

    fn unknown(self, use_unknown: bool) -> Self;

    fn config(&self, k: usize, minimum_rows: Option<usize>) -> FlexGateConfigParams;

    /// Returns a mutable reference to the [Context] of a gate thread. Spawns a new thread for the given phase, if none exists.
    /// * `phase`: The challenge phase (as an index) of the gate thread.
    fn main(&mut self) -> &mut Context<F>;

    fn witness_gen_only(&self) -> bool;

    /// Returns the `use_unknown` flag.
    fn use_unknown(&self) -> bool;

    /// Returns the current number of threads in the [GateThreadBuilder].
    fn thread_count(&self) -> usize;

    /// Creates a new thread id by incrementing the `thread count`
    fn get_new_thread_id(&mut self) -> usize;

    /// Assigns all advice and fixed cells, turns on selectors, imposes equality constraints.
    /// This should only be called during keygen.
    fn assign_all(
        &mut self,
        gate: &FlexGateConfig<F>,
        lookup_advice: &[Vec<Column<Advice>>],
        q_lookup: &[Option<Selector>],
        config: &Self::Config,
        region: &mut Region<F>,
        assignments: KeygenAssignments<F>,
    ) -> Result<KeygenAssignments<F>, Error>;

    /// Assigns witnesses. This should only be called during proof generation.
    fn assign_witnesses(
        &mut self,
        gate: &FlexGateConfig<F>,
        lookup_advice: &[Vec<Column<Advice>>],
        config: &Self::Config,
        region: &mut Region<F>,
        break_points: &mut MultiPhaseThreadBreakPoints,
    ) -> Result<(), Error>;
}
