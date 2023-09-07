use std::{cell::RefCell, iter};

use eth_types::Field;
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, FlexGateConfigParams, GateThreadBuilder, KeygenAssignments,
        },
        flex_gate::FlexGateConfig,
    },
    utils::ScalarField,
    Context,
};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, Selector},
};
use itertools::Itertools;

use super::SpreadConfig;

pub const SPREAD_PHASE: usize = 0;

#[derive(Clone, Debug, Default)]
pub struct SpreadThreadBuilder<F: ScalarField> {
    /// Threads for spread table assignment.
    pub threads_dense: Vec<Context<F>>,
    /// Threads for spread table assignment.
    pub threads_spread: Vec<Context<F>>,
    /// [`GateThreadBuilder`] with threads for basic gate; also in charge of thread IDs
    pub gate_builder: GateThreadBuilder<F>,
}

pub type ShaContexts<'a, F> = (&'a mut Context<F>, &'a mut Context<F>, &'a mut Context<F>);

impl<F: Field> SpreadThreadBuilder<F> {
    // re-expose some methods from [`GateThreadBuilder`] for convenience
    #[allow(unused_mut)]
    pub fn new(mut witness_gen_only: bool) -> Self {
        Self {
            threads_spread: Vec::new(),
            threads_dense: Vec::new(),
            gate_builder: GateThreadBuilder::new(witness_gen_only),
        }
    }

    pub fn from_stage(stage: CircuitBuilderStage) -> Self {
        Self::new(stage == CircuitBuilderStage::Prover)
    }

    pub fn mock() -> Self {
        Self::new(false)
    }

    pub fn keygen() -> Self {
        Self::new(false).unknown(true)
    }

    pub fn prover() -> Self {
        Self::new(true)
    }

    pub fn unknown(mut self, use_unknown: bool) -> Self {
        self.gate_builder = self.gate_builder.unknown(use_unknown);
        self
    }

    pub fn main(&mut self) -> ShaContexts<F> {
        if self.threads_dense.is_empty() {
            self.new_thread_dense();
        }
        if self.threads_spread.is_empty() {
            self.new_thread_spread();
        }
        (
            self.gate_builder.main(SPREAD_PHASE),
            self.threads_dense.last_mut().unwrap(),
            self.threads_spread.last_mut().unwrap(),
        )
    }

    pub fn witness_gen_only(&self) -> bool {
        self.gate_builder.witness_gen_only()
    }

    pub fn use_unknown(&self) -> bool {
        self.gate_builder.use_unknown()
    }

    pub fn thread_count(&self) -> usize {
        self.gate_builder.thread_count()
    }

    pub fn get_new_thread_id(&mut self) -> usize {
        self.gate_builder.get_new_thread_id()
    }

    pub fn new_thread_dense(&mut self) -> &mut Context<F> {
        let thread_id = self.get_new_thread_id();
        self.threads_dense
            .push(Context::new(self.witness_gen_only(), thread_id));
        self.threads_dense.last_mut().unwrap()
    }

    pub fn new_thread_spread(&mut self) -> &mut Context<F> {
        let thread_id = self.get_new_thread_id();
        self.threads_spread
            .push(Context::new(self.witness_gen_only(), thread_id));
        self.threads_spread.last_mut().unwrap()
    }

    /// Auto-calculate configuration parameters for the circuit
    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> FlexGateConfigParams {
        self.gate_builder.config(k, minimum_rows)
    }

    /// Assigns all advice and fixed cells, turns on selectors, imposes equality constraints.
    /// This should only be called during keygen.
    pub fn assign_all(
        &mut self,
        gate: &FlexGateConfig<F>,
        lookup_advice: &[Vec<Column<Advice>>],
        q_lookup: &[Option<Selector>],
        spread: &SpreadConfig<F>,
        region: &mut Region<F>,
        KeygenAssignments {
            mut assigned_advices,
            assigned_constants,
            mut break_points,
        }: KeygenAssignments<F>,
    ) -> KeygenAssignments<F> {
        assert!(!self.witness_gen_only());

        let use_unknown = self.use_unknown();
        let max_rows = gate.max_rows;

        // first we assign all RLC contexts, basically copying gate::builder::assign_all except that the length of the RLC vertical gate is 3 instead of 4 (which was length of basic gate)
        let mut gate_index = 0;
        let mut num_limb_sum = 0;
        let mut row_offset = 0;
        for (ctx_dense, ctx_spread) in self.threads_dense.iter().zip_eq(self.threads_spread.iter())
        {
            for (i, (&advice_dense, &advice_spread)) in ctx_dense
                .advice
                .iter()
                .zip_eq(ctx_spread.advice.iter())
                .enumerate()
            {
                let column_idx = num_limb_sum % spread.num_advice_columns;
                let value_dense = if use_unknown {
                    Value::unknown()
                } else {
                    Value::known(advice_dense)
                };

                let cell_dense = region
                    .assign_advice(
                        || "dense",
                        spread.denses[column_idx],
                        row_offset,
                        || value_dense,
                    )
                    .unwrap()
                    .cell();
                assigned_advices.insert((ctx_dense.context_id, i), (cell_dense, row_offset));

                let value_spread = if use_unknown {
                    Value::unknown()
                } else {
                    Value::known(advice_spread)
                };

                let cell_spread = region
                    .assign_advice(
                        || "spread",
                        spread.spreads[column_idx],
                        row_offset,
                        || value_spread,
                    )
                    .unwrap()
                    .cell();
                assigned_advices.insert((ctx_spread.context_id, i), (cell_spread, row_offset));

                // if (q && row_offset + 3 > max_rows) || row_offset >= max_rows - 1 {
                //     break_points.rlc.push(row_offset);
                //     row_offset = 0;
                //     gate_index += 1;
                //     // when there is a break point, because we may have two gates that overlap at the current cell, we must copy the current cell to the next column for safety
                //     basic_gate = *spread
                //         .basic_gates
                //         .get(gate_index)
                //         .unwrap_or_else(|| panic!("NOT ENOUGH RLC ADVICE COLUMNS. Perhaps blinding factors were not taken into account. The max non-poisoned rows is {max_rows}"));
                //     (column, q_rlc) = basic_gate;

                //     #[cfg(feature = "halo2-axiom")]
                //     {
                //         let ncell = region.assign_advice(column, row_offset, value);
                //         region.constrain_equal(ncell.cell(), &cell);
                //     }
                //     #[cfg(not(feature = "halo2-axiom"))]
                //     {
                //         let ncell = region
                //             .assign_advice(|| "", column, row_offset, || value)
                //             .unwrap()
                //             .cell();
                //         region.constrain_equal(ncell, cell).unwrap();
                //     }
                // }

                num_limb_sum += 1;
                if column_idx == spread.num_advice_columns - 1 {
                    row_offset += 1;
                }
                row_offset += 1;
            }
        }
        // in order to constrain equalities and assign constants, we copy the Spread/Dense equality constraints into the gate builder (it doesn't matter which context the equalities are in), so `GateThreadBuilder::assign_all` can take care of it
        // the phase doesn't matter for equality constraints, so we use phase 0 since we're sure there's a main context there
        let main_ctx = self.gate_builder.main(0);
        for ctx in self
            .threads_spread
            .iter_mut()
            .chain(self.threads_dense.iter_mut())
        {
            main_ctx
                .advice_equality_constraints
                .append(&mut ctx.advice_equality_constraints);
            main_ctx
                .constant_equality_constraints
                .append(&mut ctx.constant_equality_constraints);
        }

        self.gate_builder.assign_all(
            gate,
            lookup_advice,
            q_lookup,
            region,
            KeygenAssignments {
                assigned_advices,
                assigned_constants,
                break_points,
            },
        )
    }
}
