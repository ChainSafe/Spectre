use std::{cell::RefCell, collections::HashMap, iter, mem};

use eth_types::Field;
use halo2_base::{
    gates::{
        builder::{
            assign_threads_in, CircuitBuilderStage, FlexGateConfigParams, GateThreadBuilder,
            KeygenAssignments, MultiPhaseThreadBreakPoints, ThreadBreakPoints,
        },
        flex_gate::FlexGateConfig,
        range,
    },
    utils::ScalarField,
    Context,
};
use halo2_proofs::{
    circuit::{self, Region, Value},
    plonk::{Advice, Column, Selector, Error},
};
use itertools::Itertools;

use crate::util::ThreadBuilderBase;

use super::SpreadConfig;

pub const FIRST_PHASE: usize = 0;

#[derive(Clone, Debug, Default)]
pub struct ShaThreadBuilder<F: ScalarField> {
    /// Threads for spread table assignment.
    pub threads_dense: Vec<Context<F>>,
    /// Threads for spread table assignment.
    pub threads_spread: Vec<Context<F>>,
    /// [`GateThreadBuilder`] with threads for basic gate; also in charge of thread IDs
    pub gate_builder: GateThreadBuilder<F>,
}

pub type ShaContexts<'a, F> = (&'a mut Context<F>, &'a mut Context<F>);

impl<F: Field> ThreadBuilderBase<F> for ShaThreadBuilder<F> {
    type Config = SpreadConfig<F>;

    fn new(mut witness_gen_only: bool) -> Self {
        Self {
            threads_spread: Vec::new(),
            threads_dense: Vec::new(),
            gate_builder: GateThreadBuilder::new(witness_gen_only),
        }
    }

    fn unknown(mut self, use_unknown: bool) -> Self {
        self.gate_builder = self.gate_builder.unknown(use_unknown);
        self
    }

    fn main(&mut self) -> &mut Context<F> {
        self.gate_builder.main(FIRST_PHASE)
    }

    fn witness_gen_only(&self) -> bool {
        self.gate_builder.witness_gen_only()
    }

    fn use_unknown(&self) -> bool {
        self.gate_builder.use_unknown()
    }

    fn thread_count(&self) -> usize {
        self.gate_builder.thread_count()
    }

    fn get_new_thread_id(&mut self) -> usize {
        self.gate_builder.get_new_thread_id()
    }

    fn config(&self, k: usize, minimum_rows: Option<usize>) -> FlexGateConfigParams {
        self.gate_builder.config(k, minimum_rows)
    }

    fn assign_all(
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
    ) -> Result<KeygenAssignments<F>, Error> {
        assert!(!self.witness_gen_only());

        assign_threads_sha(
            &self.threads_dense,
            &self.threads_spread,
            spread,
            region,
            self.use_unknown(),
            Some(&mut assigned_advices),
        );
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

        Ok(self.gate_builder.assign_all(
            gate,
            lookup_advice,
            q_lookup,
            region,
            KeygenAssignments {
                assigned_advices,
                assigned_constants,
                break_points,
            },
        ))
    }

    fn assign_witnesses(
        &mut self,
        gate: &FlexGateConfig<F>,
        lookup_advice: &[Vec<Column<Advice>>],
        spread: &SpreadConfig<F>,
        region: &mut Region<F>,
        break_points: &mut MultiPhaseThreadBreakPoints,
    ) -> Result<(), Error> {
        
        let break_points_gate = mem::take(&mut break_points[FIRST_PHASE]);
        // warning: we currently take all contexts from phase 0, which means you can't read the values
        // from these contexts later in phase 1. If we want to read, should clone here
        let threads = mem::take(&mut self.gate_builder.threads[FIRST_PHASE]);

        assign_threads_in(
            FIRST_PHASE,
            threads,
            gate,
            &lookup_advice[FIRST_PHASE],
            region,
            break_points_gate,
        );

        let threads_dense = mem::take(&mut self.threads_dense);
        let threads_spread = mem::take(&mut self.threads_spread);

        assign_threads_sha(&threads_dense, &threads_spread, spread, region, false, None);

        Ok(())
    }
}


impl<F: Field> ShaThreadBuilder<F> {
    pub fn sha_contexts_pair(&mut self) -> (&mut Context<F>, ShaContexts<F>) {
        if self.threads_dense.is_empty() {
            self.new_thread_dense();
        }
        if self.threads_spread.is_empty() {
            self.new_thread_spread();
        }
        (
            self.gate_builder.main(FIRST_PHASE),
            (
                self.threads_dense.last_mut().unwrap(),
                self.threads_spread.last_mut().unwrap(),
            ),
        )
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
}

/// Pure advice witness assignment in a single phase. Uses preprocessed `break_points` to determine when
/// to split a thread into a new column.
#[allow(clippy::type_complexity)]
pub fn assign_threads_sha<F: Field>(
    threads_dense: &[Context<F>],
    threads_spread: &[Context<F>],
    spread: &SpreadConfig<F>,
    region: &mut Region<F>,
    use_unknown: bool,
    mut assigned_advices: Option<&mut HashMap<(usize, usize), (circuit::Cell, usize)>>,
) {
    let mut num_limb_sum = 0;
    let mut row_offset = 0;
    for (ctx_dense, ctx_spread) in threads_dense.iter().zip_eq(threads_spread.iter()) {
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

            if let Some(assigned_advices) = assigned_advices.as_mut() {
                assigned_advices.insert((ctx_dense.context_id, i), (cell_dense, row_offset));
            }

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
                    || Value::known(advice_spread),
                )
                .unwrap()
                .cell();

            if let Some(assigned_advices) = assigned_advices.as_mut() {
                assigned_advices.insert((ctx_spread.context_id, i), (cell_spread, row_offset));
            }

            num_limb_sum += 1;
            if column_idx == spread.num_advice_columns - 1 {
                row_offset += 1;
            }
            row_offset += 1;
        }
    }
}
