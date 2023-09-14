use std::{cell::RefCell, collections::HashMap, iter, mem};

use eth_types::Field;
use halo2_base::{
    gates::{
        builder::{
            assign_threads_in, CircuitBuilderStage, FlexGateConfigParams, GateThreadBuilder,
            KeygenAssignments, ThreadBreakPoints,
        },
        flex_gate::FlexGateConfig,
    },
    utils::ScalarField,
    Context,
};
use halo2_proofs::{
    circuit::{self, Region, Value},
    plonk::{Advice, Column, Error, Selector},
};
use itertools::Itertools;

use crate::util::{ThreadBuilderBase, ThreadBuilderConfigBase};

use super::{config::Sha256BitConfig, witness::ShaRow};

pub const FIRST_PHASE: usize = 0;

pub type Sha256BitContexts<F> = Sha256BitConfig<F, Context<F>, Context<F>>;

#[derive(Clone, Debug)]
pub struct ShaBitThreadBuilder<F: Field> {
    /// Threads for spread table assignment.
    sha_contexts: Sha256BitContexts<F>,
    /// [`GateThreadBuilder`] with threads for basic gate; also in charge of thread IDs
    pub gate_builder: GateThreadBuilder<F>,

    sha_offset: usize,
}

impl<F: Field> ThreadBuilderBase<F> for ShaBitThreadBuilder<F> {
    type Config = Sha256BitConfig<F>;

    fn new(mut witness_gen_only: bool) -> Self {
        let mut gate_builder = GateThreadBuilder::new(witness_gen_only);
        let mut new_context = || Context::new(witness_gen_only, gate_builder.get_new_thread_id());
        Self {
            sha_contexts: Sha256BitConfig {
                q_enable: new_context(),
                q_first: new_context(),
                q_extend: new_context(),
                q_start: new_context(),
                q_compression: new_context(),
                q_end: new_context(),
                q_padding: new_context(),
                q_padding_last: new_context(),
                q_squeeze: new_context(),
                q_final_word: new_context(),
                word_w: array_init::array_init(|_| new_context()),
                word_a: array_init::array_init(|_| new_context()),
                word_e: array_init::array_init(|_| new_context()),
                is_final: new_context(),
                is_paddings: array_init::array_init(|_| new_context()),
                data_rlcs: array_init::array_init(|_| new_context()),
                round_cst: new_context(),
                h_a: new_context(),
                h_e: new_context(),
                is_enabled: new_context(),
                input_rlc: new_context(),
                input_len: new_context(),
                hash_rlc: new_context(),
                final_hash_bytes: array_init::array_init(|_| new_context()),
                _f: std::marker::PhantomData,
                offset: 0,
            },
            gate_builder,
            sha_offset: 0,
        }
    }

    fn unknown(mut self, use_unknown: bool) -> Self {
        self.gate_builder = self.gate_builder.unknown(use_unknown);
        self
    }

    fn config(&self, k: usize, minimum_rows: Option<usize>) -> FlexGateConfigParams {
        self.gate_builder.config(k, minimum_rows)
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

    fn assign_all(
        &mut self,
        gate: &FlexGateConfig<F>,
        lookup_advice: &[Vec<Column<Advice>>],
        q_lookup: &[Option<Selector>],
        config: &Sha256BitConfig<F>,
        region: &mut Region<F>,
        KeygenAssignments {
            mut assigned_advices,
            assigned_constants,
            mut break_points,
        }: KeygenAssignments<F>,
    ) -> Result<KeygenAssignments<F>, Error> {
        assert!(!self.witness_gen_only());

        config.annotate_columns_in_region(region);

        let use_unknown = self.use_unknown();

        self.sha_contexts().assign_in_region(
            region,
            config,
            use_unknown,
            Some(&mut assigned_advices),
        )?;

        let main_ctx = self.gate_builder.main(0);
        // for ctx in self
        //     .threads_spread
        //     .iter_mut()
        //     .chain(self.threads_dense.iter_mut())
        // {
        //     main_ctx
        //         .advice_equality_constraints
        //         .append(&mut ctx.advice_equality_constraints);
        //     main_ctx
        //         .constant_equality_constraints
        //         .append(&mut ctx.constant_equality_constraints);
        // }

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
        config: &Self::Config,
        region: &mut Region<F>,
        break_points: &mut halo2_base::gates::builder::MultiPhaseThreadBreakPoints,
    ) -> Result<(), Error> {
        let use_unknown = self.use_unknown();

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

        self.sha_contexts()
            .assign_in_region(region, config, use_unknown, None)
    }
}

impl<F: Field> ShaBitThreadBuilder<F> {
    pub fn sha_contexts(&mut self) -> &mut Sha256BitContexts<F> {
        &mut self.sha_contexts
    }
}
