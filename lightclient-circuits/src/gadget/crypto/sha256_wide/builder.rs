use std::{cell::RefCell, collections::HashMap, iter};

use eth_types::Field;
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, FlexGateConfigParams, GateThreadBuilder, KeygenAssignments,
            ThreadBreakPoints,
        },
        flex_gate::FlexGateConfig,
    },
    utils::ScalarField,
    Context,
};
use halo2_proofs::{
    circuit::{self, Region, Value},
    plonk::{Advice, Column, Selector},
};
use itertools::Itertools;

use crate::util::BaseThreadBuilder;

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

impl<F: Field> ShaBitThreadBuilder<F> {
    // re-expose some methods from [`GateThreadBuilder`] for convenience
    #[allow(unused_mut)]
    pub fn new(mut witness_gen_only: bool) -> Self {
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
                offset: todo!(),
            },
            gate_builder,
            sha_offset: 0
        }
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

    /// Auto-calculate configuration parameters for the circuit
    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> FlexGateConfigParams {
        self.gate_builder.config(k, minimum_rows)
    }

    pub fn sha_contexts(&mut self) -> &mut Sha256BitContexts<F> {
        // Sha256BitContexts{
        //     q_enable: &mut self.sha_contexts.q_enable,
        //     q_first: &mut self.sha_contexts.q_first,
        //     q_extend: &mut self.sha_contexts.q_extend,
        //     q_start: &mut self.sha_contexts.q_start,
        //     q_compression: &mut self.sha_contexts.q_compression,
        //     q_end: &mut self.sha_contexts.q_end,
        //     q_padding: &mut self.sha_contexts.q_padding,
        //     q_padding_last: &mut self.sha_contexts.q_padding_last,
        //     q_squeeze: &mut self.sha_contexts.q_squeeze,
        //     q_final_word: &mut self.sha_contexts.q_final_word,
        //     word_w: self.sha_contexts.word_w.iter_mut().collect::<Vec<&mut _>>().try_into().unwrap(),
        //     word_a: self.sha_contexts.word_a.iter_mut().collect::<Vec<&mut _>>().try_into().unwrap(),
        //     word_e: self.sha_contexts.word_e.iter_mut().collect::<Vec<&mut _>>().try_into().unwrap(),
        //     is_final: &mut self.sha_contexts.is_final,
        //     is_paddings: self.sha_contexts.is_paddings.iter_mut().collect::<Vec<&mut _>>().try_into().unwrap(),
        //     data_rlcs: self.sha_contexts.data_rlcs.iter_mut().collect::<Vec<&mut _>>().try_into().unwrap(),
        //     round_cst: &mut self.sha_contexts.round_cst,
        //     h_a: &mut self.sha_contexts.h_a,
        //     h_e: &mut self.sha_contexts.h_e,
        //     is_enabled: &mut self.sha_contexts.is_enabled,
        //     input_rlc: &mut self.sha_contexts.input_rlc,
        //     input_len: &mut self.sha_contexts.input_len,
        //     hash_rlc: &mut self.sha_contexts.hash_rlc,
        //     final_hash_bytes: self.sha_contexts.final_hash_bytes.iter_mut().collect::<Vec<&mut _>>().try_into().unwrap(),
        //     _f: std::marker::PhantomData,
        //     offset: &mut self.sha_offset
        // }
        &mut self.sha_contexts
    }

    /// Assigns all advice and fixed cells, turns on selectors, imposes equality constraints.
    /// This should only be called during keygen.
    pub fn assign_all(
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
    ) -> KeygenAssignments<F> {
        assert!(!self.witness_gen_only());

        // assign_threads_sha(
        //     &self.threads_dense,
        //     &self.threads_spread,
        //     spread,
        //     region,
        //     self.use_unknown(),
        //     Some(&mut assigned_advices),
        // );
        // in order to constrain equalities and assign constants, we copy the Spread/Dense equality constraints into the gate builder (it doesn't matter which context the equalities are in), so `GateThreadBuilder::assign_all` can take care of it
        // the phase doesn't matter for equality constraints, so we use phase 0 since we're sure there's a main context there
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

impl<F: Field> BaseThreadBuilder<F> for ShaBitThreadBuilder<F> {
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
}
