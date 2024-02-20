// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::any::TypeId;

use eth_types::Field;
use getset::CopyGetters;
use halo2_base::{
    halo2_proofs::circuit::{Region, Value},
    virtual_region::{
        copy_constraints::{CopyConstraintManager, SharedCopyConstraintManager},
        manager::VirtualRegionManager,
    },
    Context, ContextCell,
};
use itertools::Itertools;

use crate::util::{CommonGateManager, GateBuilderConfig};

use super::SpreadConfig;

pub const FIRST_PHASE: usize = 0;

struct Dence;
struct Spread;

/// `ShaFlexGateManager` keeps track of halo2-lib virtual cells and assigns them to the region corresponding to the `SpreadConfig`.
/// It also loads of the copy (permutation) constraints between halo2-lib and vanilla cells in Plonk table.
#[derive(Clone, Debug, Default, CopyGetters)]
pub struct ShaFlexGateManager<F: Field> {
    #[getset(get_copy = "pub")]
    witness_gen_only: bool,
    /// The `unknown` flag is used during key generation. If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    #[getset(get_copy = "pub")]
    pub(crate) use_unknown: bool,
    /// Threads for spread table assignment.
    pub threads_dense: Vec<Context<F>>,
    /// Threads for spread table assignment.
    pub threads_spread: Vec<Context<F>>,

    pub copy_manager: SharedCopyConstraintManager<F>,
}

pub type ShaContexts<'a, F> = (&'a mut Context<F>, &'a mut Context<F>);

impl<F: Field> ShaFlexGateManager<F> {
    /// Mutates `self` to use the given copy manager everywhere, including in all threads.
    pub fn set_copy_manager(&mut self, copy_manager: SharedCopyConstraintManager<F>) {
        self.copy_manager = copy_manager.clone();
        for ctx in &mut self.threads_dense {
            ctx.copy_manager = copy_manager.clone();
        }
        for ctx in &mut self.threads_spread {
            ctx.copy_manager = copy_manager.clone();
        }
    }

    pub fn new_thread_dense(&mut self) -> &mut Context<F> {
        let thread_id = self.threads_dense.len();
        self.threads_dense.push(Context::new(
            self.witness_gen_only(),
            FIRST_PHASE,
            "dense",
            thread_id,
            self.copy_manager.clone(),
        ));
        self.threads_dense.last_mut().unwrap()
    }

    pub fn new_thread_spread(&mut self) -> &mut Context<F> {
        let thread_id = self.threads_spread.len();
        self.threads_spread.push(Context::new(
            self.witness_gen_only(),
            FIRST_PHASE,
            "spead",
            thread_id,
            self.copy_manager.clone(),
        ));
        self.threads_spread.last_mut().unwrap()
    }
}

impl<F: Field> CommonGateManager<F> for ShaFlexGateManager<F> {
    type CustomContext<'a> = ShaContexts<'a, F>;

    fn new(witness_gen_only: bool) -> Self {
        Self {
            witness_gen_only,
            use_unknown: false,
            threads_spread: Vec::new(),
            threads_dense: Vec::new(),
            copy_manager: SharedCopyConstraintManager::default(),
        }
    }

    fn custom_context(&mut self) -> ShaContexts<F> {
        if self.threads_dense.is_empty() {
            self.new_thread_dense();
        }
        if self.threads_spread.is_empty() {
            self.new_thread_spread();
        }
        (
            self.threads_dense.last_mut().unwrap(),
            self.threads_spread.last_mut().unwrap(),
        )
    }

    fn use_copy_manager(mut self, copy_manager: SharedCopyConstraintManager<F>) -> Self {
        self.set_copy_manager(copy_manager);
        self
    }

    fn unknown(mut self, use_unknown: bool) -> Self {
        self.use_unknown = use_unknown;
        self
    }
}

impl<F: Field> VirtualRegionManager<F> for ShaFlexGateManager<F> {
    type Config = SpreadConfig<F>;

    fn assign_raw(&self, spread: &Self::Config, region: &mut Region<F>) {
        spread.annotate_columns_in_region(region);

        if self.witness_gen_only() {
            assign_threads_sha(
                &self.threads_dense,
                &self.threads_spread,
                spread,
                region,
                false,
                None,
            );
        } else {
            let mut copy_manager = self.copy_manager.lock().unwrap();

            assign_threads_sha(
                &self.threads_dense,
                &self.threads_spread,
                spread,
                region,
                self.use_unknown(),
                Some(&mut copy_manager),
            );
        }
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
    mut copy_manager: Option<&mut CopyConstraintManager<F>>,
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

            if let Some(copy_manager) = copy_manager.as_mut() {
                copy_manager.assigned_advices.insert(
                    ContextCell::new(ctx_dense.type_id(), ctx_dense.id(), i),
                    cell_dense,
                );
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
                    || value_spread,
                )
                .unwrap()
                .cell();

            if let Some(copy_manager) = copy_manager.as_mut() {
                copy_manager.assigned_advices.insert(
                    ContextCell::new(ctx_spread.type_id(), ctx_spread.id(), i),
                    cell_spread,
                );
            }

            num_limb_sum += 1;
            if column_idx == spread.num_advice_columns - 1 {
                row_offset += 1;
            }
            row_offset += 1;
        }
    }
}
