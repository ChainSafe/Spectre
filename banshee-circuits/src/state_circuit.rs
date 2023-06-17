use crate::{util::ConstrainBuilderCommon, MAX_VALIDATORS};

pub mod cell_manager;
use cell_manager::CellManager;

pub mod constraint_builder;
use constraint_builder::ConstraintBuilder;

pub mod merkle_tree;
use merkle_tree::TreeLevel;

use crate::{
    gadget::IsEqualGadget,
    table::{sha256_table, LookupTable, SHA256Table, StateTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, MerkleTrace},
};
use eth_types::*;
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    util::{not, Expr},
};
use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed, Instance,
        SecondPhase, Selector, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use std::{
    fmt::format,
    iter,
    ops::{Add, Mul},
    vec,
};

pub const CHUNKS_PER_VALIDATOR: usize = 8;
pub const USED_CHUNKS_PER_VALIDATOR: usize = 5;
// pub const TREE_MAX_LEAVES: usize = MAX_VALIDATORS * CHUNKS_PER_VALIDATOR;
pub const TREE_DEPTH: usize = 10; // ceil(log2(TREE_MAX_LEAVES))
pub const TREE_LEVEL_AUX_COLUMNS: usize = 1;

pub const PUBKEYS_LEVEL: usize = 10;
pub const VALIDATORS_LEVEL: usize = PUBKEYS_LEVEL - 1;

#[derive(Clone, Debug)]
pub(crate) struct PathChipConfig<F: Field> {
    selector: Selector,
    tree: [TreeLevel<F>; TREE_DEPTH],
    sha256_table: SHA256Table,
}

/// chip for verify Merkle-multi proof
pub(crate) struct PathChip<'a, F: Field> {
    offset: usize,
    config: PathChipConfig<F>,
    trace: &'a MerkleTrace<F>,
}

impl<F: Field> Chip<F> for PathChip<'_, F> {
    type Config = PathChipConfig<F>;
    type Loaded = MerkleTrace<F>;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        self.trace
    }
}

impl<'a, F: Field> PathChip<'a, F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        sha256_table: SHA256Table,
        validators_num: usize,
    ) -> <Self as Chip<F>>::Config {
        let selector = meta.selector();
        let mut height: usize = validators_num;
        let mut tree = vec![TreeLevel::configure(
            meta,
            height,
            PUBKEYS_LEVEL,
            0,
            3,
            true,
        )];

        let mut padding = 0;
        for i in (1..TREE_DEPTH).rev() {
            let prev_height = height;
            height = validators_num * 2f64.powf((3 - TREE_DEPTH - i) as f64).ceil() as usize;
            if i != VALIDATORS_LEVEL {
                padding = padding * 2 + 1;
            }
            let level =
                TreeLevel::configure(meta, height, i, prev_height, padding, i == VALIDATORS_LEVEL);
            tree.push(level);
        }

        let mut tree: [_; TREE_DEPTH] = tree.into_iter().rev().collect_vec().try_into().unwrap();

        for i in (0..TREE_DEPTH).rev() {
            let level = &tree[i];
            let next_level = &tree[i - 1];

            meta.create_gate("tree_level boolean checks", |meta| {
                let selector = meta.query_selector(selector);
                let mut cb = ConstraintBuilder::new();
                cb.require_boolean("into_left is boolean", level.into_left(meta));
                if let Some(is_left_col) = level.is_left {
                    cb.require_boolean(
                        "is_left is boolean",
                        meta.query_advice(is_left_col, Rotation::cur()),
                    );
                }
                if let Some(is_right_col) = level.is_right {
                    cb.require_boolean(
                        "is_right is boolean",
                        meta.query_advice(is_right_col, Rotation::cur()),
                    );
                }
                cb.gate(selector)
            });

            if let Some(is_left_col) = level.is_left {
                meta.lookup_any(
                    "state_table.lookup(tree_level,node, tree_level.index)",
                    |meta| {
                        let selector = meta.query_selector(selector);
                        let is_left = meta.query_advice(is_left_col, Rotation::cur());

                        // TODO: constraint (node, index) with StateTable
                        // https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/main/zkevm-circuits/src/evm_circuit/execution.rs#L815-L816
                        // state_table.build_lookup(
                        //     meta,
                        //     selector * is_left,
                        //     level.node(meta),
                        //     level.node_index(meta),
                        // )
                        vec![]
                    },
                );
            }

            if let Some(is_right_col) = level.is_right {
                meta.lookup_any(
                    "state_table.lookup(tree_level.sibling, tree_level.sibling_index",
                    |meta| {
                        let selector = meta.query_selector(selector);
                        let is_right = meta.query_advice(is_right_col, Rotation::cur());

                        // TODO: constraint (sibling, sibling_index) with StateTable
                        // state_table.build_lookup(
                        //     meta,
                        //     selector * is_right,
                        //     level.sibling(meta),
                        //     level.sibling_index(meta),
                        // )
                        vec![]
                    },
                );
            }

            meta.lookup_any(
                "hash(tree_level.node | tree_level.sibling) == next_level.node",
                |meta| {
                    let selector = meta.query_selector(selector);
                    let into_node = level.into_left(meta);
                    let node = level.node(meta);
                    let sibling = level.sibling(meta);
                    let parent = next_level.node(meta);
                    sha256_table.build_lookup(meta, selector * into_node, node, sibling, parent)
                },
            );

            meta.lookup_any("hash(tree_level.node | tree_level.sibling) == next_level.sibling@rotation(-(padding + 1))", |meta| {
                let selector = meta.query_selector(selector);
                let into_sibling: Expression<F> = not::expr(level.into_left(meta));
                let node = level.node(meta);
                let sibling = level.sibling(meta);
                let parent = next_level.sibling_at(level.padding().add(1).mul(-1), meta);
                sha256_table.build_lookup(
                    meta,
                    selector * into_sibling,
                    node,
                    sibling,
                    parent,
                )
            });
        }

        PathChipConfig {
            selector,
            tree,
            sha256_table,
        }
    }

    fn construct(
        config: <Self as Chip<F>>::Config,
        offset: usize,
        trace: &'a <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self {
            config,
            offset,
            trace,
        }
    }

    fn assign(&self, region: &mut Region<'_, F>) -> Result<usize, Error> {
        let trace_by_depth = self
            .trace
            .into_iter()
            .group_by(|step| step.depth)
            .into_iter()
            .sorted_by_key(|(depth, steps)| depth.clone())
            .rev()
            .map(|(depth, steps)| steps.collect_vec())
            .collect_vec();

        let max_rows = trace_by_depth
            .iter()
            .map(|steps| steps.len())
            .max()
            .unwrap();

        for offset in 0..max_rows {
            self.config.selector.enable(region, offset)?;
        }

        for (level, steps) in self.config.tree.iter().zip(trace_by_depth) {
            level.assign_with_region(region, steps)?;
        }

        Ok(max_rows)
    }
}
