use std::collections::HashMap;

use crate::{table::state_table::StateTable, witness::MerkleTraceStep};
use eth_types::*;
use gadgets::util::rlc;
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{
        Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;

#[derive(Clone, Debug)]
pub struct LongMerkleTree<F> {
    enable: Column<Fixed>,
    root: Column<Fixed>,
    node: Column<Advice>,
    sibling: Column<Advice>,
    parent: Column<Advice>,
    index: Column<Advice>,
    parent_index: Column<Advice>,
    depth: Column<Advice>,
    _f: std::marker::PhantomData<F>,
}

impl<F: Field> LongMerkleTree<F> {
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let node = meta.advice_column();
        let sibling = meta.advice_column();
        let parent = meta.advice_column();
        let index = meta.advice_column();
        let depth = meta.advice_column();
        let enable = meta.fixed_column();
        let parent_index = meta.advice_column();
        let root = meta.fixed_column();

        // enable permutation checks
        meta.enable_equality(node);
        meta.enable_equality(sibling);
        meta.enable_equality(parent);
        meta.enable_equality(index);

        let config = Self {
            node,
            sibling,
            parent,
            index,
            depth,
            _f: std::marker::PhantomData,
            enable,
            parent_index,
            root,
        };

        // Annotate columns
        config
            .annotations()
            .into_iter()
            .for_each(|(col, ann)| meta.annotate_lookup_any_column(col, || &ann));

        config
    }

    pub fn annotations(&self) -> Vec<(Column<Any>, String)> {
        vec![
            (self.node.into(), String::from("node")),
            (self.sibling.into(), String::from("sibling")),
            (self.parent.into(), String::from("parent")),
            (self.index.into(), String::from("index")),
            (self.depth.into(), String::from("depth")),
            (self.enable.into(), String::from("enable")),
            (self.parent_index.into(), String::from("parent_index")),
            (self.root.into(), String::from("root")),
        ]
    }

    pub fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.annotations()
            .into_iter()
            .for_each(|(col, ann)| region.name_column(|| &ann, col));
    }

    pub fn node(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.node, Rotation::cur())
    }
    pub fn sibling(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.sibling, Rotation::cur())
    }
    pub fn parent(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.parent, Rotation::cur())
    }
    pub fn index(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.index, Rotation::cur())
    }
    pub fn depth(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.depth, Rotation::cur())
    }
    pub fn parent_index(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.parent_index, Rotation::cur())
    }
    pub fn enable(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_fixed(self.enable, Rotation::cur())
    }
    pub fn root(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_fixed(self.root, Rotation::cur())
    }

    // Assigns the columns given the MerkleTraceSteps which are indexed by their Gindex
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        steps: &HashMap<usize, &MerkleTraceStep>,
        challange: Value<F>,
    ) -> Result<(), Error> {
        // First row
        // let root_cell = (
        //     region.assign_advice(|| "parent", self.parent, 1, || Value::known(F::zero()))?,
        //     region.assign_advice(
        //         || "parent index",
        //         self.parent_index,
        //         1,
        //         || Value::known(F::zero()),
        //     )?,
        //     region.assign_advice(
        //         || "node",
        //         self.node,
        //         1,
        //         || challange.map(|rnd| rlc::value(&steps[&1].node, rnd)),
        //     )?,
        //     region.assign_advice(|| "sibling", self.sibling, 1, || Value::known(F::zero()))?,
        //     region.assign_advice(|| "depth", self.depth, 1, || Value::known(F::one()))?,

        //     region.assign_fixed(|| "enable", self.enable, 1, || Value::known(F::one()))?,

        //     region.assign_advice(|| "index", self.index, 1, || Value::known(F::one()))?,
        //     region.assign_fixed(|| "root", self.root, 1, || Value::known(F::one()))?,
        // );

        // Assign all other rows/depths
        let mut cells = steps
            .iter()
            .filter(|(_, entry)| entry.index != 1)
            .map(|(_, entry)| {
                let index = entry.index;
                let p_index = entry.parent_index;
                let index_cell = region.assign_advice(
                    || "index",
                    self.index,
                    index as usize,
                    || Value::known(F::from(index as u64)),
                )?;
                let parent_cell = region.assign_advice(
                    || "parent",
                    self.parent,
                    index as usize,
                    || challange.map(|rnd| rlc::value(&entry.parent, rnd)),
                )?;
                let parent_index_cell = region.assign_advice(
                    || "parent_index",
                    self.parent_index,
                    index as usize,
                    || Value::known(F::from(p_index as u64)),
                )?;

                let node_cell = region.assign_advice(
                    || "node",
                    self.node,
                    index as usize,
                    || {
                        if entry.is_rlc[0] {
                            challange.map(|rnd| rlc::value(&entry.node, rnd))
                        } else {
                            Value::known(F::from_bytes_le_unsecure(&entry.node))
                        }
                    },
                )?;
                let sibling_cell = region.assign_advice(
                    || "sibling",
                    self.sibling,
                    index as usize,
                    || {
                        if entry.is_rlc[1] {
                            challange.map(|rnd| rlc::value(&entry.sibling, rnd))
                        } else {
                            Value::known(F::from_bytes_le_unsecure(&entry.sibling))
                        }
                    },
                )?;

                let depth_cell = region.assign_advice(
                    || "depth",
                    self.depth,
                    index as usize,
                    || Value::known(F::from(entry.depth as u64)),
                )?;
                let enable_cell = region.assign_fixed(
                    || "enable",
                    self.enable,
                    index as usize,
                    || Value::known(F::one()),
                )?;
                let root_cell = region.assign_fixed(
                    || "root",
                    self.root,
                    index as usize,
                    || Value::known(F::zero()),
                )?;
                Ok((
                    index,
                    (
                        parent_cell,
                        parent_index_cell,
                        node_cell,
                        sibling_cell,
                        depth_cell,
                        enable_cell,
                        index_cell,
                        root_cell,
                    ),
                ))
            })
            .collect::<Result<HashMap<u64, _>, Error>>()?;

        // cells.insert(1, root_cell);
        let cells = cells;

        // Apply equality constraints
        for (index, cell) in cells.iter() {
            let (
                parent_cell,
                _parent_index_cell,
                _node_cell,
                _sibling_cell,
                _depth_cell,
                _enable_cell,
                _index_cell,
                _root_cell,
            ): &(
                halo2_proofs::circuit::AssignedCell<F, F>,
                halo2_proofs::circuit::AssignedCell<F, F>,
                halo2_proofs::circuit::AssignedCell<F, F>,
                halo2_proofs::circuit::AssignedCell<F, F>,
                halo2_proofs::circuit::AssignedCell<F, F>,
                halo2_proofs::circuit::AssignedCell<F, F>,
                halo2_proofs::circuit::AssignedCell<F, F>,
                halo2_proofs::circuit::AssignedCell<F, F>,
            ) = cell;
            if *index == 1 {
                continue;
            } else {
                let parent_index = index / 2;
                let right = parent_index % 2;

                if parent_index == 1 {
                    // parent is root node
                    // region.constrain_equal(parent_cell.cell(), cells[&1].2.cell())?;
                    continue;
                }

                // if parent index is odd, that means its a sibling node
                // TODO: Rename node to "left" and sibling to "right"
                let parent_node_cell = if right == 0 {
                    // node cell (left)
                    &cells[&parent_index].2
                } else if right == 1 {
                    // sibling cell (right)
                    &cells[&(parent_index - 1)].3
                } else {
                    unreachable!()
                };

                region.constrain_equal(parent_cell.cell(), parent_node_cell.cell())?;
            }
        }

        Ok(())
    }
}

impl<F: Field> From<LongMerkleTree<F>> for StateTable {
    fn from(val: LongMerkleTree<F>) -> Self {
        StateTable {
            is_enabled: val.enable,
            sibling: val.sibling,
            node: val.node,
            index: val.index,
        }
    }
}
