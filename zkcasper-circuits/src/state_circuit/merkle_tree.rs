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
use rand::seq::index;

#[derive(Clone, Debug)]
pub struct LongMerkleTree<F> {
    enable: Column<Fixed>,
    node: Column<Advice>,
    sibling: Column<Advice>,
    parent: Column<Advice>,
    index: Column<Advice>,
    parent_index: Column<Advice>,
    depth: Column<Advice>,
    _f: std::marker::PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct TreeLevel<F> {
    q_enabled: Column<Fixed>,
    pub(crate) depth: usize,
    padding: usize,
    sibling: Column<Advice>,
    // TODO: remove `sibling_index` after changing lookup strategy to leverage `gindex +- 1` trick
    sibling_index: Option<Column<Advice>>,
    node: Column<Advice>,
    index: Option<Column<Advice>>,
    into_left: Column<Advice>,
    offset: usize,
    _f: std::marker::PhantomData<F>,
    // pub(super) cell_manager: CellManager<F>,
}

impl <F: Field> LongMerkleTree<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> Self {
        let node = meta.advice_column();
        let sibling = meta.advice_column();
        let parent = meta.advice_column();
        let index = meta.advice_column();
        let depth = meta.advice_column();
        let enable = meta.fixed_column();
        let parent_index = meta.advice_column();

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
    pub fn selector(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_fixed(self.enable, Rotation::cur())
    }
    pub fn parent_index(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.parent_index, Rotation::cur())
    }
    pub fn enable(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_fixed(self.enable, Rotation::cur())
    }
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        steps: &HashMap<usize, &MerkleTraceStep>,
        challange: Value<F>,
    ) -> Result<(), Error> {

        // Assign every cell
        // TODO: Do the first level separately
        // First row 
        // let mut node = if steps[0][0].is_rlc[0] {
        //     challange.map(|rnd| rlc::value(&steps[0][0].node, rnd))
        // } else {
        //     Value::known(F::from_bytes_le_unsecure(&steps[0][0].node))
        // };

        // let mut node_cell = region.assign_advice(
        //     || "node",
        //     self.node,
        //     0,
        //     || node,
        // )?;
        // let mut sibling_cell = region.assign_advice(
        //     || "sibling",
        //     self.sibling,
        //     0,
        //     || Value::known(F::zero()),
        // )?;
        // let mut parent_cell = region.assign_advice(|| "parent", self.parent, 0, || Value::known(F::zero()))?;
        // let mut index_cell = region.assign_advice(|| "index", self.index, 0, || Value::known(F::one()))?;
        // let mut depth_cell = region.assign_advice(|| "depth", self.depth, 0, || Value::known(F::one()))?;
        // let mut parent_index_cell = region.assign_advice(|| "parent_index", self.parent_index, 0, || Value::known(F::zero()))?;

        // let mut enable_cell = region.assign_fixed(|| "enable", self.enable, 0, || Value::known(F::one()))?;

        let cells = steps.iter().skip(1).map(|(_, entry)|  {
                let index = entry.index;
                let p_index = entry.parent_index;
                let index_cell = region.assign_advice(|| "index", self.index, index as usize, || Value::known(F::from(index as u64)))?;
                let parent_cell = region.assign_advice(|| "parent", self.parent, index as usize, || {
                        challange.map(|rnd| rlc::value(&entry.parent, rnd))
                })?;
                let parent_index_cell = region.assign_advice(|| "parent_index", self.parent_index, index as usize, || Value::known(F::from(p_index as u64)))?;
                
                let node_cell = region.assign_advice(|| "node", self.node, index as usize, || {
                    if entry.is_rlc[0] {
                        challange.map(|rnd| rlc::value(&entry.node, rnd))
                    } else {
                        Value::known(F::from_bytes_le_unsecure(&entry.node))
                    }
                })?;
                let sibling_cell = region.assign_advice(|| "sibling", self.sibling, index as usize, || {
                    if entry.is_rlc[1] {
                        challange.map(|rnd| rlc::value(&entry.sibling, rnd))
                    } else {
                        Value::known(F::from_bytes_le_unsecure(&entry.sibling))
                    }
                })?;
    
                let depth_cell = region.assign_advice(|| "depth", self.depth, index as usize, || Value::known(F::from(entry.depth as u64)))?;
                let enable_cell = region.assign_fixed(|| "enable", self.enable, index as usize, || Value::known(F::one()))?;
                Ok((index, (parent_cell, parent_index_cell, node_cell, sibling_cell, depth_cell, enable_cell, index_cell)))
        }).collect::<Result<HashMap<u64, _>, Error>>()?;

        // Apply equality constraints 
        for (index, cell) in cells.iter() {
            let (parent_cell, parent_index_cell, node_cell, sibling_cell, depth_cell, enable_cell, index_cell) = cell;
            if *index == 1 {
                continue;
            } else {
                let (parent_index, right) = (index / 2, index % 2); 
                // if parent index is odd, that means its a sibling node 
                // TODO: Rename node to "left" and sibling to "right"
                let parent_node_cell = if right == 0 {
                    &cells[&parent_index].2
                } else if right == 1 {
                    &cells[&parent_index].3
                } else {
                    unreachable!()
                };

                region.constrain_equal(parent_cell.cell(), parent_node_cell.cell())?;
            }
        };

        Ok(())
    }
}

impl<F: Field> TreeLevel<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        depth: usize,
        offset: usize,
        padding: usize,
        has_leaves: bool,
    ) -> Self {
        let q_enabled = meta.fixed_column();
        let sibling = meta.advice_column_in(SecondPhase);
        let node = meta.advice_column_in(SecondPhase);
        let into_left = meta.advice_column();

        let index = if has_leaves {
            Some(meta.advice_column_in(SecondPhase))
        } else {
            None
        };

        let sibling_index = if has_leaves {
            Some(meta.advice_column_in(SecondPhase))
        } else {
            None
        };

        let config = Self {
            q_enabled,
            depth,
            padding,
            sibling,
            sibling_index,
            node,
            index,
            into_left,
            offset,
            _f: std::marker::PhantomData,
        };

        // Annotate columns
        config
            .annotations()
            .into_iter()
            .for_each(|(col, ann)| meta.annotate_lookup_any_column(col, || &ann));

        config
    }

    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        steps: Vec<&MerkleTraceStep>,
        challange: Value<F>,
    ) -> Result<(), Error> {
        for (i, step) in steps.into_iter().enumerate() {
            let offset = self.offset + i * (self.padding + 1);
            assert_eq!(step.sibling.len(), 32);
            assert_eq!(step.node.len(), 32);
            let node = if step.is_rlc[0] {
                challange.map(|rnd| rlc::value(&step.node, rnd))
            } else {
                Value::known(F::from_bytes_le_unsecure(&step.node))
            };
            let sibling = if step.is_rlc[1] {
                challange.map(|rnd| rlc::value(&step.sibling, rnd))
            } else {
                Value::known(F::from_bytes_le_unsecure(&step.sibling))
            };

            // TODO: fixed q_enabled should be set seprarately to the bottom of the table
            region.assign_fixed(
                || "q_enabled",
                self.q_enabled,
                offset,
                || Value::known(F::one()),
            )?;
            region.assign_advice(|| "sibling", self.sibling, offset, || sibling)?;
            if let Some(sibling_index) = self.sibling_index {
                region.assign_advice(
                    || "sibling_index",
                    sibling_index,
                    offset,
                    || Value::known(F::from(step.sibling_index)),
                )?;
            }
            region.assign_advice(|| "node", self.node, offset, || node)?;
            if let Some(index) = self.index {
                region.assign_advice(
                    || "index",
                    index,
                    offset,
                    || Value::known(F::from(step.index)),
                )?;
            }
            region.assign_advice(
                || "into_left",
                self.into_left,
                offset,
                || Value::known(F::from(step.into_left as u64)),
            )?;
        }

        Ok(())
    }

    pub fn annotations(&self) -> Vec<(Column<Any>, String)> {
        let mut annots = vec![
            (self.q_enabled.into(), format!("{}/q_enabled", self.depth)),
            (self.sibling.into(), format!("{}/sibling", self.depth)),
            (self.node.into(), format!("{}/node", self.depth)),
            (self.into_left.into(), format!("{}/into_left", self.depth)),
        ];

        if let Some(index) = self.index {
            annots.push((index.into(), format!("{}/index", self.depth)))
        }

        if let Some(sibling_index) = self.sibling_index {
            annots.push((
                sibling_index.into(),
                format!("{}/sibling_index", self.depth),
            ))
        }

        annots
    }

    pub fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.annotations()
            .into_iter()
            .for_each(|(col, ann)| region.name_column(|| &ann, col));
    }

    pub fn padding(&self) -> i32 {
        self.padding as i32
    }

    pub fn selector(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_fixed(self.q_enabled, Rotation::cur())
    }

    pub fn sibling(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.sibling, Rotation::cur())
    }

    pub fn sibling_next(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.sibling, Rotation(self.padding() + 1))
    }

    pub fn sibling_at(&self, offset: i32, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.sibling, Rotation(offset))
    }

    pub fn node(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.node, Rotation::cur())
    }

    pub fn node_next(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.node, Rotation(self.padding() + 1))
    }

    pub fn node_at(&self, offset: i32, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.node, Rotation(offset))
    }

    pub fn into_left(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.into_left, Rotation::cur())
    }
}

impl<F: Field> From<TreeLevel<F>> for StateTable {
    fn from(val: TreeLevel<F>) -> Self {
        StateTable {
            is_enabled: val.q_enabled,
            sibling: val.sibling,
            sibling_index: val.sibling_index.expect("cannot use tree levels without leaves"),
            node: val.node,
            index: val.index.expect("cannot use tree levels without leaves"),
        }
    }
}
