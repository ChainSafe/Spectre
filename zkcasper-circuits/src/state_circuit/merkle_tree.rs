use super::cell_manager::CellManager;
use crate::{
    state_circuit::{StateSSZCircuitConfig, TREE_LEVEL_AUX_COLUMNS},
    table::state_table::StateTable,
    util::{Cell, CellType},
    witness::{MerkleTrace, MerkleTraceStep},
};
use eth_types::*;
use gadgets::{
    binary_number::BinaryNumberConfig,
    util::{rlc, Expr},
};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{
        Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use rand_chacha::rand_core::le;

#[derive(Clone, Debug)]
pub struct TreeLevel<F> {
    q_enabled: Column<Fixed>,
    pub(crate) depth: usize,
    padding: usize,
    sibling: Column<Advice>,
    sibling_index: Column<Advice>,
    node: Column<Advice>,
    index: Column<Advice>,
    into_left: Column<Advice>,
    offset: usize,
    _f: std::marker::PhantomData<F>,
    // pub(super) cell_manager: CellManager<F>,
}

impl<F: Field> TreeLevel<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        depth: usize,
        offset: usize,
        padding: usize,
    ) -> Self {
        let q_enabled = meta.fixed_column();
        let sibling = meta.advice_column_in(SecondPhase);
        let sibling_index = meta.advice_column_in(SecondPhase);
        let node = meta.advice_column_in(SecondPhase);
        let index = meta.advice_column_in(SecondPhase);
        let into_left = meta.advice_column();

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
            let node_rlc = challange.map(|rnd| rlc::value(&step.node, rnd));
            let sibling_rlc = challange.map(|rnd| rlc::value(&step.sibling, rnd));

            // TODO: fixed q_enabled should be set seprarately to the bottom of the table
            region.assign_fixed(
                || "q_enabled",
                self.q_enabled,
                offset,
                || Value::known(F::one()),
            )?;
            region.assign_advice(|| "sibling", self.sibling, offset, || sibling_rlc)?;
            region.assign_advice(
                || "sibling_index",
                self.sibling_index,
                offset,
                || Value::known(F::from(step.sibling_index as u64)),
            )?;
            region.assign_advice(|| "node", self.node, offset, || node_rlc)?;
            region.assign_advice(
                || "index",
                self.index,
                offset,
                || Value::known(F::from(step.index as u64)),
            )?;
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
        vec![
            (self.q_enabled.into(), format!("{}/q_enabled", self.depth)),
            (self.sibling.into(), format!("{}/sibling", self.depth)),
            (
                self.sibling_index.into(),
                format!("{}/sibling_index", self.depth),
            ),
            (self.node.into(), format!("{}/node", self.depth)),
            (self.index.into(), format!("{}/index", self.depth)),
            (self.into_left.into(), format!("{}/into_left", self.depth)),
        ]
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

    pub fn sibling_index(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.sibling_index, Rotation::cur())
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

    pub fn index(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.index, Rotation::cur())
    }

    pub fn into_left(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.into_left, Rotation::cur())
    }
}

impl<F: Field> Into<StateTable> for TreeLevel<F> {
    fn into(self) -> StateTable {
        StateTable {
            is_enabled: self.q_enabled,
            sibling: self.sibling,
            sibling_index: self.sibling_index,
            node: self.node,
            index: self.index,
        }
    }
}
