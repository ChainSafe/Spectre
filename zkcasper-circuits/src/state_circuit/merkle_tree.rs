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
