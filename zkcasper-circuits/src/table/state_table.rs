use gadgets::util::rlc;

use std::collections::HashMap;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{
    state_circuit::{PUBKEYS_LEVEL, VALIDATORS_LEVEL},
    witness::{MerkleTrace, MerkleTraceStep},
};

use super::*;

/// The StateTable contains records of the state of the beacon chain.
#[derive(Clone, Debug)]
pub struct StateTable {
    pub is_enabled: Column<Fixed>,
    pub sibling: Column<Advice>,
    pub node: Column<Advice>,
    pub index: Column<Advice>,
}

#[derive(Clone, Debug, EnumIter, PartialEq, Eq, Hash)]
pub enum StateTreeLevel {
    PubKeys,
    Validators,
}

impl<F: Field> LookupTable<F> for StateTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.is_enabled.into(),
            self.sibling.into(),
            self.node.into(),
            self.index.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("is_enabled"),
            String::from("sibling"),
            String::from("node"),
            String::from("index"),
        ]
    }
}

impl StateTable {
    // For `StateTables::dev_constract` only.
    fn constuct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let is_enabled = meta.fixed_column();
        let sibling = meta.advice_column();
        let node = meta.advice_column();
        let index = meta.advice_column_in(FirstPhase);

        Self {
            is_enabled,
            sibling,
            node,
            index,
        }
    }

    // For `StateTables::dev_construct` only. Must not be used in `StateCircuit` as it does not adds padding.
    fn assign_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        steps: Vec<&MerkleTraceStep>,
        challenge: Value<F>,
    ) -> Result<(), Error> {
        for (i, step) in steps.into_iter().enumerate() {
            assert_eq!(step.sibling.len(), 32);
            assert_eq!(step.node.len(), 32);
            let node = if step.is_rlc[0] {
                challenge.map(|rnd| rlc::value(&step.node, rnd))
            } else {
                Value::known(F::from_bytes_le_unsecure(&step.node))
            };
            let sibling = if step.is_rlc[1] {
                challenge.map(|rnd| rlc::value(&step.sibling, rnd))
            } else {
                Value::known(F::from_bytes_le_unsecure(&step.sibling))
            };

            region.assign_fixed(
                || "is_enabled",
                self.is_enabled,
                i,
                || Value::known(F::one()),
            )?;
            region.assign_advice(|| "sibling", self.sibling, i, || sibling)?;
            region.assign_advice(|| "node", self.node, i, || node)?;
            region.assign_advice(
                || "index",
                self.index,
                i,
                || Value::known(F::from(step.index)),
            )?;
        }

        Ok(())
    }

    pub fn build_lookup<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
        level: StateTreeLevel,
        is_left: bool,
        enable: Expression<F>,
        gindex: Expression<F>,
        value_rlc: Expression<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let value_col = if is_left { self.node } else { self.sibling };
        let index_col = self.index;

        let gindex = if is_left {
            gindex
        } else {
            gindex - Expression::Constant(F::one())
        };

        vec![
            (
                enable.clone(),
                meta.query_fixed(self.is_enabled, Rotation::cur()),
            ),
            (
                value_rlc * enable.clone(),
                meta.query_advice(value_col, Rotation::cur()),
            ),
            (
                gindex * enable,
                meta.query_advice(index_col, Rotation::cur()),
            ),
        ]
    }

    /// Load state table without running the full [`StateTable`].
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        trace: &MerkleTrace,
        challenge: Value<F>,
    ) -> Result<(), Error> {
        let mut trace_by_depth = trace.trace_by_level_map();

        let mut trace = trace_by_depth.remove(&PUBKEYS_LEVEL).unwrap();
        trace.extend(trace_by_depth.remove(&VALIDATORS_LEVEL).unwrap());

        layouter.assign_region(
            || "dev load state tables",
            |mut region| {
                self.annotate_columns_in_region(&mut region);
                self.assign_with_region(&mut region, trace.clone(), challenge)?;

                Ok(())
            },
        )?;
        Ok(())
    }

    /// Construct a new [`ValidatorsTable`] outside of [`StateTable`].
    pub fn dev_construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        StateTable::constuct(meta)
    }
}
