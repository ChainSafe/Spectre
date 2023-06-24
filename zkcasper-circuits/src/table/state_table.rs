use itertools::Itertools;

use crate::witness::{StateEntry, StateRow};

use super::*;

/// The StateTable contains records of the state of the beacon chain.
#[derive(Clone, Debug)]
pub struct StateTable {
    /// ValidatorIndex when tag == 'Validator', CommitteeIndex otherwise.
    pub id: Column<Advice>,
    /// Type of entity contained in BeaconState "god" object
    pub tag: Column<Advice>,
    /// Signals whether validator is active during that epoch.
    pub is_active: Column<Advice>,
    /// Signals whether validator have attested during that epoch.
    pub is_attested: Column<Advice>,
    /// Type of field the row represents.
    pub field_tag: Column<Advice>,
    /// Index for FieldTag
    pub index: Column<Advice>,
    /// Generalized index for State tree Merkle proofs.
    pub gindex: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
    /// SSZ chunk RLC
    pub ssz_rlc: Column<Advice>,
}

impl<F: Field> LookupTable<F> for StateTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.id.into(),
            self.tag.into(),
            self.is_active.into(),
            self.is_attested.into(),
            self.field_tag.into(),
            self.index.into(),
            self.gindex.into(),
            self.value.into(),
            self.ssz_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("id"),
            String::from("tag"),
            String::from("is_active"),
            String::from("is_attested"),
            String::from("field_tag"),
            String::from("index"),
            String::from("gindex"),
            String::from("value"),
            String::from("ssz_rlc"),
        ]
    }
}

impl StateTable {
    /// Construct a new StateTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            id: meta.advice_column(),
            tag: meta.advice_column(),
            is_active: meta.advice_column(),
            is_attested: meta.advice_column(),
            field_tag: meta.advice_column(),
            index: meta.advice_column(), // meta.advice_column_in(SecondPhase),
            gindex: meta.advice_column_in(SecondPhase),
            value: meta.advice_column_in(SecondPhase),
            ssz_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &StateRow<Value<F>>,
    ) -> Result<(), Error> {
        for (column, value) in [
            (self.id, row.id),
            (self.tag, row.tag),
            (self.is_active, row.is_active),
            (self.is_attested, row.is_attested),
            (self.field_tag, row.field_tag),
            (self.index, row.index),
            (self.gindex, row.gindex),
            (self.value, row.value),
            (self.ssz_rlc, row.ssz_rlc),
        ] {
            region.assign_advice(
                || "assign state row on state table",
                column,
                offset,
                || value,
            )?;
        }
        Ok(())
    }

    /// Load the state table into the circuit.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        entries: &[StateEntry],
        challenge: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "state table",
            |mut region| {
                self.annotate_columns_in_region(&mut region);
                for (offset, row) in entries
                    .iter()
                    .flat_map(|e| e.table_assignment(challenge))
                    .enumerate()
                {
                    self.assign(&mut region, offset, &row)?;
                }

                Ok(())
            },
        )
    }

    pub fn build_lookup<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
        enable: Expression<F>,
        gindex: Expression<F>,
        value_rlc: Expression<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        vec![
            (
                gindex.clone() * enable.clone(),
                meta.query_advice(self.gindex, Rotation::cur()),
            ),
            (
                value_rlc.clone() * enable.clone(),
                meta.query_advice(self.ssz_rlc, Rotation::cur())
            )
            // TODO: should any other columns be included?
        ]
    }
}
