use super::*;
use crate::util::Challenges;

/// Keccak Table, used to verify keccak hashing from RLC'ed input.
#[derive(Clone, Debug)]
pub struct SHA256Table {
    /// True when the row is enabled
    pub is_enabled: Column<Advice>,
    /// Byte array first input as `RLC(input1)`
    pub first_rlc: Column<Advice>,
    /// Byte array first input length
    pub first_len: Column<Advice>,
    /// Byte array second input as `RLC(input2)`
    pub second_rlc: Column<Advice>,
    /// Byte array second input length
    pub second_len: Column<Advice>,
    /// RLC of the hash result
    pub hash_rlc: Column<Advice>,
}

impl<F: Field> LookupTable<F> for SHA256Table {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.is_enabled.into(),
            self.first_rlc.into(),
            self.first_len.into(),
            self.second_rlc.into(),
            self.second_len.into(),
            self.hash_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("is_enabled"),
            String::from("first_rlc"),
            String::from("first_len"),
            String::from("second_rlc"),
            String::from("second_len"),
            String::from("hash_rlc"),
        ]
    }
}

impl SHA256Table {
    /// Construct a new KeccakTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            is_enabled: meta.advice_column(),
            first_rlc: meta.advice_column_in(SecondPhase),
            first_len: meta.advice_column(),
            second_rlc: meta.advice_column_in(SecondPhase),
            second_len: meta.advice_column(),
            hash_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    /// Assign a table row for keccak table
    pub fn assign_row<F: Field>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        values: [Value<F>; 6],
    ) -> Result<(), Error> {
        for (&column, value) in <SHA256Table as LookupTable<F>>::advice_columns(self)
            .iter()
            .zip(values.iter())
        {
            region.assign_advice(|| format!("assign {}", offset), column, offset, || *value)?;
        }
        Ok(())
    }

    pub fn build_lookup<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
        enable: Expression<F>,
        fst: Expression<F>,
        snd: Expression<F>,
        hash: Expression<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        vec![
            (
                enable.clone() * Expression::Constant(F::ZERO),
                meta.query_advice(self.is_enabled, Rotation::cur()),
            ),
            (
                enable.clone() * fst,
                meta.query_advice(self.first_rlc, Rotation::cur()),
            ),
            (
                enable.clone() * snd,
                meta.query_advice(self.second_len, Rotation::cur()),
            ),
            (
                enable * hash,
                meta.query_advice(self.hash_rlc, Rotation::cur()),
            ),
        ]
    }
}
