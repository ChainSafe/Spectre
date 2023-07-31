use super::*;
use crate::{util::rlc, witness::HashInput};
use halo2_proofs::circuit::AssignedCell;
use itertools::Itertools;
use sha2::Digest;

/// Keccak Table, used to verify keccak hashing from RLC'ed input.
#[derive(Clone, Debug)]
pub struct Sha256Table {
    /// True when the row is enabled
    pub is_enabled: Column<Advice>,
    /// Byte array input parts as `RLC(input[i])`
    pub input_chunks: [Column<Advice>; 2],
    /// Byte array first input as `RLC(input[i])`
    pub input_rlc: Column<Advice>,
    /// Length of first+second inputs
    pub input_len: Column<Advice>,
    /// RLC of the hash result
    pub hash_rlc: Column<Advice>,
}

impl<F: Field> LookupTable<F> for Sha256Table {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.is_enabled.into(),
            self.input_chunks[0].into(),
            self.input_chunks[1].into(),
            self.input_rlc.into(),
            self.input_len.into(),
            self.hash_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("is_enabled"),
            String::from("left_chunk"),
            String::from("right_chunk"),
            String::from("input_rlc"),
            String::from("input_len"),
            String::from("hash_rlc"),
        ]
    }
}

impl Sha256Table {
    /// Construct a new KeccakTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            is_enabled: meta.advice_column(),
            input_chunks: [
                meta.advice_column_in(SecondPhase),
                meta.advice_column_in(SecondPhase),
            ],
            input_rlc: meta.advice_column_in(SecondPhase),
            input_len: meta.advice_column(),
            hash_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    /// Assign a table row for keccak table
    pub fn assign_row<F: Field>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        values: [Value<F>; 6],
    ) -> Result<[AssignedCell<F, F>; 6], Error> {
        <Sha256Table as LookupTable<F>>::advice_columns(self)
            .iter()
            .zip(values.iter())
            .map(|(&column, value)| {
                region.assign_advice(|| format!("assign {}", offset), column, offset, || *value)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|res| res.try_into().unwrap())
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
                enable.clone(),
                meta.query_advice(self.is_enabled, Rotation::cur()),
            ),
            (
                enable.clone() * fst,
                meta.query_advice(self.input_chunks[0], Rotation::cur()),
            ),
            (
                enable.clone() * snd,
                meta.query_advice(self.input_chunks[1], Rotation::cur()),
            ),
            (
                enable * hash,
                meta.query_advice(self.hash_rlc, Rotation::cur()),
            ),
        ]
    }

    /// Load sha256 table without running the full sha256 circuit.
    pub fn dev_load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: impl IntoIterator<Item = &'a HashInput<u8>> + Clone,
        challenge: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "sha256 table",
            |mut region| {
                self.annotate_columns_in_region(&mut region);

                let sha256_table_columns = <Sha256Table as LookupTable<F>>::advice_columns(self);
                for (offset, input) in inputs.clone().into_iter().enumerate() {
                    let row = Self::assignments_dev(input, challenge);

                    for (&column, value) in sha256_table_columns.iter().zip_eq(row) {
                        region.assign_advice(
                            || format!("sha256 table row {}", offset),
                            column,
                            offset,
                            || value,
                        )?;
                    }
                }
                Ok(())
            },
        )
    }

    /// Generate the sha256 table assignments from a byte array input.
    fn assignments_dev<F: Field>(input: &HashInput<u8>, challenge: Value<F>) -> [Value<F>; 6] {
        let (input_chunks, input_rlc, preimage) = match input {
            HashInput::Single(inner) => {
                let input_rlc = if inner.is_rlc {
                    challenge.map(|randomness| rlc::value(&inner.bytes, randomness))
                } else {
                    Value::known(F::from_bytes_le_unsecure(&inner.bytes))
                };

                (
                    [input_rlc, Value::known(F::zero())],
                    input_rlc,
                    inner.bytes.clone(),
                )
            }
            HashInput::TwoToOne(left, right) => {
                let chunk_rlcs = [
                    challenge.map(|randomness| rlc::value(&left.bytes, randomness)),
                    challenge.map(|randomness| rlc::value(&right.bytes, randomness)),
                ];
                let chunk_vals = [
                    F::from_bytes_le_unsecure(&left.bytes),
                    F::from_bytes_le_unsecure(&right.bytes),
                ];
                let preimage = input.clone().to_vec();
                let input_rlc = challenge.map(|randomness| rlc::value(&preimage, randomness));

                let input_chunks = [
                    if left.is_rlc {
                        chunk_rlcs[0]
                    } else {
                        Value::known(chunk_vals[0])
                    },
                    if right.is_rlc {
                        chunk_rlcs[1]
                    } else {
                        Value::known(chunk_vals[1])
                    },
                ];

                (input_chunks, input_rlc, preimage)
            }
        };

        let input_len = F::from(preimage.len() as u64);

        let output = sha2::Sha256::digest(preimage).to_vec();
        let output_rlc = challenge.map(|randomness| rlc::value(&output, randomness));

        [
            Value::known(F::one()),
            input_chunks[0],
            input_chunks[1],
            input_rlc,
            Value::known(input_len),
            output_rlc,
        ]
    }
}
