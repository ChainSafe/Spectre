use std::hash::Hash;

use eth_types::Field;
use halo2_base::{AssignedValue, QuantumCell};
use itertools::Itertools;

use crate::util::{ConstantFrom, IntoWitness, WitnessFrom};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum HashInput<T> {
    Single(HashInputChunk<T>),
    TwoToOne(HashInputChunk<T>, HashInputChunk<T>),
}

impl<T: Clone> HashInput<T> {
    pub fn to_vec(self) -> Vec<T> {
        match self {
            HashInput::Single(inner) => inner.0,
            HashInput::TwoToOne(left, right) => {
                let mut result = left.0;
                result.extend(right.0);
                result
            }
        }
    }

    pub fn map<B, F: FnMut(T) -> B>(self, f: F) -> HashInput<B> {
        match self {
            HashInput::Single(inner) => {
                HashInput::Single(HashInputChunk(inner.0.into_iter().map(f).collect()))
            }
            HashInput::TwoToOne(left, right) => {
                let left_size = left.0.len();
                let mut all = left.0.into_iter().chain(right.0).map(f).collect_vec();
                let remainer = all.split_off(left_size);
                let left = HashInputChunk(all);
                let right = HashInputChunk(remainer);

                HashInput::TwoToOne(left, right)
            }
        }
    }
}

impl<F: Field> IntoIterator for HashInput<QuantumCell<F>> {
    type Item = QuantumCell<F>;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.to_vec().into_iter()
    }
}

impl<I: Into<HashInputChunk<u8>>> From<I> for HashInput<u8> {
    fn from(input: I) -> Self {
        HashInput::Single(input.into())
    }
}

impl<IL: Into<HashInputChunk<u8>>, IR: Into<HashInputChunk<u8>>> From<(IL, IR)> for HashInput<u8> {
    fn from(input: (IL, IR)) -> Self {
        let left = input.0.into();
        let right = input.1.into();
        HashInput::TwoToOne(left, right)
    }
}

impl<F: Field, I: Into<HashInputChunk<QuantumCell<F>>>> From<I> for HashInput<QuantumCell<F>> {
    fn from(input: I) -> Self {
        HashInput::Single(input.into())
    }
}

impl<F: Field, I: Into<HashInputChunk<u8>>> WitnessFrom<I> for HashInput<QuantumCell<F>> {
    fn witness_from(input: I) -> Self {
        let input: HashInputChunk<u8> = input.into();

        HashInput::Single(HashInputChunk(
            input
                .0
                .into_iter()
                .map(|b| QuantumCell::Witness(F::from(b as u64)))
                .collect(),
        ))
    }
}

impl<F: Field, IL: Into<HashInputChunk<u8>>, IR: Into<HashInputChunk<u8>>> WitnessFrom<(IL, IR)>
    for HashInput<QuantumCell<F>>
{
    fn witness_from((left, right): (IL, IR)) -> Self {
        HashInput::TwoToOne(left.into_witness(), right.into_witness())
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct HashInputChunk<T>(Vec<T>);

impl<T> HashInputChunk<T> {
    pub fn new(bytes: Vec<T>) -> Self {
        Self(bytes)
    }

    pub fn map<B, F: FnMut(T) -> B>(self, f: F) -> HashInputChunk<B> {
        HashInputChunk(self.0.into_iter().map(f).collect())
    }

    pub fn to_vec(self) -> Vec<T> {
        self.0
    }
}

impl<F: Field> IntoIterator for HashInputChunk<QuantumCell<F>> {
    type Item = QuantumCell<F>;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<F: Field, I: Into<HashInputChunk<u8>>> WitnessFrom<I> for HashInputChunk<QuantumCell<F>> {
    fn witness_from(input: I) -> Self {
        let input: HashInputChunk<u8> = input.into();

        HashInputChunk(
            input
                .0
                .into_iter()
                .map(|b| QuantumCell::Witness(F::from(b as u64)))
                .collect(),
        )
    }
}

impl<F: Field, I: Into<HashInputChunk<u8>>> ConstantFrom<I> for HashInputChunk<QuantumCell<F>> {
    fn constant_from(input: I) -> Self {
        let input: HashInputChunk<u8> = input.into();

        HashInputChunk(
            input
                .0
                .into_iter()
                .map(|b| QuantumCell::Constant(F::from(b as u64)))
                .collect(),
        )
    }
}

impl From<&[u8]> for HashInputChunk<u8> {
    fn from(input: &[u8]) -> Self {
        HashInputChunk(input.to_vec())
    }
}

impl From<Vec<u8>> for HashInputChunk<u8> {
    fn from(input: Vec<u8>) -> Self {
        HashInputChunk(input)
    }
}

impl From<u64> for HashInputChunk<u8> {
    fn from(input: u64) -> Self {
        HashInputChunk(pad_to_32(&input.to_le_bytes()))
    }
}

impl From<usize> for HashInputChunk<u8> {
    fn from(input: usize) -> Self {
        HashInputChunk(pad_to_32(&input.to_le_bytes()))
    }
}

impl<F: Field, I: IntoIterator<Item = AssignedValue<F>>> From<I>
    for HashInputChunk<QuantumCell<F>>
{
    fn from(input: I) -> Self {
        let bytes = input
            .into_iter()
            .map(|av| QuantumCell::Existing(av))
            .collect_vec();
        HashInputChunk(bytes)
    }
}

fn pad_to_32(le_bytes: &[u8]) -> Vec<u8> {
    assert!(le_bytes.len() <= 32);
    let mut chunk = le_bytes.to_vec();
    chunk.resize(32, 0);
    chunk
}
