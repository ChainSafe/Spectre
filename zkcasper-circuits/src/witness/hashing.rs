use std::hash::Hash;

use banshee_preprocessor::util::pad_to_ssz_chunk;
use eth_types::Field;
use halo2_base::{AssignedValue, Context, QuantumCell};
use halo2_proofs::circuit::AssignedCell;
use itertools::Itertools;

use crate::util::{ConstantFrom, IntoWitness, WitnessFrom};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum HashInput<T> {
    Single(HashInputChunk<T>),
    TwoToOne(HashInputChunk<T>, HashInputChunk<T>),
}

impl<T: Clone> HashInput<T> {
    pub fn len(&self) -> usize {
        match self {
            HashInput::Single(inner) => inner.bytes.len(),
            HashInput::TwoToOne(left, right) => left.bytes.len() + right.bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn to_vec(self) -> Vec<T> {
        match self {
            HashInput::Single(inner) => inner.bytes,
            HashInput::TwoToOne(left, right) => {
                let mut result = left.bytes;
                result.extend(right.bytes);
                result
            }
        }
    }

    pub fn map<B, F: FnMut(T) -> B>(self, f: F) -> HashInput<B> {
        match self {
            HashInput::Single(inner) => HashInput::Single(HashInputChunk {
                bytes: inner.bytes.into_iter().map(f).collect(),
                is_rlc: inner.is_rlc,
            }),
            HashInput::TwoToOne(left, right) => {
                let left_size = left.bytes.len();
                let mut all = left
                    .bytes
                    .into_iter()
                    .chain(right.bytes.into_iter())
                    .map(f)
                    .collect_vec();
                let remainer = all.split_off(left_size);
                let left = HashInputChunk {
                    bytes: all,
                    is_rlc: left.is_rlc,
                };
                let right = HashInputChunk {
                    bytes: remainer,
                    is_rlc: right.is_rlc,
                };

                HashInput::TwoToOne(left, right)
            }
        }
    }
}

impl<F: Field> HashInput<QuantumCell<F>> {
    pub fn into_assigned(self, ctx: &mut Context<F>) -> HashInput<AssignedValue<F>> {
        self.map(|cell| match cell {
            QuantumCell::Existing(v) => v,
            QuantumCell::Witness(v) => ctx.load_witness(v),
            QuantumCell::Constant(v) => ctx.load_constant(v),
            _ => unreachable!(),
        })
    }
}

impl<F: Field> From<HashInput<QuantumCell<F>>> for HashInput<u8> {
    fn from(input: HashInput<QuantumCell<F>>) -> Self {
        input.map(|cell| match cell {
            QuantumCell::Existing(v) => v.value().get_lower_32() as u8,
            QuantumCell::Witness(v) => v.get_lower_32() as u8,
            QuantumCell::Constant(v) => v.get_lower_32() as u8,
            _ => unreachable!(),
        })
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

        HashInput::Single(HashInputChunk {
            bytes: input
                .bytes
                .into_iter()
                .map(|b| QuantumCell::Witness(F::from(b as u64)))
                .collect(),
            is_rlc: input.is_rlc,
        })
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
pub struct HashInputChunk<T> {
    pub bytes: Vec<T>,
    pub is_rlc: bool,
}

impl<T> HashInputChunk<T> {
    pub fn new(bytes: Vec<T>, is_rlc: bool) -> Self {
        Self { bytes, is_rlc }
    }

    pub fn map<B, F: FnMut(T) -> B>(self, f: F) -> HashInputChunk<B> {
        HashInputChunk {
            bytes: self.bytes.into_iter().map(f).collect(),
            is_rlc: self.is_rlc,
        }
    }
}

impl<F: Field, I: Into<HashInputChunk<u8>>> WitnessFrom<I> for HashInputChunk<QuantumCell<F>> {
    fn witness_from(input: I) -> Self {
        let input: HashInputChunk<u8> = input.into();

        HashInputChunk {
            bytes: input
                .bytes
                .into_iter()
                .map(|b| QuantumCell::Witness(F::from(b as u64)))
                .collect(),
            is_rlc: input.is_rlc,
        }
    }
}

impl<F: Field, I: Into<HashInputChunk<u8>>> ConstantFrom<I> for HashInputChunk<QuantumCell<F>> {
    fn constant_from(input: I) -> Self {
        let input: HashInputChunk<u8> = input.into();

        HashInputChunk {
            bytes: input
                .bytes
                .into_iter()
                .map(|b| QuantumCell::Constant(F::from(b as u64)))
                .collect(),
            is_rlc: input.is_rlc,
        }
    }
}

impl From<&[u8]> for HashInputChunk<u8> {
    fn from(input: &[u8]) -> Self {
        HashInputChunk {
            bytes: input.to_vec(),
            is_rlc: input.len() >= 32,
        }
    }
}

impl From<Vec<u8>> for HashInputChunk<u8> {
    fn from(input: Vec<u8>) -> Self {
        let is_rlc = input.len() >= 32;
        HashInputChunk {
            bytes: input,
            is_rlc,
        }
    }
}

impl From<u64> for HashInputChunk<u8> {
    fn from(input: u64) -> Self {
        HashInputChunk {
            bytes: pad_to_ssz_chunk(&input.to_le_bytes()),
            is_rlc: false,
        }
    }
}

impl From<usize> for HashInputChunk<u8> {
    fn from(input: usize) -> Self {
        HashInputChunk {
            bytes: pad_to_ssz_chunk(&input.to_le_bytes()),
            is_rlc: false,
        }
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
        HashInputChunk {
            is_rlc: bytes.len() >= 32,
            bytes,
        }
    }
}
