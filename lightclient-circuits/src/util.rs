//! Common utility traits and functions.

mod common;
pub use common::*;

mod conversion;
pub(crate) use conversion::*;

mod proof;
pub use proof::*;

mod circuit;
pub use circuit::*;

use eth_types::*;

pub fn bigint_to_le_bytes<F: Field>(
    limbs: impl IntoIterator<Item = F>,
    limb_bits: usize,
    total_bytes: usize,
) -> Vec<u8> {
    let limb_bytes = limb_bits / 8;
    limbs
        .into_iter()
        .flat_map(|x| x.to_bytes_le()[..limb_bytes].to_vec())
        .take(total_bytes)
        .collect()
}

pub fn pad_to_ssz_chunk(le_bytes: &[u8]) -> Vec<u8> {
    assert!(le_bytes.len() <= 32);
    let mut chunk = le_bytes.to_vec();
    chunk.resize(32, 0);
    chunk
}
