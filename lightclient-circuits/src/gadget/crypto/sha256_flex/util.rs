use eth_types::Field;
use halo2_base::utils::{biguint_to_fe, fe_to_biguint};
use halo2_proofs::circuit::AssignedCell;
use itertools::Itertools;
use num_bigint::BigUint;

use crate::{util::AssignedValueCell, witness::HashInput};

pub fn fe_to_bits_le<F: Field>(val: &F, size: usize) -> Vec<bool> {
    let val_bytes = fe_to_biguint(val).to_bytes_le();
    let mut bits = val_bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
        .collect_vec();
    bits.extend_from_slice(&vec![false; size - bits.len()]);
    bits
}

pub fn bits_le_to_fe<F: Field>(bits: &[bool]) -> F {
    let bytes = bits
        .chunks(8)
        .map(|bits| {
            let mut byte = 0u8;
            for idx in 0..8 {
                if bits[idx] {
                    byte += 1 << idx;
                }
            }
            byte
        })
        .collect_vec();
    biguint_to_fe(&BigUint::from_bytes_le(&bytes))
}
