use core::fmt::Debug;

use crate::Field;

pub trait Spec: 'static + Sized + Copy + Default + Debug {
    const SYNC_COMMITTEE_SIZE: usize;
    const DST: &'static [u8];

    // Number of digits containing the participation bits per committee for a given field element.
    // ceil(Self::SYNC_COMMITTEE_SIZE / F::NUM_BITS)
    fn participation_digits_len<F: Field>() -> usize {
        (Self::SYNC_COMMITTEE_SIZE + F::NUM_BITS as usize - 1) / F::NUM_BITS as usize
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Test;

impl Spec for Test {
    const SYNC_COMMITTEE_SIZE: usize = 512;
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Mainnet;

impl Spec for Mainnet {
    const SYNC_COMMITTEE_SIZE: usize = 2048;
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
}
