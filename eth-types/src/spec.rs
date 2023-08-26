use core::fmt::Debug;

pub trait Spec: 'static + Sized + Copy + Default + Debug {
    const SYNC_COMMITTEE_SIZE: usize;
    const DST: &'static [u8];
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
    const SYNC_COMMITTEE_SIZE: usize = 512;
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
}
