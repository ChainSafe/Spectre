use core::fmt::Debug;

pub trait Spec: 'static + Sized + Copy + Default + Debug {
    const SYNC_COMMITTEE_SIZE: usize;
    const DST: &'static [u8];
    const EXECUTION_STATE_ROOT_INDEX: usize;
    const EXECUTION_STATE_ROOT_DEPTH: usize;
    const FINALIZED_HEADER_INDEX: usize;
    const FINALIZED_HEADER_DEPTH: usize;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Minimal;

impl Spec for Minimal {
    const SYNC_COMMITTEE_SIZE: usize = 32;
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const EXECUTION_STATE_ROOT_INDEX: usize = 402;
    const EXECUTION_STATE_ROOT_DEPTH: usize = 8;
    const FINALIZED_HEADER_INDEX: usize = 105;
    const FINALIZED_HEADER_DEPTH: usize = 6;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Test;

impl Spec for Test {
    const SYNC_COMMITTEE_SIZE: usize = 512;
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const EXECUTION_STATE_ROOT_INDEX: usize = 402;
    const EXECUTION_STATE_ROOT_DEPTH: usize = 8;
    const FINALIZED_HEADER_INDEX: usize = 105;
    const FINALIZED_HEADER_DEPTH: usize = 6;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Mainnet;

impl Spec for Mainnet {
    const SYNC_COMMITTEE_SIZE: usize = 512;
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const EXECUTION_STATE_ROOT_INDEX: usize = 402;
    const EXECUTION_STATE_ROOT_DEPTH: usize = 8;
    const FINALIZED_HEADER_INDEX: usize = 105;
    const FINALIZED_HEADER_DEPTH: usize = 6;
}
