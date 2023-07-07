#![feature(associated_type_bounds)]
#![feature(inherent_associated_types)]
pub(crate) mod gadget;
pub mod table;
pub(crate) mod util;
pub mod witness;

pub mod aggregation_circuit;
pub mod sha256_circuit;
pub mod state_circuit;
pub mod super_circuit;
pub mod validators_circuit;

// TODO: impl as Spec trait
// example: https://github.com/ChainSafe/Zipline/blob/main/finality-client/libs/zipline-spec/src/lib.rs

pub const MAX_VALIDATORS: usize = 100;

pub const VALIDATOR0_GINDEX: usize = 32;

pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

pub(crate) const N_BYTES_U64: usize = 8;

pub trait Spec {
    const MAX_VALIDATORS: usize;
}

struct MainnetSpec;

impl Spec for MainnetSpec {
    const MAX_VALIDATORS: usize = 100;
}
