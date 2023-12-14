#![allow(incomplete_features)]
#![feature(associated_type_bounds)]
#![feature(associated_type_defaults)]
#![feature(generic_const_exprs)]
#![feature(trait_alias)]
mod spec;
use halo2_base::utils::BigPrimeField;
use halo2curves::ff::PrimeField;
pub use spec::{Mainnet, Minimal, Spec, Testnet};

pub const NUM_LIMBS: usize = 4;
pub const LIMB_BITS: usize = 104;

/// The field used in circuits.
pub trait Field = BigPrimeField + PrimeField<Repr = [u8; 32]>;
