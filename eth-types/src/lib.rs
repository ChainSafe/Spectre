// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

#![feature(trait_alias)]

mod spec;
use halo2_base::utils::BigPrimeField;
use halo2curves::ff::PrimeField;
pub use spec::{Mainnet, Minimal, Spec, Testnet};

pub const NUM_LIMBS: usize = 5;
pub const LIMB_BITS: usize = 104;

/// The field used in circuits.
pub trait Field = BigPrimeField + PrimeField<Repr = [u8; 32]>;
