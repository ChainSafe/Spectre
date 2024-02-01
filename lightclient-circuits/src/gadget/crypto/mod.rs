// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

mod builder;
mod ecc;

mod sha256_flex;
mod sha256_wide;

pub use builder::{SHAConfig, ShaCircuitBuilder};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bls12_381::{Fp2Chip, Fp2Point, FpChip},
    ecc::{EcPoint, EccChip},
};
pub use sha256_flex::{Sha256Chip, ShaContexts, ShaFlexGateManager, SpreadConfig};
pub use sha256_wide::{Sha256ChipWide, ShaBitGateManager};

pub use ecc::calculate_ysquared;

pub type G1Point<F> = EcPoint<F, ProperCrtUint<F>>;
pub type G2Point<F> = EcPoint<F, Fp2Point<F>>;

#[allow(type_alias_bounds)]
pub type G1Chip<'chip, F> = EccChip<'chip, F, FpChip<'chip, F>>;

#[allow(type_alias_bounds)]
pub type G2Chip<'chip, F> = EccChip<'chip, F, Fp2Chip<'chip, F>>;

pub use halo2_ecc::ecc::hash_to_curve::HashInstructions;
