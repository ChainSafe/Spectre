mod builder;
mod ecc;

mod sha256_flex;
mod sha256_wide;

pub use builder::{SHAConfig, ShaCircuitBuilder};
use eth_types::Field;
use halo2_ecc::{
    bigint::ProperCrtUint,
    bls12_381::{Fp2Chip, Fp2Point, FpChip},
    ecc::{EcPoint, EccChip},
};
pub use sha256_flex::{Sha256Chip, ShaContexts, ShaFlexGateManager};
pub use sha256_wide::{Sha256ChipWide, ShaBitGateManager};

pub use ecc::calculate_ysquared;

pub type G1Point<F> = EcPoint<F, ProperCrtUint<F>>;
pub type G2Point<F> = EcPoint<F, Fp2Point<F>>;

#[allow(type_alias_bounds)]
pub type G1Chip<'chip, F> = EccChip<'chip, F, FpChip<'chip, F>>;

#[allow(type_alias_bounds)]
pub type G2Chip<'chip, F> = EccChip<'chip, F, Fp2Chip<'chip, F>>;

pub use halo2_ecc::ecc::hash_to_curve::HashInstructions;

// This is a temporary measure. TODO: use challenges API.
pub fn constant_randomness<F: Field>() -> F {
    F::from_u128(0xca9d6022267d3bd658bf)
}
