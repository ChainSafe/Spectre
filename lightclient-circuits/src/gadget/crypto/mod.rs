mod builder;
mod ecc;
// mod hash2curve;
mod sha256_flex;
// mod sha256_wide;

pub use builder::{SHAConfig, ShaCircuitBuilder};
use eth_types::Field;
use halo2_base::{AssignedValue, QuantumCell};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bls12_381::{Fp2Chip, Fp2Point, FpChip},
    ecc::{EcPoint, EccChip},
    fields::{fp2, vector::FieldVector, FieldExtConstructor},
};
use lazy_static::lazy_static;
pub use sha256_flex::{Sha256Chip, ShaContexts, ShaThreadBuilder};
// pub use sha256_wide::{Sha256ChipWide, ShaBitThreadBuilder};

pub use ecc::calculate_ysquared;

use crate::witness::HashInput;
pub type G1Point<F> = EcPoint<F, ProperCrtUint<F>>;
pub type G2Point<F> = EcPoint<F, Fp2Point<F>>;

#[allow(type_alias_bounds)]
pub type G1Chip<'chip, F> = EccChip<'chip, F, FpChip<'chip, F>>;

#[allow(type_alias_bounds)]
pub type G2Chip<'chip, F> = EccChip<'chip, F, Fp2Chip<'chip, F>>;

pub use halo2_ecc::ecc::hash_to_curve::HashInstructions;

#[derive(Debug, Clone)]
pub struct AssignedHashResult<F: Field> {
    // pub input_len: AssignedValue<F>,
    pub input_bytes: Vec<AssignedValue<F>>,
    pub output_bytes: [AssignedValue<F>; 32],
}

// This is a temporary measure. TODO: use challenges API.
pub fn constant_randomness<F: Field>() -> F {
    F::from_u128(0xca9d6022267d3bd658bf)
}
