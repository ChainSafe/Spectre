mod hash2curve;
mod sha256;
mod sha256_wide;
mod util;

use eth_types::{AppCurveExt, HashCurveExt};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bls12_381::{Fp2Chip, FpChip},
    ecc::{EcPoint, EccChip},
    fields::{fp2, vector::FieldVector, FieldExtConstructor},
};
// pub use hash2curve::{HashToCurveCache, HashToCurveChip};
pub use sha256::{AssignedHashResult, HashChip, Sha256Chip, SpreadConfig};
pub use sha256_wide::*;
pub type FpPoint<F> = ProperCrtUint<F>;
pub type Fp2Point<F> = FieldVector<FpPoint<F>>;
pub type G1Point<F> = EcPoint<F, ProperCrtUint<F>>;
pub type G2Point<F> = EcPoint<F, Fp2Point<F>>;

#[allow(type_alias_bounds)]
pub type G1Chip<'chip, F> = EccChip<'chip, F, FpChip<'chip, F>>;

#[allow(type_alias_bounds)]
pub type G2Chip<'chip, F> = EccChip<'chip, F, Fp2Chip<'chip, F>>;
