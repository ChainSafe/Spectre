mod cached_hash;
mod hash2curve;
mod sha256;
mod util;

pub use cached_hash::CachedHashChip;
use eth_types::HashCurveExt;
use halo2_ecc::{bigint::ProperCrtUint, ecc::EcPoint, fields::vector::FieldVector};
pub use sha256::{AssignedHashResult, HashChip, Sha256Chip};

pub type FpPoint<F> = ProperCrtUint<F>;
pub type Fp2Point<F> = FieldVector<FpPoint<F>>;
pub type G1Point<F> = EcPoint<F, ProperCrtUint<F>>;
pub type G2Point<F> = EcPoint<F, Fp2Point<F>>;

#[allow(type_alias_bounds)]
pub type FpChip<'chip, F, C: HashCurveExt> = halo2_ecc::fields::fp::FpChip<'chip, F, C::Fp>;
#[allow(type_alias_bounds)]
pub type Fp2Chip<'chip, F, C: HashCurveExt> =
    halo2_ecc::fields::fp2::Fp2Chip<'chip, F, FpChip<'chip, F, C>, C::Fq>;
#[allow(type_alias_bounds)]
pub type EccChip<'chip, F, C: HashCurveExt> =
    halo2_ecc::ecc::EccChip<'chip, F, Fp2Chip<'chip, F, C>>;
