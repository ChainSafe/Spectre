mod builder;
mod hash2curve;
mod sha256;
mod sha256_wide;
mod util;
mod ecc;

pub use builder::{SHAConfig, ShaCircuitBuilder};
use eth_types::{AppCurveExt, Field, HashCurveExt};
use halo2_base::{safe_types::RangeChip, AssignedValue, QuantumCell};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bls12_381::{Fp2Chip, FpChip},
    ecc::{EcPoint, EccChip},
    fields::{fp2, vector::FieldVector, FieldExtConstructor},
};
use halo2_proofs::plonk::Error;
pub use hash2curve::{HashToCurveCache, HashToCurveChip};
use lazy_static::lazy_static;
pub use sha256::{Sha256Chip, ShaContexts, ShaThreadBuilder};
pub use sha256_wide::{Sha256ChipWide, ShaBitThreadBuilder};

pub use ecc::calculate_ysquared;

use crate::{util::ThreadBuilderBase, witness::HashInput};
pub type FpPoint<F> = ProperCrtUint<F>;
pub type Fp2Point<F> = FieldVector<FpPoint<F>>;
pub type G1Point<F> = EcPoint<F, ProperCrtUint<F>>;
pub type G2Point<F> = EcPoint<F, Fp2Point<F>>;

#[allow(type_alias_bounds)]
pub type G1Chip<'chip, F> = EccChip<'chip, F, FpChip<'chip, F>>;

#[allow(type_alias_bounds)]
pub type G2Chip<'chip, F> = EccChip<'chip, F, Fp2Chip<'chip, F>>;

pub trait HashInstructions<F: Field, ThreadBuilder: ThreadBuilderBase<F> = ShaThreadBuilder<F>> {
    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;

    /// Digests input using hash function and returns finilized output.
    /// `MAX_INPUT_SIZE` is the maximum size of input that can be processed by the hash function.
    /// `strict` flag indicates whether to perform range check on input bytes.
    fn digest<const MAX_INPUT_SIZE: usize>(
        &self,
        thread_pool: &mut ThreadBuilder,
        input: HashInput<QuantumCell<F>>,
        strict: bool,
    ) -> Result<AssignedHashResult<F>, Error>;

    fn range(&self) -> &RangeChip<F>;
}

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
