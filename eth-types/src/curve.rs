use std::array::TryFromSliceError;
use std::iter;

use halo2_ecc::fields::PrimeField;
use halo2_ecc::halo2_base::utils::CurveAffineExt;
use halo2_proofs::arithmetic::Field as Halo2Field;
use halo2curves::CurveExt;
use halo2curves::FieldExt;
use itertools::Itertools;
use pasta_curves::arithmetic::SqrtRatio;
use pasta_curves::group::GroupEncoding;
use pasta_curves::group::UncompressedEncoding;

use crate::Field;

pub trait AppCurveExt: CurveExt<AffineExt: CurveAffineExt> {
    /// Prime field of order $p$ over which the elliptic curves is defined.
    type Fp: PrimeField;
    /// Prime field of order $q = p^k$ where k is the embedding degree.
    type Fq: PrimeField + FieldExt + Halo2Field = Self::Fp;
    /// Affine version of the curve.
    type Affine: CurveAffineExt<Base = Self::Fq>
        + GroupEncoding<Repr = Self::CompressedRepr>
        + UncompressedEncoding<Uncompressed = Self::UnompressedRepr>;
    /// Compressed representation of the curve.
    type CompressedRepr: TryFrom<Vec<u8>, Error = TryFromSliceError>;
    /// Compressed representation of the curve.
    type UnompressedRepr: TryFrom<Vec<u8>, Error = TryFromSliceError>;
    /// Constant $b$ in the curve equation $y^2 = x^3 + b$.
    const B: u64;
    // Bytes needed to encode [`Self::Fq];
    const BYTES_COMPRESSED: usize;
    // Bytes needed to encode curve in uncompressed form.
    const BYTES_UNCOMPRESSED: usize;
    /// Number of bits in a single limb.
    const LIMB_BITS: usize;
    /// Number of limbs in the prime field.
    const NUM_LIMBS: usize;

    fn generator_affine() -> <Self as AppCurveExt>::Affine;

    fn limb_bytes_bases<F: Field>() -> Vec<F> {
        iter::repeat(8)
            .enumerate()
            .map(|(i, x)| i * x)
            .take_while(|&bits| bits <= Self::LIMB_BITS)
            .map(|bits| F::from_u128(1u128 << bits))
            .collect()
    }
}


mod bls12_381 {
    use super::*;
    use halo2curves::bls12_381::{
        Fq, Fq2, G1Affine, G1Compressed, G1Uncompressed, G2Affine, G2Compressed, G2Uncompressed,
        G1, G2,
    };

    impl AppCurveExt for G1 {
        type Affine = G1Affine;
        type Fp = Fq;
        type CompressedRepr = G1Compressed;
        type UnompressedRepr = G1Uncompressed;
        const BYTES_COMPRESSED: usize = 48;
        const BYTES_UNCOMPRESSED: usize = Self::BYTES_COMPRESSED * 2;
        const LIMB_BITS: usize = 112;
        const NUM_LIMBS: usize = 4;
        const B: u64 = 4;

        fn generator_affine() -> G1Affine {
            G1Affine::generator()
        }
    }

    impl AppCurveExt for G2 {
        type Affine = G2Affine;
        type Fp = Fq;
        type Fq = Fq2;
        type CompressedRepr = G2Compressed;
        type UnompressedRepr = G2Uncompressed;
        const BYTES_COMPRESSED: usize = 96;
        const BYTES_UNCOMPRESSED: usize = Self::BYTES_COMPRESSED * 2;
        const LIMB_BITS: usize = 112;
        const NUM_LIMBS: usize = 4;
        const B: u64 = 4;

        fn generator_affine() -> G2Affine {
            G2Affine::generator()
        }
    }
}
