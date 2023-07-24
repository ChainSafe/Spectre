use super::Validator;
use eth_types::Spec;
pub use ethereum_consensus::phase0::{Attestation as SszAttestation, AttestationData};
use halo2curves::{
    bls12_381::{G1Affine, G2Affine},
    group::{prime::PrimeCurveAffine, Curve, GroupEncoding},
};
use pasta_curves::group::UncompressedEncoding;
use ssz_rs::Merkleized;

#[allow(type_alias_bounds)]
pub type Attestation<S: Spec> = SszAttestation<{ S::MAX_VALIDATORS_PER_COMMITTEE }>;
