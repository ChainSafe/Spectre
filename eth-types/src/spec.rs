use core::fmt::Debug;

use halo2curves::bls12_381;

use crate::curve::AppCurveExt;
use crate::curve::HashCurveExt;
use crate::Field;

pub trait Spec: 'static + Sized + Copy + Default + Debug {
    const VALIDATOR_REGISTRY_LIMIT: usize;
    const MAX_VALIDATORS_PER_COMMITTEE: usize;
    const MAX_COMMITTEES_PER_SLOT: usize;
    const SLOTS_PER_EPOCH: usize;
    const VALIDATOR_0_GINDEX: usize;
    const STATE_TREE_DEPTH: usize;
    const STATE_TREE_LEVEL_PUBKEYS: usize;
    const STATE_TREE_LEVEL_VALIDATORS: usize;
    const STATE_TREE_LEVEL_BEACON_STATE: usize;
    const DST: &'static [u8];

    type PubKeysCurve: AppCurveExt;
    type SiganturesCurve: AppCurveExt<Fp = <Self::PubKeysCurve as AppCurveExt>::Fq> + HashCurveExt;

    // Number of digits containing the attestation bits per committee for a given field element.
    // ceil(Self::MAX_VALIDATORS_PER_COMMITTEE / F::NUM_BITS)
    fn attest_digits_len<F: Field>() -> usize {
        (Self::MAX_VALIDATORS_PER_COMMITTEE + F::NUM_BITS as usize - 1) / F::NUM_BITS as usize
    }
}

/// Ethereum Foundation specifications.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Test;

impl Spec for Test {
    const VALIDATOR_REGISTRY_LIMIT: usize = 100;
    const MAX_VALIDATORS_PER_COMMITTEE: usize = 5;
    const MAX_COMMITTEES_PER_SLOT: usize = 1;
    const SLOTS_PER_EPOCH: usize = 1;
    const VALIDATOR_0_GINDEX: usize = 94557999988736;
    const STATE_TREE_DEPTH: usize = 51;
    const STATE_TREE_LEVEL_PUBKEYS: usize = Self::STATE_TREE_DEPTH;
    const STATE_TREE_LEVEL_VALIDATORS: usize = Self::STATE_TREE_LEVEL_PUBKEYS - 1;
    const STATE_TREE_LEVEL_BEACON_STATE: usize = 6;
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    type PubKeysCurve = bls12_381::G1;
    type SiganturesCurve = bls12_381::G2;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Mainnet;

impl Spec for Mainnet {
    const VALIDATOR_REGISTRY_LIMIT: usize = 1099511627776;
    const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
    const MAX_COMMITTEES_PER_SLOT: usize = 64;
    const SLOTS_PER_EPOCH: usize = 32;
    const VALIDATOR_0_GINDEX: usize = 94557999988736;
    const STATE_TREE_DEPTH: usize = 51;
    const STATE_TREE_LEVEL_PUBKEYS: usize = Self::STATE_TREE_DEPTH;
    const STATE_TREE_LEVEL_VALIDATORS: usize = Self::STATE_TREE_LEVEL_PUBKEYS - 1;
    const STATE_TREE_LEVEL_BEACON_STATE: usize = 6;
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    type PubKeysCurve = bls12_381::G1;
    type SiganturesCurve = bls12_381::G2;
}
