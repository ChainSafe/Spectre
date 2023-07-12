use core::fmt::Debug;

use halo2curves::{bls12_381, bn256, CurveExt};

pub trait Spec: 'static + Default + Debug {
    const VALIDATOR_REGISTRY_LIMIT: usize;
    const MAX_VALIDATORS_PER_COMMITTEE: usize;
    const MAX_COMMITTEES_PER_SLOT: usize;
    const SLOTS_PER_EPOCH: usize;
    const VALIDATOR_0_G_INDEX: usize;
    const VALIDATOR_SSZ_CHUNKS: usize;
    const USED_CHUNKS_PER_VALIDATOR: usize;
    const STATE_TREE_DEPTH: usize;
    const STATE_TREE_LEVEL_PUBKEYS: usize;
    const STATE_TREE_LEVEL_VALIDATORS: usize;
    const G1_BYTES_COMPRESSED: usize;
    const G1_BYTES_UNCOMPRESSED: usize;
    const G2_BYTES_COMPRESSED: usize;
    const LIMB_BITS: usize;
    const NUM_LIMBS: usize;
    type PubKeysCurve: CurveExt;
    type SiganturesCurve: CurveExt;
}

/// Ethereum Foundation specifications.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Test;

impl Spec for Test {
    const VALIDATOR_REGISTRY_LIMIT: usize = 100;
    const MAX_VALIDATORS_PER_COMMITTEE: usize = 10;
    const MAX_COMMITTEES_PER_SLOT: usize = 5;
    const SLOTS_PER_EPOCH: usize = 32;
    const VALIDATOR_0_G_INDEX: usize = 32;
    const VALIDATOR_SSZ_CHUNKS: usize = 8;
    const USED_CHUNKS_PER_VALIDATOR: usize = 5;
    const STATE_TREE_DEPTH: usize = 10;
    const STATE_TREE_LEVEL_PUBKEYS: usize = 10;
    const STATE_TREE_LEVEL_VALIDATORS: usize = Self::STATE_TREE_LEVEL_PUBKEYS - 1;
    const G1_BYTES_COMPRESSED: usize = 32; // TODO: 48 for BLS12-381.
    const G1_BYTES_UNCOMPRESSED: usize = Self::G1_BYTES_COMPRESSED * 2;
    const G2_BYTES_COMPRESSED: usize = Self::G1_BYTES_COMPRESSED * 2;
    const LIMB_BITS: usize = 88;
    const NUM_LIMBS: usize = 3;
    type PubKeysCurve = bn256::G1;
    type SiganturesCurve = bn256::G2;
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Mainnet;

impl Spec for Mainnet {
    const VALIDATOR_REGISTRY_LIMIT: usize = 1099511627776;
    const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
    const MAX_COMMITTEES_PER_SLOT: usize = 64;
    const SLOTS_PER_EPOCH: usize = 32;
    const VALIDATOR_0_G_INDEX: usize = 94557999988736;
    const VALIDATOR_SSZ_CHUNKS: usize = 9;
    const USED_CHUNKS_PER_VALIDATOR: usize = 5;
    const STATE_TREE_DEPTH: usize = 47;
    // TODO: calculate and verify the pubkeys level for mainnet
    const STATE_TREE_LEVEL_PUBKEYS: usize = 49;
    const STATE_TREE_LEVEL_VALIDATORS: usize = Self::STATE_TREE_LEVEL_PUBKEYS - 1;
    const G1_BYTES_COMPRESSED: usize = 48;
    const G1_BYTES_UNCOMPRESSED: usize = Self::G1_BYTES_COMPRESSED * 2;
    const G2_BYTES_COMPRESSED: usize = Self::G1_BYTES_COMPRESSED * 2;
    const LIMB_BITS: usize = 112;
    const NUM_LIMBS: usize = 5;
    type PubKeysCurve = bls12_381::G1;
    type SiganturesCurve = bls12_381::G2;
}
