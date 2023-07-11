use core::fmt::Debug;

pub trait Spec: 'static + Default + Debug {
    const VALIDATOR_REGISTRY_LIMIT: usize;
    const VALIDATOR_0_G_INDEX: usize;
    const VALIDATOR_SSZ_CHUNKS: usize;
    const USED_CHUNKS_PER_VALIDATOR: usize;
    const STATE_TREE_DEPTH: usize; 
    const STATE_TREE_LEVEL_PUBKEYS: usize;
    const STATE_TREE_LEVEL_VALIDATORS: usize;
    const G1_FQ_BYTES: usize;
    const G1_BYTES_UNCOMPRESSED: usize;
    const LIMB_BITS: usize;
    const NUM_LIMBS: usize;
}

/// Ethereum Foundation specifications.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Test;

impl Spec for Test {

    const VALIDATOR_REGISTRY_LIMIT: usize = 100;
    const VALIDATOR_0_G_INDEX: usize = 32;
    const VALIDATOR_SSZ_CHUNKS: usize = 8;
    const USED_CHUNKS_PER_VALIDATOR: usize = 5;
    const STATE_TREE_DEPTH: usize = 10;
    const STATE_TREE_LEVEL_PUBKEYS: usize = 10;
    const STATE_TREE_LEVEL_VALIDATORS: usize = Self::STATE_TREE_LEVEL_PUBKEYS - 1;
    const G1_FQ_BYTES: usize = 32; // TODO: 48 for BLS12-381.
    const G1_BYTES_UNCOMPRESSED: usize = Self::G1_FQ_BYTES * 2;
    const LIMB_BITS: usize = 88;
    const NUM_LIMBS: usize = 3;
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Mainnet;

impl Spec for Mainnet {
    const VALIDATOR_REGISTRY_LIMIT: usize = 1099511627776;
    const VALIDATOR_0_G_INDEX: usize = 94557999988736;
    const VALIDATOR_SSZ_CHUNKS: usize = 9;
    const USED_CHUNKS_PER_VALIDATOR: usize = 5;
    const STATE_TREE_DEPTH: usize = 47;
    // TODO: calculate and verify the pubkeys level for mainnet
    const STATE_TREE_LEVEL_PUBKEYS: usize = 49;
    const STATE_TREE_LEVEL_VALIDATORS: usize = Self::STATE_TREE_LEVEL_PUBKEYS - 1;
    const G1_FQ_BYTES: usize = 48;
    const G1_BYTES_UNCOMPRESSED: usize = Self:: G1_FQ_BYTES * 2;
    const LIMB_BITS: usize = 112;
    const NUM_LIMBS: usize = 5;
}
