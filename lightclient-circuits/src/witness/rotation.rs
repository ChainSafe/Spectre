use std::iter;
use std::marker::PhantomData;

use crate::gadget::crypto::constant_randomness;

use super::{HashInput, Validator};
use eth_types::AppCurveExt;
use eth_types::{Field, Spec};
use ethereum_consensus::bellatrix::mainnet;
use ethereum_consensus::bellatrix::BeaconState;
use ethereum_consensus::capella;
use ethereum_consensus::phase0::BeaconBlockHeader;
use halo2curves::bls12_381::Fq;
use halo2curves::bls12_381::G1;
use itertools::Itertools;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ssz_rs::Merkleized;
use ssz_rs::Node;

#[derive(Debug, Clone)]
pub struct CommitteeRotationArgs<S: Spec, F: Field> {
    pub pubkeys_compressed: Vec<Vec<u8>>,

    pub randomness: F,

    pub _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> Default for CommitteeRotationArgs<S, F> {
    fn default() -> Self {
        let dummy_x_bytes = iter::once(192).pad_using(48, |_| 0).rev().collect();

        Self {
            pubkeys_compressed: iter::repeat(dummy_x_bytes)
                .take(S::SYNC_COMMITTEE_SIZE)
                .collect_vec(),
            randomness: constant_randomness(),
            _spec: PhantomData,
        }
    }
}
