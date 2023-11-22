use crate::gadget::crypto::constant_randomness;
use eth_types::{Field, Spec};
use itertools::Itertools;
use std::iter;
use std::marker::PhantomData;
use sync_committee_primitives::consensus_types::BeaconBlockHeader;

#[derive(Debug, Clone)]
pub struct CommitteeRotationArgs<S: Spec, F: Field> {
    pub pubkeys_compressed: Vec<Vec<u8>>,

    pub finalized_header: BeaconBlockHeader,

    pub sync_committee_branch: Vec<Vec<u8>>,

    pub randomness: F,

    pub _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> Default for CommitteeRotationArgs<S, F> {
    fn default() -> Self {
        let dummy_x_bytes = iter::once(192).pad_using(48, |_| 0).rev().collect();

        let sync_committee_branch = vec![vec![0; 32]; S::SYNC_COMMITTEE_DEPTH + 1];

        Self {
            pubkeys_compressed: iter::repeat(dummy_x_bytes)
                .take(S::SYNC_COMMITTEE_SIZE)
                .collect_vec(),
            sync_committee_branch,
            randomness: constant_randomness(),
            finalized_header: Default::default(),
            _spec: PhantomData,
        }
    }
}
