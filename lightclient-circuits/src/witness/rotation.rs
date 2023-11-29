use eth_types::Spec;
use ethereum_consensus_types::BeaconBlockHeader;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{iter, marker::PhantomData};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeRotationArgs<S: Spec> {
    pub pubkeys_compressed: Vec<Vec<u8>>,

    pub finalized_header: BeaconBlockHeader,

    pub sync_committee_branch: Vec<Vec<u8>>,

    pub _spec: PhantomData<S>,
}

impl<S: Spec> Default for CommitteeRotationArgs<S> {
    fn default() -> Self {
        let dummy_x_bytes = iter::once(192).pad_using(48, |_| 0).rev().collect();

        let sync_committee_branch = vec![vec![0; 32]; S::SYNC_COMMITTEE_DEPTH + 1];

        Self {
            pubkeys_compressed: iter::repeat(dummy_x_bytes)
                .take(S::SYNC_COMMITTEE_SIZE)
                .collect_vec(),
            sync_committee_branch,
            finalized_header: Default::default(),
            _spec: PhantomData,
        }
    }
}
