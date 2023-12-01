use eth_types::Spec;
use ethereum_consensus_types::BeaconBlockHeader;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{iter, marker::PhantomData};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeRotationArgs<S: Spec> {
    pub pubkeys_compressed: Vec<Vec<u8>>,

    pub finalized_header: BeaconBlockHeader,

    pub sync_committee_branch: Vec<Vec<u8>>,

    #[serde(skip)]
    pub _spec: PhantomData<S>,
}

impl<S: Spec> Default for CommitteeRotationArgs<S> {
    fn default() -> Self {
        let dummy_x_bytes = iter::once(192).pad_using(48, |_| 0).rev().collect_vec();

        let sync_committee_branch = vec![vec![0; 32]; S::SYNC_COMMITTEE_PUBKEYS_DEPTH];

        let hashed_pk = sha2::Sha256::digest(
            &dummy_x_bytes
                .iter()
                .copied()
                .pad_using(64, |_| 0)
                .collect_vec(),
        )
        .to_vec();

        assert!(S::SYNC_COMMITTEE_SIZE.is_power_of_two());

        let mut chunks = vec![hashed_pk; S::SYNC_COMMITTEE_SIZE];

        while chunks.len() > 1 {
            chunks = chunks
                .into_iter()
                .tuples()
                .map(|(left, right)| sha2::Sha256::digest(&[left, right].concat()).to_vec())
                .collect();
        }

        let committee_root = chunks.pop().unwrap();

        let state_root = mock_root(
            committee_root,
            &sync_committee_branch,
            S::SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX,
        );

        Self {
            pubkeys_compressed: iter::repeat(dummy_x_bytes)
                .take(S::SYNC_COMMITTEE_SIZE)
                .collect_vec(),
            sync_committee_branch,
            finalized_header: BeaconBlockHeader {
                state_root: state_root.as_slice().try_into().unwrap(),
                ..Default::default()
            },
            _spec: PhantomData,
        }
    }
}

pub(crate) fn mock_root(leaf: Vec<u8>, branch: &[Vec<u8>], mut gindex: usize) -> Vec<u8> {
    let mut last_hash = leaf;

    for i in 0..branch.len() {
        last_hash = Sha256::digest(
            &if gindex % 2 == 0 {
                [last_hash, branch[i].clone()]
            } else {
                [branch[i].clone(), last_hash]
            }
            .concat(),
        )
        .to_vec();
        gindex /= 2;
    }

    last_hash
}
