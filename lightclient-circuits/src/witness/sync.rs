use std::iter;
use std::marker::PhantomData;

use super::HashInput;
use eth_types::{Field, Spec};
use itertools::Itertools;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ssz_rs::{Merkleized, Node};
use sync_committee_primitives::consensus_types::{BeaconBlockHeader, BeaconState};

#[derive(Debug, Clone, Deserialize)]
pub struct SyncStepArgs<S: Spec> {
    pub signature_compressed: Vec<u8>,

    pub pubkeys_uncompressed: Vec<Vec<u8>>,

    pub pariticipation_bits: Vec<bool>,

    pub attested_header: BeaconBlockHeader,

    pub finalized_header: BeaconBlockHeader,

    pub domain: [u8; 32],

    pub execution_payload_branch: Vec<Vec<u8>>,

    pub execution_payload_root: Vec<u8>,

    pub finality_branch: Vec<Vec<u8>>,

    #[serde(skip)]
    pub _spec: PhantomData<S>,
}

impl<S: Spec> Default for SyncStepArgs<S> {
    fn default() -> Self {
        let dummy_pk_bytes = hex::decode("f5f151e52f1e8a5b09e4c6f0b25fb13463d442709f21a84f98dcb76a7953aa5225c12e4dd524a95f9be8dfdfa0621c0252adea177adcce725f8b47d0b27370572ad6c5638122cab820103c9bcbb3239939de60b4814c117631d82963a7d7900a").unwrap();

        let state_merkle_branch = iter::repeat(vec![0u8; 32])
            .take(S::FINALIZED_HEADER_DEPTH)
            .collect_vec();

        let compute_root = |leaf: Vec<u8>, branch: &[Vec<u8>]| -> Vec<u8> {
            let mut last_hash = Sha256::digest([leaf, branch[0].clone()].concat()).to_vec();

            for i in 1..branch.len() {
                last_hash = Sha256::digest([last_hash, branch[i].clone()].concat()).to_vec();
            }

            last_hash
        };

        let execution_state_root = vec![0; 32];
        let execution_merkle_branch = vec![vec![0; 32]; S::EXECUTION_STATE_ROOT_DEPTH];
        let beacon_block_body_root =
            compute_root(execution_state_root.clone(), &state_merkle_branch);

        let mut finalized_block = BeaconBlockHeader {
            body_root: Node::from_bytes(beacon_block_body_root.try_into().unwrap()),
            ..Default::default()
        };
        let finalized_header = finalized_block.hash_tree_root().unwrap().as_ref().to_vec();

        let finality_merkle_branch = vec![vec![0; 32]; S::FINALIZED_HEADER_DEPTH];

        Self {
            signature_compressed: hex::decode("462c5acb68722355eaa568a166e6da4c46702a496586aa94c681e0b03a200394b8f4adc98d6b5a68e3caf9dae31ff7035a402aad93bdd4752e521b3b536b47dee55d129b6374177f2be8c99b6ea6618abae84b389affc5a50ad8d991f763beaa").unwrap(),
            pubkeys_uncompressed: iter::repeat(dummy_pk_bytes)
                .take(S::SYNC_COMMITTEE_SIZE)
                .collect_vec(),
            pariticipation_bits: vec![true; S::SYNC_COMMITTEE_SIZE],
            domain: [
                7, 0, 0, 0, 48, 83, 175, 74, 95, 250, 246, 166, 104, 40, 151, 228, 42, 212, 194, 8,
                48, 56, 232, 147, 61, 9, 41, 204, 88, 234, 56, 134,
            ],
            attested_header: BeaconBlockHeader::default(),
            finalized_header: finalized_block,
            finality_branch: finality_merkle_branch,
            execution_payload_branch: execution_merkle_branch,
            execution_payload_root: execution_state_root,
            _spec: PhantomData,
        }
    }
}
