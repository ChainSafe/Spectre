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

    pub finality_branch: Vec<Vec<u8>>,

    pub execution_payload_root: Vec<u8>,

    pub execution_payload_branch: Vec<Vec<u8>>,

    pub domain: [u8; 32],

    #[serde(skip)]
    pub _spec: PhantomData<S>,
}

impl<S: Spec> Default for SyncStepArgs<S> {
    fn default() -> Self {
        let dummy_pk_bytes = hex::decode("021c62a0dfdfe89b5fa924d54d2ec12552aa53796ab7dc984fa8219f7042d46334b15fb2f0c6e4095b8a1e2fe551f1f50a90d7a76329d83176114c81b460de399923b3cb9b3c1020b8ca228163c5d62a577073b2d0478b5f72cedc7a17eaad52").unwrap();
        let signature_compressed = hex::decode("aabe63f791d9d80aa5c5ff9a384be8ba8a61a66e9bc9e82b7f1774639b125de5de476b533b1b522e75d4bd93ad2a405a03f71fe3daf9cae3685a6b8dc9adf4b89403203ab0e081c694aa8665492a70464cdae666a168a5ea55237268cb5a2c46").unwrap();

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
            signature_compressed,
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
