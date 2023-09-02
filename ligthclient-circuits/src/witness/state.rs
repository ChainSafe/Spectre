use std::marker::PhantomData;

use crate::sha256_circuit::Sha256CircuitConfig;

use super::{validators, HashInput};
use super::{MerkleTrace, Validator};
use eth_types::{Field, Spec};
use ethereum_consensus::bellatrix::mainnet;
use ethereum_consensus::bellatrix::BeaconState;
use ethereum_consensus::phase0::BeaconBlockHeader;
use serde::Deserialize;
use ssz_rs::Merkleized;

/// SyncState is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SyncState {
    pub target_epoch: u64,

    pub sync_committee: Vec<Validator>,

    pub sync_signature: Vec<u8>,

    pub attested_block: BeaconBlockHeader,

    pub domain: [u8; 32],

    pub merkle_trace: MerkleTrace,

    // pub sha256_inputs: Vec<HashInput<u8>>,

    pub exec_merkle_branch: Vec<Vec<u8>>,

    pub state_merkle_branch: Vec<Vec<u8>>,

    pub state_root: [u8; 32],
}

