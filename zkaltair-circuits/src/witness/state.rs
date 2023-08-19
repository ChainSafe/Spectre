use std::marker::PhantomData;

use crate::sha256_circuit::Sha256CircuitConfig;

use super::{validators, HashInput};
use super::{MerkleTrace, Validator};
use eth_types::{Field, Spec};
use ethereum_consensus::bellatrix::mainnet;
use ethereum_consensus::bellatrix::BeaconState;
use serde::Deserialize;
use ssz_rs::Merkleized;

/// SyncState is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default)]
pub struct SyncState<S: Spec, F: Field> {
    pub randomness: F,

    pub target_epoch: u64,

    pub sync_committee: Vec<Validator>,

    pub sync_signature: Vec<u8>,

    pub attested_header: [u8; 32],

    pub merkle_trace: MerkleTrace,

    pub sha256_inputs: Vec<HashInput<u8>>,

    pub state_root: [u8; 32],

    _s: PhantomData<S>,
}

/// SyncState is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SyncStateInput {
    pub target_epoch: u64,

    pub sync_committee: Vec<Validator>,

    pub sync_signature: Vec<u8>,

    pub attested_header: [u8; 32],

    pub merkle_trace: MerkleTrace,
}

impl<S: Spec, F: Field> From<SyncStateInput> for SyncState<S, F> {
    fn from(
        SyncStateInput {
            target_epoch,
            sync_committee,
            sync_signature,
            attested_header,
            merkle_trace,
        }: SyncStateInput,
    ) -> Self {
        let sha256_inputs = vec![]; //merkle_trace.sha256_inputs();
        Self {
            target_epoch,
            sync_committee,
            sync_signature,
            attested_header,
            state_root: [0; 32], //merkle_trace.root(),
            merkle_trace,
            sha256_inputs,
            randomness: Sha256CircuitConfig::fixed_challenge(),
            _s: PhantomData,
        }
    }
}
