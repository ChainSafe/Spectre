use std::marker::PhantomData;

use crate::sha256_circuit::Sha256CircuitConfig;

use super::{validators, Attestation, HashInput};
use super::{MerkleTrace, Validator};
use eth_types::{Field, Spec};
use ethereum_consensus::bellatrix::mainnet;
use ethereum_consensus::bellatrix::BeaconState;
use ssz_rs::Merkleized;

// TODO: Remove fields that are duplicated in`eth_block`
/// Block is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default)]
pub struct State<S: Spec, F: Field>
where
    [(); { S::MAX_VALIDATORS_PER_COMMITTEE }]:,
{
    pub randomness: F,

    /// The target epoch
    pub target_epoch: u64,

    pub validators: Vec<Validator>,

    pub attestations: Vec<Attestation<S>>,

    pub merkle_trace: MerkleTrace,

    pub sha256_inputs: Vec<HashInput<u8>>,

    pub state_root: [u8; 32],
}

#[allow(non_camel_case_types)]
impl<S: Spec, F: Field> State<S, F>
where
    [(); { S::MAX_VALIDATORS_PER_COMMITTEE }]:,
{
    pub fn new(
        target_epoch: u64,
        validators: Vec<Validator>,
        attestations: Vec<Attestation<S>>,
        merkle_trace: MerkleTrace,
    ) -> Self {
        let sha256_inputs = merkle_trace.sha256_inputs();
        Self {
            target_epoch,
            validators,
            attestations,
            state_root: merkle_trace.root(),
            merkle_trace,
            sha256_inputs,
            randomness: Sha256CircuitConfig::fixed_challenge(),
        }
    }

    pub fn from_beacon_state<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
    >(
        mut beacon_state: BeaconState<
            { mainnet::SLOTS_PER_HISTORICAL_ROOT },
            { mainnet::HISTORICAL_ROOTS_LIMIT },
            { mainnet::ETH1_DATA_VOTES_BOUND },
            { mainnet::VALIDATOR_REGISTRY_LIMIT },
            { mainnet::EPOCHS_PER_HISTORICAL_VECTOR },
            { mainnet::EPOCHS_PER_SLASHINGS_VECTOR },
            { mainnet::MAX_VALIDATORS_PER_COMMITTEE },
            { mainnet::SYNC_COMMITTEE_SIZE },
            { mainnet::BYTES_PER_LOGS_BLOOM },
            { mainnet::MAX_EXTRA_DATA_BYTES },
            { mainnet::MAX_BYTES_PER_TRANSACTION },
            { mainnet::MAX_TRANSACTIONS_PER_PAYLOAD },
        >,
    ) -> Self {
        let block = State::<S, F> {
            // FIXME: this is a problem because the struct definition above says the
            // target_epoch is u64, but here it's returning an `F` type, which is not trait bound
            // to be *convertible* into a u64. Is that what we want?
            target_epoch: beacon_state.current_justified_checkpoint.epoch,
            validators: Validator::build_from_validators(beacon_state.validators.iter()),
            attestations: vec![],
            merkle_trace: MerkleTrace::empty(),
            sha256_inputs: vec![],
            state_root: beacon_state
                .hash_tree_root()
                .unwrap()
                .as_ref()
                .try_into()
                .unwrap(),
            randomness: Sha256CircuitConfig::fixed_challenge(),
        };
        block
    }
}
