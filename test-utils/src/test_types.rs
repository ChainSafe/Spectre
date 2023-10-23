use ssz_rs::prelude::*;
use lightclient_circuits::witness::{CommitteeRotationArgs, SyncStepArgs};
use eth_types::Spec;
use halo2curves::bn256::Fr;

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct TestMeta {
    pub genesis_validators_root: String,
    pub trusted_block_root: String,
    pub bootstrap_fork_digest: String,
    pub store_fork_digest: String,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStep {
    ProcessUpdate {
        update_fork_digest: String,
        update: String,
        current_slot: u64,
        checks: Checks,
    },
    ForceUpdate {
        current_slot: u64,
        checks: Checks,
    },
}

#[derive(Debug)]
pub enum SpectreTestStep<S: Spec> {
    // after posting a step update with the given sync_witness we expect the contract
    // head to match the spot in post_date_head and the beacon/execution block roots for
    // that slot to also be stored
    SyncStep {
        sync_witness: SyncStepArgs<S>,
        post_head_state: RootAtSlot,
    },
    // after posting a rotate update with the given witness we expect no change in the
    // post_head_state (should match the previous step, and for the post_sync_committee_poseidon 
    // to be stored in the contract at the post_sync_period
    RotateStep {
        sync_witness: SyncStepArgs<S>,
        rotate_witness: CommitteeRotationArgs<S, Fr>,
        post_head_state: RootAtSlot,
        post_sync_period: u64,
        post_sync_committee_poseidon: String,
    }
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct Checks {
    pub finalized_header: RootAtSlot,
    pub optimistic_header: RootAtSlot,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct RootAtSlot {
    pub slot: u64,
    pub beacon_root: String,
    pub execution_root: String,
}

// TODO: remove this once we have a better way to handle the `ssz_rs` dependency
#[derive(Debug, Default, Clone, PartialEq, SimpleSerialize, Eq)]
pub struct ByteVector<const N: usize>(pub Vector<u8, N>);
#[derive(Default, Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct ByteList<const N: usize>(pub List<u8, N>);
pub type ExecutionAddress = ByteVector<20>;
