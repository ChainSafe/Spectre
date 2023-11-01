use ssz_rs::prelude::*;

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
