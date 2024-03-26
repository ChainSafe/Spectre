// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

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
