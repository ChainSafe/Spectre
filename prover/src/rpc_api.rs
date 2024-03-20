// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use primitive_types::U256;
use serde::{Deserialize, Serialize};

pub const RPC_EVM_PROOF_STEP_CIRCUIT_COMPRESSED: &str = "genEvmProof_SyncStepCompressed";
pub const RPC_EVM_PROOF_COMMITTEE_UPDATE_CIRCUIT_COMPRESSED: &str =
    "genEvmProof_CommitteeUpdateCompressed";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofStepParams {
    // Serializing as Vec<u8> so that we can differentiate between Mainnet, Testnet, Minimal at runtime
    pub light_client_finality_update: Vec<u8>,
    pub pubkeys: Vec<u8>,

    pub domain: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofCommitteeUpdateParams {
    // Serializing as Vec<u8> so that we can differentiate between Mainnet, Testnet, Minimal at runtime
    pub light_client_update: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStepCompressedEvmProofResult {
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeUpdateEvmProofResult {
    pub proof: Vec<u8>,
    pub committee_poseidon: U256,
}
