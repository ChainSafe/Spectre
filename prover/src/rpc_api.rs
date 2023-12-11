use crate::args;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

pub const RPC_EVM_PROOF_STEP_CIRCUIT: &str = "genEvmProof_SyncStep";
pub const RPC_EVM_PROOF_ROTATION_CIRCUIT: &str = "genEvmProof_CommitteeUpdate";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofRotationParams {
    pub spec: args::Spec,

    #[serde(default = "default_beacon_api")]
    pub beacon_api: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofStepParams {
    pub spec: args::Spec,

    #[serde(default = "default_beacon_api")]
    pub beacon_api: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofStepWithWitnessParams {
    pub spec: args::Spec,

    // Serializing as Vec<u8> so that we can differentiate between Mainnet, Testnet, Minimal at runtime
    pub light_client_finality_update: Vec<u8>,
    pub pubkeys: Vec<u8>,

    pub domain: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofRotationWithWitnessParams {
    pub spec: args::Spec,

    // Serializing as Vec<u8> so that we can differentiate between Mainnet, Testnet, Minimal at runtime
    pub light_client_update: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmProofResult {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<U256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedEvmProofResult {
    pub proof: Vec<u8>,
    pub accumulator: [U256; 12],
    pub committee_poseidon: U256,
    pub public_inputs: Vec<U256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCommitteePoseidonParams {
    pub pubkeys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCommitteePoseidonResult {
    pub commitment: [u8; 32],
}

fn default_beacon_api() -> String {
    String::from("http://127.0.0.1:5052")
}
