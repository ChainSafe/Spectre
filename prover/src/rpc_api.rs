use crate::args;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofRotationParams {
    pub spec: args::Spec,

    pub k: Option<u32>,
    #[serde(default = "default_beacon_api")]
    pub beacon_api: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofStepParams {
    pub spec: args::Spec,

    pub k: Option<u32>,
    #[serde(default = "default_beacon_api")]
    pub beacon_api: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofStepWithWitnessParams {
    pub spec: args::Spec,

    pub k: Option<u32>,

    // Serializing as Vec<u8> so that we can differentiate between Mainnet, Testnet, Minimal at runtime
    pub light_client_finality_update: Vec<u8>,
    pub pubkeys: Vec<u8>,

    pub domain: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofRotationWithWitnessParams {
    pub spec: args::Spec,

    pub k: Option<u32>,

    // Serializing as Vec<u8> so that we can differentiate between Mainnet, Testnet, Minimal at runtime
    pub light_client_update: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmProofResult {
    pub proof: Vec<u8>,
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

pub const EVM_PROOF_STEP_CIRCUIT: &str = "genEvmProofAndInstancesStepSyncCircuit";
pub const EVM_PROOF_ROTATION_CIRCUIT: &str = "genEvmProofAndInstancesRotationCircuit";

pub const EVM_PROOF_STEP_CIRCUIT_WITH_WITNESS: &str =
    "genEvmProofAndInstancesStepSyncCircuitWithWitness";
pub const EVM_PROOF_ROTATION_CIRCUIT_WITH_WITNESS: &str =
    "genEvmProofAndInstancesRotationCircuitWithWitness";

pub const SYNC_COMMITTEE_POSEIDON_COMPRESSED: &str = "syncCommitteePoseidonCompressed";
pub const SYNC_COMMITTEE_POSEIDON_UNCOMPRESSED: &str = "syncCommitteePoseidonUncompressed";
