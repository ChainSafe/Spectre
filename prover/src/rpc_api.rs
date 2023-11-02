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

    pub witness: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenProofRotationWithWitnessParams {
    pub spec: args::Spec,

    pub k: Option<u32>,

    pub witness: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmProofResult {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<U256>,
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
