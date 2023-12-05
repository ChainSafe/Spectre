use std::sync::Arc;

use jsonrpc_v2::{Error, RequestObject};
use spectre_prover::rpc_api::{
    EvmProofResult, GenProofRotationParams, GenProofRotationWithWitnessParams, GenProofStepParams,
    GenProofStepWithWitnessParams, SyncCommitteePoseidonParams, SyncCommitteePoseidonResult,
    EVM_PROOF_ROTATION_CIRCUIT, EVM_PROOF_ROTATION_CIRCUIT_WITH_WITNESS, EVM_PROOF_STEP_CIRCUIT,
    EVM_PROOF_STEP_CIRCUIT_WITH_WITNESS, SYNC_COMMITTEE_POSEIDON_COMPRESSED,
    SYNC_COMMITTEE_POSEIDON_UNCOMPRESSED,
};
use url::Url;
const SEPOLIA_BEACON_API: &str = "http://65.109.55.120:9596";
const SPECTRE_API: &str = "http://localhost:3000/rpc";

use beacon_api_client::mainnet::Client as MainnetBeaconClient;
use beacon_api_client::Client as BeaconClient;
use beacon_api_client::{BlockId, ClientTypes, StateId, VersionedValue};
use jsonrpc_v2::{MapRouter as JsonRpcMapRouter, Server as JsonRpcServer};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use spectre_prover::rpc_client::{Client as SpectreClient, JsonRpcResponse};
/// RPC client to send JSON-RPC requests to the prover
pub struct MockClient {
    pub server: JsonRpcServer<JsonRpcMapRouter>,
}

impl MockClient {
    pub fn new(server: JsonRpcServer<JsonRpcMapRouter>) -> Self {
        Self { server }
    }
    /// Generates a proof along with instance values for committee Rotation circuit
    pub async fn gen_evm_proof_rotation_circuit(
        &self,
        params: GenProofRotationParams,
    ) -> Result<EvmProofResult, Error> {
        self.call(EVM_PROOF_ROTATION_CIRCUIT, params).await
    }

    /// Generates a proof along with instance values for Step circuit
    pub async fn gen_evm_proof_step_circuit(
        &self,
        params: GenProofStepParams,
    ) -> Result<EvmProofResult, Error> {
        self.call(EVM_PROOF_STEP_CIRCUIT, params).await
    }

    /// Generates a proof along with instance values for committee Rotation circuit
    pub async fn gen_evm_proof_rotation_circuit_with_witness(
        &self,
        params: GenProofRotationWithWitnessParams,
    ) -> Result<EvmProofResult, Error> {
        self.call(EVM_PROOF_ROTATION_CIRCUIT_WITH_WITNESS, params)
            .await
    }

    /// Generates a proof along with instance values for Step circuit
    pub async fn gen_evm_proof_step_circuit_with_witness(
        &self,
        params: GenProofStepWithWitnessParams,
    ) -> Result<EvmProofResult, Error> {
        self.call(EVM_PROOF_STEP_CIRCUIT_WITH_WITNESS, params).await
    }

    pub async fn sync_committee_poseidon_compressed(
        &self,
        params: SyncCommitteePoseidonParams,
    ) -> Result<SyncCommitteePoseidonResult, Error> {
        self.call(SYNC_COMMITTEE_POSEIDON_COMPRESSED, params).await
    }

    pub async fn sync_committee_poseidon_uncompressed(
        &self,
        params: SyncCommitteePoseidonParams,
    ) -> Result<SyncCommitteePoseidonResult, Error> {
        self.call(SYNC_COMMITTEE_POSEIDON_UNCOMPRESSED, params)
            .await
    }

    /// Utility method for sending RPC requests over HTTP
    async fn call<P, R>(&self, method_name: &str, params: P) -> Result<R, Error>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let rpc_req = RequestObject::request()
            .with_method(method_name)
            .with_params(serde_json::to_value(params)?)
            .finish();

        let response = self.server.handle(rpc_req).await;
        match response {
            jsonrpc_v2::ResponseObjects::One(r) => Ok(r),
            jsonrpc_v2::ResponseObjects::Many(_) => unreachable!(),
            jsonrpc_v2::ResponseObjects::Empty => Err("Empty".to_string()),
        }
        // let response_str = serde_json::to_string(&response);
        // log::debug!("RPC response: {:?}", response_str);

        // match response_str {
        //     Ok(result) => Ok(result),
        //     Err(err) => (
        //         Err(err.to_string()),
        //     ),
        // }
    }
}

#[tokio::test]
async fn e2e_step() {
    let reqwest_client = reqwest::Client::new();
    let beacon_client = Arc::new(MainnetBeaconClient::new_with_client(
        reqwest_client.clone(),
        Url::parse(SEPOLIA_BEACON_API).unwrap(),
    ));
}
