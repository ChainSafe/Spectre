pub use jsonrpc_v2;
use jsonrpc_v2::{Error, Id, RequestObject, V2};
use reqwest::IntoUrl;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use crate::rpc_api::{
    EvmProofResult, GenProofRotationParams, GenProofRotationWithWitnessParams, GenProofStepParams,
    GenProofStepWithWitnessParams, SyncCommitteePoseidonParams, SyncCommitteePoseidonResult,
    EVM_PROOF_ROTATION_CIRCUIT, EVM_PROOF_ROTATION_CIRCUIT_WITH_WITNESS, EVM_PROOF_STEP_CIRCUIT,
    EVM_PROOF_STEP_CIRCUIT_WITH_WITNESS, SYNC_COMMITTEE_POSEIDON_COMPRESSED,
    SYNC_COMMITTEE_POSEIDON_UNCOMPRESSED,
};

/// Error object in a response
#[derive(Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum JsonRpcResponse<R> {
    Result {
        jsonrpc: V2,
        result: R,
        id: Id,
    },
    Error {
        jsonrpc: V2,
        error: JsonRpcError,
        id: Id,
    },
}

/// RPC client to send JSON-RPC requests to the prover
pub struct Client {
    client: reqwest::Client,
    api_url: Url,
}

impl Client {
    pub fn new(url: impl IntoUrl) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_url: url.into_url().unwrap(),
        }
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

        let request = self.client.post(self.api_url.clone()).json(&rpc_req);

        let rpc_res = request.send().await?.error_for_status()?.json().await?;

        match rpc_res {
            JsonRpcResponse::Result { result, .. } => Ok(result),
            JsonRpcResponse::Error { error, .. } => Err(Error::Full {
                data: None,
                code: error.code,
                message: error.message,
            }),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::args;
    use jsonrpc_v2::Error;

    #[tokio::test]
    #[ignore = "requires a running prover"]
    async fn test_rpc_client() {
        let client = Client::new("http://localhost:3000/rpc");

        let p = GenProofStepParams {
            spec: args::Spec::Testnet,
            k: Some(21),
            beacon_api: String::from("http://3.128.78.74:5052"),
        };
        let r = client.gen_evm_proof_step_circuit(p).await;

        match r {
            Ok(r) => {
                println!("res: {:?}", r);
            }
            Err(Error::Full {
                data: _,
                code,
                message,
            }) => {
                println!("Error: {}, Code: {}", message, code);
            }
            Err(Error::Provided { code, message }) => {
                println!("Error: {}, Code: {}", message, code);
            }
        }
    }
}
