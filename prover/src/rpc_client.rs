use jsonrpc_v2::{Error, Id, RequestObject, V2};
use reqwest::IntoUrl;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use crate::rpc_api::{
    EvmProofResult, GenProofRotationParams, GenProofStepParams, EVM_PROOF_ROTATION_CIRCUIT,
    EVM_PROOF_STEP_CIRCUIT,
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
    pub async fn gen_evm_proof_rotation_circuit(
        &self,
        params: GenProofRotationParams,
    ) -> Result<EvmProofResult, Error> {
        self.call(EVM_PROOF_ROTATION_CIRCUIT, params).await
    }

    pub async fn gen_evm_proof_step_circuit(
        &self,
        params: GenProofStepParams,
    ) -> Result<EvmProofResult, Error> {
        self.call(EVM_PROOF_STEP_CIRCUIT, params).await
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
