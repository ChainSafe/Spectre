#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod rotation;
mod step;

use beacon_api_client::{BlockId, Client, ClientTypes, Value, VersionedValue};
use eth_types::Spec;
use ethereum_consensus_types::bls::BlsSignature;
use ethereum_consensus_types::{
    BeaconBlockHeader, LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdateCapella,
    Root,
};

pub use rotation::*;
use serde::{Deserialize, Serialize};
use ssz_rs::Node;
pub use step::*;

pub async fn get_light_client_update_at_period<S: Spec, C: ClientTypes>(
    client: &Client<C>,
    period: u64,
) -> eyre::Result<
    LightClientUpdateCapella<
        { S::SYNC_COMMITTEE_SIZE },
        { S::SYNC_COMMITTEE_ROOT_INDEX },
        { S::SYNC_COMMITTEE_DEPTH },
        { S::FINALIZED_HEADER_INDEX },
        { S::FINALIZED_HEADER_DEPTH },
        { S::BYTES_PER_LOGS_BLOOM },
        { S::MAX_EXTRA_DATA_BYTES },
    >,
>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::SYNC_COMMITTEE_ROOT_INDEX]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::FINALIZED_HEADER_INDEX]:,
{
    let route = format!("eth/v1/beacon/light_client/updates");
    let mut updates: Vec<VersionedValue<_>> = client
        .http
        .get(client.endpoint.join(&route)?)
        .query(&[("start_period", period), ("count", 1)])
        .send()
        .await?
        .json()
        .await?;
    assert!(updates.len() == 1, "should only get one update");
    Ok(updates.pop().unwrap().data)
}

pub async fn get_light_client_bootstrap<S: Spec, C: ClientTypes>(
    client: &Client<C>,
    block_root: Node,
) -> eyre::Result<
    LightClientBootstrap<
        { S::SYNC_COMMITTEE_SIZE },
        { S::SYNC_COMMITTEE_DEPTH },
        { S::BYTES_PER_LOGS_BLOOM },
        { S::MAX_EXTRA_DATA_BYTES },
    >,
>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
{
    let route = format!("eth/v1/beacon/light_client/bootstrap/{block_root:?}");
    let bootstrap = client.get::<VersionedValue<_>>(&route).await?.data;
    Ok(bootstrap)
}

pub async fn get_light_client_finality_update<S: Spec, C: ClientTypes>(
    client: &Client<C>,
) -> eyre::Result<
    LightClientFinalityUpdate<
        { S::SYNC_COMMITTEE_SIZE },
        { S::FINALIZED_HEADER_DEPTH },
        { S::BYTES_PER_LOGS_BLOOM },
        { S::MAX_EXTRA_DATA_BYTES },
    >,
>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
{
    Ok(client
        .get::<VersionedValue<_>>("eth/v1/beacon/light_client/finality_update")
        .await?
        .data)
}

pub async fn get_block_header<C: ClientTypes>(
    client: &Client<C>,
    id: BlockId,
) -> eyre::Result<BeaconBlockHeader> {
    // TODO: Once the ethereum beacon_api_client is updated, we can avoid this struct definition
    #[derive(Serialize, Deserialize)]
    struct BeaconHeaderSummary {
        pub root: Root,
        pub canonical: bool,
        pub header: SignedBeaconBlockHeader,
    }
    #[derive(Serialize, Deserialize)]
    struct SignedBeaconBlockHeader {
        pub message: BeaconBlockHeader,
        pub signature: BlsSignature,
    }

    let route = format!("eth/v1/beacon/headers/{id}");
    let block: BeaconHeaderSummary = client.get::<Value<_>>(&route).await?.data;
    Ok(block.header.message)
}
