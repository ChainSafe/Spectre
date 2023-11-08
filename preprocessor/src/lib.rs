#![feature(generic_const_exprs)]

mod sync;
use beacon_api_client::{BlockId, Client, ClientTypes, Value, VersionedValue};
use ethereum_consensus_types::{
    BeaconBlockHeader, LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdateCapella,
    Root,
};
use serde::{Deserialize, Serialize};
use ssz_rs::Node;
pub use sync::*;
mod rotation;
pub use rotation::*;
use zipline_cryptography::bls::BlsSignature;

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

pub async fn get_light_client_update_at_current_period<
    C: ClientTypes,
    const SYNC_COMMITTEE_SIZE: usize,
    const NEXT_SYNC_COMMITTEE_GINDEX: usize,
    const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
    const FINALIZED_ROOT_GINDEX: usize,
    const FINALIZED_ROOT_PROOF_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    client: &Client<C>,
) -> eyre::Result<
    LightClientUpdateCapella<
        SYNC_COMMITTEE_SIZE,
        NEXT_SYNC_COMMITTEE_GINDEX,
        NEXT_SYNC_COMMITTEE_PROOF_SIZE,
        FINALIZED_ROOT_GINDEX,
        FINALIZED_ROOT_PROOF_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
> {
    let block = get_block_header(client, BlockId::Head).await?;
    let slot = block.slot;
    let period = slot / (32 * 256);

    let route = format!("eth/v1/beacon/light_client/updates");
    let mut updates: Vec<
        VersionedValue<
            LightClientUpdateCapella<
                SYNC_COMMITTEE_SIZE,
                NEXT_SYNC_COMMITTEE_GINDEX,
                NEXT_SYNC_COMMITTEE_PROOF_SIZE,
                FINALIZED_ROOT_GINDEX,
                FINALIZED_ROOT_PROOF_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
        >,
    > = client
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

pub async fn get_light_client_update_at_period<
    C: ClientTypes,
    const SYNC_COMMITTEE_SIZE: usize,
    const NEXT_SYNC_COMMITTEE_GINDEX: usize,
    const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
    const FINALIZED_ROOT_GINDEX: usize,
    const FINALIZED_ROOT_PROOF_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    client: &Client<C>,
    period: u64,
) -> eyre::Result<
    LightClientUpdateCapella<
        SYNC_COMMITTEE_SIZE,
        NEXT_SYNC_COMMITTEE_GINDEX,
        NEXT_SYNC_COMMITTEE_PROOF_SIZE,
        FINALIZED_ROOT_GINDEX,
        FINALIZED_ROOT_PROOF_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
> {
    let route = format!("eth/v1/beacon/light_client/updates");
    let mut updates: Vec<
        VersionedValue<
            LightClientUpdateCapella<
                SYNC_COMMITTEE_SIZE,
                NEXT_SYNC_COMMITTEE_GINDEX,
                NEXT_SYNC_COMMITTEE_PROOF_SIZE,
                FINALIZED_ROOT_GINDEX,
                FINALIZED_ROOT_PROOF_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
        >,
    > = client
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

pub async fn get_light_client_bootstrap<
    C: ClientTypes,
    const SYNC_COMMITTEE_SIZE: usize,
    const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    client: &Client<C>,
    block_root: Node,
) -> eyre::Result<
    LightClientBootstrap<
        SYNC_COMMITTEE_SIZE,
        NEXT_SYNC_COMMITTEE_PROOF_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
> {
    let route = format!("eth/v1/beacon/light_client/bootstrap/{block_root:?}");
    let bootstrap = client
        .get::<VersionedValue<
            LightClientBootstrap<
                SYNC_COMMITTEE_SIZE,
                NEXT_SYNC_COMMITTEE_PROOF_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
        >>(&route)
        .await?
        .data;
    Ok(bootstrap)
}

pub async fn get_light_client_finality_update<
    C: ClientTypes,
    const SYNC_COMMITTEE_SIZE: usize,
    const FINALIZED_ROOT_PROOF_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    client: &Client<C>,
) -> eyre::Result<
    LightClientFinalityUpdate<
        SYNC_COMMITTEE_SIZE,
        FINALIZED_ROOT_PROOF_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
> {
    Ok(client
        .get::<VersionedValue<
            LightClientFinalityUpdate<
                SYNC_COMMITTEE_SIZE,
                FINALIZED_ROOT_PROOF_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
        >>("eth/v1/beacon/light_client/finality_update")
        .await?
        .data)
}
