#![feature(generic_const_exprs)]

mod sync;
use std::ops::Deref;

use beacon_api_client::{BlockId, Client, ClientTypes, Value, VersionedValue};
use eth_types::Spec;
use ethereum_consensus_types::{
    BeaconBlockHeader, ByteVector, LightClientBootstrap, LightClientFinalityUpdate,
    LightClientUpdateCapella, Root,
};
use halo2curves::bn256::Fr;
use itertools::Itertools;
use lightclient_circuits::witness::{CommitteeRotationArgs, SyncStepArgs};
use serde::{Deserialize, Serialize};
use ssz_rs::{Node, Vector};
pub use sync::*;
mod rotation;
pub use rotation::*;
use zipline_cryptography::bls::BlsPublicKey;
use zipline_cryptography::bls::BlsSignature;
pub async fn light_client_update_to_args<S: Spec>(
    update: &mut LightClientUpdateCapella<
        { S::SYNC_COMMITTEE_SIZE },
        { S::SYNC_COMMITTEE_ROOT_INDEX },
        { S::SYNC_COMMITTEE_DEPTH },
        { S::FINALIZED_HEADER_INDEX },
        { S::FINALIZED_HEADER_DEPTH },
        { S::BYTES_PER_LOGS_BLOOM },
        { S::MAX_EXTRA_DATA_BYTES },
    >,
    pubkeys_compressed: Vector<BlsPublicKey, { S::SYNC_COMMITTEE_SIZE }>,
    domain: [u8; 32],
) -> eyre::Result<(SyncStepArgs<S>, CommitteeRotationArgs<S, Fr>)>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::SYNC_COMMITTEE_ROOT_INDEX]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::FINALIZED_HEADER_INDEX]:,
{
    let finality_update = LightClientFinalityUpdate {
        attested_header: update.attested_header.clone(),
        finalized_header: update.finalized_header.clone(),
        finality_branch: Vector::try_from(
            update
                .finality_branch
                .iter()
                .map(|v| ByteVector(Vector::try_from(v.deref().to_vec()).unwrap()))
                .collect_vec(),
        )
        .unwrap(),
        sync_aggregate: update.sync_aggregate.clone(),
        signature_slot: update.signature_slot,
    };

    let rotation_args = rotation::rotation_args_from_update(update).await?;

    let sync_args =
        sync::step_args_from_finality_update(finality_update, pubkeys_compressed, domain).await?;

    Ok((sync_args, rotation_args))
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
