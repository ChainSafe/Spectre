// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod rotation;
mod ssz_proofs;
mod step;

use beacon_api_client::{BlockId, Client, ClientTypes, Value, VersionedValue};
use eth_types::Spec;
use ethereum_consensus_types::bls::BlsSignature;
use ethereum_consensus_types::{
    BeaconBlockHeader, BlsPublicKey, ByteVector, LightClientBootstrap, LightClientFinalityUpdate,
    LightClientUpdateCapella, Root,
};

use itertools::Itertools;
use lightclient_circuits::witness::{CommitteeUpdateArgs, SyncStepArgs};
pub use rotation::*;
use serde::{Deserialize, Serialize};
pub use ssz_proofs::*;
use ssz_rs::{Node, Vector};
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
    let route = "eth/v1/beacon/light_client/updates";
    let mut updates: Vec<VersionedValue<_>> = client
        .http
        .get(client.endpoint.join(route)?)
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

pub async fn light_client_update_to_args<S: Spec>(
    update: &LightClientUpdateCapella<
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
) -> eyre::Result<(SyncStepArgs<S>, CommitteeUpdateArgs<S>)>
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
                .map(|v| ByteVector(Vector::try_from(v.to_vec()).unwrap()))
                .collect_vec(),
        )
        .unwrap(),
        sync_aggregate: update.sync_aggregate.clone(),
        signature_slot: update.signature_slot,
    };

    let rotation_args = rotation::rotation_args_from_update(update).await?;

    let sync_args =
        step::step_args_from_finality_update(finality_update, pubkeys_compressed, domain).await?;

    Ok((sync_args, rotation_args))
}

#[cfg(test)]
mod tests {
    use beacon_api_client::StateId;
    use eth_types::Testnet;
    use ethereum_consensus_types::signing::{compute_domain, DomainType};
    use ethereum_consensus_types::ForkData;
    use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
    use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use halo2_base::utils::fs::gen_srs;
    use lightclient_circuits::committee_update_circuit::CommitteeUpdateCircuit;
    use lightclient_circuits::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use lightclient_circuits::util::{Eth2ConfigPinning, Halo2ConfigPinning};
    use lightclient_circuits::{
        halo2_base::gates::circuit::CircuitBuilderStage, sync_step_circuit::StepCircuit,
        util::AppCircuit,
    };
    use snark_verifier_sdk::CircuitExt;

    use super::*;
    use beacon_api_client::mainnet::Client as MainnetClient;
    use reqwest::Url;

    #[tokio::test]
    async fn test_both_circuit_sepolia() {
        const K: u32 = 21;
        let client =
            MainnetClient::new(Url::parse("https://lodestar-sepolia.chainsafe.io").unwrap());

        let block = get_block_header(&client, BlockId::Finalized).await.unwrap();
        let slot = block.slot;
        let period = slot / (32 * 256);

        println!(
            "Fetching light client update at current Slot: {} at Period: {}",
            slot, period
        );

        // Fetch light client update and create circuit arguments
        let (s, mut c) = {
            let update = get_light_client_update_at_period(&client, period)
                .await
                .unwrap();

            let block_root = client
                .get_beacon_block_root(BlockId::Slot(slot))
                .await
                .unwrap();

            let bootstrap = get_light_client_bootstrap(&client, block_root)
                .await
                .unwrap();

            let pubkeys_compressed = bootstrap.current_sync_committee.pubkeys;

            let fork_version = client
                .get_fork(StateId::Head)
                .await
                .unwrap()
                .current_version;
            let genesis_validators_root = client
                .get_genesis_details()
                .await
                .unwrap()
                .genesis_validators_root;
            let fork_data = ForkData {
                genesis_validators_root,
                fork_version,
            };
            let domain = compute_domain(DomainType::SyncCommittee, &fork_data).unwrap();
            light_client_update_to_args::<Testnet>(&update, pubkeys_compressed, domain)
                .await
                .unwrap()
        };

        let mut finalized_sync_committee_branch = {
            let block_root = client
                .get_beacon_block_root(BlockId::Slot(s.finalized_header.slot))
                .await
                .unwrap();

            get_light_client_bootstrap::<Testnet, _>(&client, block_root)
                .await
                .unwrap()
                .current_sync_committee_branch
                .iter()
                .map(|n| n.to_vec())
                .collect_vec()
        };

        // Magic swap of sync committee branch
        finalized_sync_committee_branch.insert(0, c.sync_committee_branch[0].clone());
        finalized_sync_committee_branch[1] = c.sync_committee_branch[1].clone();
        c.sync_committee_branch = finalized_sync_committee_branch;
        // Replaces the attested header with step circuits finalized header
        c.finalized_header = s.finalized_header.clone();

        let params: ParamsKZG<Bn256> = gen_srs(K);

        let circuit = StepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            None,
            &s,
            &params,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied_par();

        const CONFIG_PATH: &str = "../lightclient-circuits/config/committee_update_testnet.json";

        let pinning = Eth2ConfigPinning::from_path(CONFIG_PATH);
        let circuit = CommitteeUpdateCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            Some(pinning),
            &c,
            &params,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied_par();
    }
}
