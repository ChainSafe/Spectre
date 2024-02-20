// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::marker::PhantomData;

// use beacon_api_client::{BlockId, Client, ClientTypes};
use crate::get_light_client_update_at_period;
use eth2::{types::BlockId, BeaconNodeHttpClient};
use eth_types::Spec;
use ethereum_types::{EthSpec, LightClientUpdate};
use itertools::Itertools;
use lightclient_circuits::witness::beacon_header_multiproof_and_helper_indices;
use lightclient_circuits::witness::{
    // beacon_header_multiproof_and_helper_indices,
    CommitteeUpdateArgs,
};
use log::debug;
use tree_hash::TreeHash;

/// Fetches LightClientUpdate from the beacon client and converts it to a [`CommitteeUpdateArgs`] witness
pub async fn fetch_rotation_args<S: Spec, T: EthSpec>(
    client: &BeaconNodeHttpClient,
) -> eyre::Result<CommitteeUpdateArgs<S>>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::SYNC_COMMITTEE_ROOT_INDEX]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::FINALIZED_HEADER_INDEX]:,
{
    let block = client
        .get_beacon_headers_block_id(BlockId::Head)
        .await
        .unwrap()
        .unwrap()
        .data
        .header
        .message;

    let slot = block.slot.as_u64();
    let period = slot / (32 * 256);
    debug!(
        "Fetching light client update at current Slot: {} at Period: {}",
        slot, period
    );

    let update = get_light_client_update_at_period::<S, T>(client, period).await?;
    rotation_args_from_update(&update).await
}

/// Converts a [`LightClientUpdateCapella`] to a [`CommitteeUpdateArgs`] witness.
pub async fn rotation_args_from_update<S: Spec, T: EthSpec>(
    update: &LightClientUpdate<T>,
) -> eyre::Result<CommitteeUpdateArgs<S>>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::SYNC_COMMITTEE_ROOT_INDEX]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::FINALIZED_HEADER_INDEX]:,
{
    let mut update = update.clone();
    let pubkeys_compressed = update
        .next_sync_committee
        .pubkeys
        .iter()
        .map(|pk| pk.serialize().to_vec())
        .collect_vec();
    let mut sync_committee_branch = update.next_sync_committee_branch.as_ref().to_vec();

    sync_committee_branch.insert(
        0,
        update.next_sync_committee.aggregate_pubkey.tree_hash_root(),
    );

    // assert!(
    //     ssz_rs::is_valid_merkle_branch(
    //         update.next_sync_committee.pubkeys.hash_tree_root().unwrap(),
    //         &sync_committee_branch
    //             .iter()
    //             .map(|n| n.as_ref())
    //             .collect_vec(),
    //         S::SYNC_COMMITTEE_PUBKEYS_DEPTH,
    //         S::SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX,
    //         update.attested_header.beacon.state_root,
    //     )
    //     .is_ok(),
    //     "Execution payload merkle proof verification failed"
    // );

    let (finalized_header_multiproof, finalized_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &mut update.finalized_header.beacon(),
            &[S::HEADER_STATE_ROOT_INDEX],
        );
    let leaves = update.finalized_header.beacon().tree_hash_packed_encoding();

    let args = CommitteeUpdateArgs::<S> {
        pubkeys_compressed,
        finalized_header: update.finalized_header.beacon().clone(),
        sync_committee_branch: sync_committee_branch
            .into_iter()
            .map(|n| n.0.to_vec())
            .collect_vec(),
        _spec: PhantomData,
        finalized_header_multiproof,
        finalized_header_helper_indices,
        // finalized_header_multiproof: vec![],
        // finalized_header_helper_indices: vec![],
    };
    Ok(args)
}

#[cfg(test)]
mod tests {

    use super::*;
    use eth2::{BeaconNodeHttpClient, SensitiveUrl, Timeouts};
    use eth_types::Testnet;
    use ethereum_types::EthSpec;
    use ethereum_types::MainnetEthSpec;
    use halo2_base::utils::fs::gen_srs;
    use lightclient_circuits::halo2_proofs::halo2curves::bn256::Fr;
    use lightclient_circuits::{
        committee_update_circuit::CommitteeUpdateCircuit, util::AppCircuit,
    };
    use reqwest::Url;
    use std::time::Duration;
    #[tokio::test]
    async fn test_rotation_snark_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/committee_update_20.json";
        const K: u32 = 20;

        const URL: &str = "https://lodestar-sepolia.chainsafe.io";
        let client = BeaconNodeHttpClient::new(
            SensitiveUrl::parse(URL).unwrap(),
            Timeouts::set_all(Duration::from_secs(10)),
        );

        let params = gen_srs(K);

        let pk = CommitteeUpdateCircuit::<Testnet, Fr>::create_pk(
            &params,
            "../build/sync_step_20.pkey",
            CONFIG_PATH,
            &CommitteeUpdateArgs::<Testnet>::default(),
            None,
        );
        let mut witness = fetch_rotation_args::<Testnet, MainnetEthSpec>(&client)
            .await
            .unwrap();
        let mut finalized_sync_committee_branch = {
            let block_root = witness.finalized_header.canonical_root();

            client
                .get_light_client_bootstrap::<MainnetEthSpec>(block_root)
                .await
                .unwrap()
                .unwrap()
                .data
                .current_sync_committee_branch
                .into_iter()
                .map(|n| n.0.to_vec())
                .collect_vec()
        };

        // Magic swap of sync committee branch
        finalized_sync_committee_branch.insert(0, witness.sync_committee_branch[0].clone());
        finalized_sync_committee_branch[1] = witness.sync_committee_branch[1].clone();
        witness.sync_committee_branch = finalized_sync_committee_branch;

        CommitteeUpdateCircuit::<Testnet, Fr>::gen_snark_shplonk(
            &params,
            &pk,
            CONFIG_PATH,
            None::<String>,
            &witness,
        )
        .unwrap();
    }
}
