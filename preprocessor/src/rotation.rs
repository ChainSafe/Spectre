// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::marker::PhantomData;

use beacon_api_client::{BlockId, Client, ClientTypes};
use eth_types::Spec;
use ethereum_consensus_types::LightClientUpdateCapella;
use itertools::Itertools;
use lightclient_circuits::witness::CommitteeUpdateArgs;
use log::debug;
use ssz_rs::Merkleized;

use crate::{get_block_header, get_light_client_update_at_period};

/// Fetches LightClientUpdate from the beacon client and converts it to a [`CommitteeUpdateArgs`] witness
pub async fn fetch_rotation_args<S: Spec, C: ClientTypes>(
    client: &Client<C>,
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
    let block = get_block_header(client, BlockId::Head).await?;
    let slot = block.slot;
    let period = slot / (32 * 256);
    debug!(
        "Fetching light client update at current Slot: {} at Period: {}",
        slot, period
    );

    let mut update = get_light_client_update_at_period(client, period).await?;
    rotation_args_from_update(&mut update).await
}

/// Converts a [`LightClientUpdateCapella`] to a [`CommitteeUpdateArgs`] witness.
pub async fn rotation_args_from_update<S: Spec>(
    update: &mut LightClientUpdateCapella<
        { S::SYNC_COMMITTEE_SIZE },
        { S::SYNC_COMMITTEE_ROOT_INDEX },
        { S::SYNC_COMMITTEE_DEPTH },
        { S::FINALIZED_HEADER_INDEX },
        { S::FINALIZED_HEADER_DEPTH },
        { S::BYTES_PER_LOGS_BLOOM },
        { S::MAX_EXTRA_DATA_BYTES },
    >,
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
    let pubkeys_compressed = update
        .next_sync_committee
        .pubkeys
        .iter()
        .map(|pk| pk.to_bytes().to_vec())
        .collect_vec();
    let mut sync_committee_branch = update.next_sync_committee_branch.as_ref().to_vec();

    sync_committee_branch.insert(
        0,
        update
            .next_sync_committee
            .aggregate_pubkey
            .hash_tree_root()
            .unwrap(),
    );

    assert!(
        ssz_rs::is_valid_merkle_branch(
            update.next_sync_committee.pubkeys.hash_tree_root().unwrap(),
            &sync_committee_branch
                .iter()
                .map(|n| n.as_ref())
                .collect_vec(),
            S::SYNC_COMMITTEE_PUBKEYS_DEPTH,
            S::SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX,
            update.attested_header.beacon.state_root,
        )
        .is_ok(),
        "Execution payload merkle proof verification failed"
    );

    let args = CommitteeUpdateArgs::<S> {
        pubkeys_compressed,
        finalized_header: update.attested_header.beacon.clone(),
        sync_committee_branch: sync_committee_branch
            .into_iter()
            .map(|n| n.to_vec())
            .collect_vec(),
        _spec: PhantomData,
    };
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_api_client::mainnet::Client as MainnetClient;
    use eth_types::Testnet;
    use halo2_base::utils::fs::gen_srs;
    use lightclient_circuits::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use lightclient_circuits::{
        committee_update_circuit::CommitteeUpdateCircuit,
        halo2_base::gates::circuit::CircuitBuilderStage,
        util::{AppCircuit, Eth2ConfigPinning, Halo2ConfigPinning},
    };
    use reqwest::Url;
    use snark_verifier_sdk::CircuitExt;

    #[tokio::test]
    async fn test_rotation_circuit_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/committee_update.json";
        const K: u32 = 21;
        let client =
            MainnetClient::new(Url::parse("https://lodestar-sepolia.chainsafe.io").unwrap());
        let witness = fetch_rotation_args::<Testnet, _>(&client).await.unwrap();
        let pinning = Eth2ConfigPinning::from_path(CONFIG_PATH);

        let circuit = CommitteeUpdateCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            Some(pinning),
            &witness,
            K,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied_par();
    }

    #[tokio::test]
    async fn test_rotation_step_snark_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/committee_update_18.json";
        const K: u32 = 21;
        let params = gen_srs(K);

        let pk = CommitteeUpdateCircuit::<Testnet, Fr>::read_or_create_pk(
            &params,
            "../build/sync_step_21.pkey",
            CONFIG_PATH,
            false,
            &CommitteeUpdateArgs::<Testnet>::default(),
        );
        let client =
            MainnetClient::new(Url::parse("https://lodestar-sepolia.chainsafe.io").unwrap());
        let witness = fetch_rotation_args::<Testnet, _>(&client).await.unwrap();

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
