use std::marker::PhantomData;

use beacon_api_client::{BlockId, Client, ClientTypes};
use eth_types::Spec;
use ethereum_consensus_types::{BeaconBlockHeader, LightClientUpdateCapella};
use halo2curves::bn256::Fr;
use itertools::Itertools;
use lightclient_circuits::{gadget::crypto, witness::CommitteeRotationArgs};
use log::debug;
use ssz_rs::Merkleized;
use tokio::fs;

use crate::{get_block_header, get_light_client_update_at_period};

pub async fn fetch_rotation_args<S: Spec, C: ClientTypes>(
    client: &Client<C>,
) -> eyre::Result<CommitteeRotationArgs<S, Fr>> {
    let block = get_block_header(&client, BlockId::Head).await?;
    let slot = block.slot;
    let period = slot / (32 * 256);
    debug!(
        "Fetching light client update at current Slot: {} at Period: {}",
        slot, period
    );

    let mut update: LightClientUpdateCapella<512, 55, 5, 105, 6, 256, 32> =
        get_light_client_update_at_period(&client, period).await?;

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

    let args = CommitteeRotationArgs::<S, Fr> {
        pubkeys_compressed,
        randomness: crypto::constant_randomness(),
        finalized_header: update.attested_header.beacon,
        sync_committee_branch: sync_committee_branch
            .into_iter()
            .map(|n| n.to_vec())
            .collect_vec(),
        _spec: PhantomData,
    };
    Ok(args)
}

pub async fn read_rotation_args<S: Spec>(
    path: String,
) -> eyre::Result<CommitteeRotationArgs<S, Fr>> {
    #[derive(serde::Deserialize)]
    struct ArgsJson {
        finalized_header: BeaconBlockHeader,
        committee_root_branch: Vec<Vec<u8>>,
        pubkeys_compressed: Vec<Vec<u8>>,
    }

    let ArgsJson {
        pubkeys_compressed,
        committee_root_branch,
        finalized_header,
    } = serde_json::from_slice(
        &fs::read(path)
            .await
            .map_err(|e| eyre::eyre!("Error reading witness file {}", e))?,
    )
    .map_err(|e| eyre::eyre!("Error decoding witness {}", e))?;

    Ok(CommitteeRotationArgs::<S, Fr> {
        pubkeys_compressed,
        randomness: crypto::constant_randomness(),
        finalized_header,
        sync_committee_branch: committee_root_branch,
        _spec: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_api_client::mainnet::Client as MainnetClient;
    use eth_types::Testnet;
    use halo2_base::gates::builder::CircuitBuilderStage;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;
    use lightclient_circuits::{
        committee_update_circuit::CommitteeUpdateCircuit,
        util::{gen_srs, AppCircuit, Eth2ConfigPinning, Halo2ConfigPinning},
    };
    use snark_verifier_sdk::CircuitExt;

    #[tokio::test]
    async fn test_rotation_circuit_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/committee_update.json";
        const K: u32 = 21;
        let client = MainnetClient::new(Url::parse("http://65.109.55.120:9596").unwrap());
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
        const CONFIG_PATH: &str = "../lightclient-circuits/config/committee_update.json";
        const K: u32 = 21;
        let params = gen_srs(K);

        let pk = CommitteeUpdateCircuit::<Testnet, Fr>::read_or_create_pk(
            &params,
            "../build/sync_step.pkey",
            CONFIG_PATH,
            false,
            &CommitteeRotationArgs::<Testnet, Fr>::default(),
        );
        let client = MainnetClient::new(Url::parse("http://65.109.55.120:9596").unwrap());
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
