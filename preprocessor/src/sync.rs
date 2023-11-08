use std::marker::PhantomData;


use beacon_api_client::mainnet::Client;
use eth_types::Spec;
use ethereum_consensus_types::signing::{compute_domain, DomainType};
use ethereum_consensus_types::{ForkData, LightClientBootstrap, LightClientFinalityUpdate};
use itertools::Itertools;
use lightclient_circuits::witness::SyncStepArgs;
use reqwest::Url;
use ssz_rs::{Merkleized, Node};

use beacon_api_client::{BlockId, StateId, VersionedValue};
use tokio::fs;

pub async fn fetch_step_args<S: Spec>(node_url: String) -> eyre::Result<SyncStepArgs<S>> {
    let client = Client::new(Url::parse(&node_url)?);
    let block = client.get_beacon_block_root(BlockId::Head).await.unwrap();
    let route = format!("eth/v1/beacon/light_client/bootstrap/{block:?}");
    let bootstrap = client
        .get::<VersionedValue<LightClientBootstrap<512, 5, 256, 32>>>(&route)
        .await?
        .data;
    let finality_update = client
        .get::<VersionedValue<LightClientFinalityUpdate<512, 6, 256, 32>>>(
            "eth/v1/beacon/light_client/finality_update",
        )
        .await?
        .data;

    let pubkeys_uncompressed = bootstrap
        .current_sync_committee
        .pubkeys
        .iter()
        .map(|pk| {
            let p = pk.decompressed_bytes();
            let mut x = p[0..48].to_vec();
            let mut y = p[48..96].to_vec();
            x.reverse();
            y.reverse();
            let mut res = vec![];
            res.append(&mut x);
            res.append(&mut y);
            res
        })
        .collect_vec();

    let attested_state_id = finality_update.attested_header.beacon.state_root;
    let fork_version = client
        .get_fork(StateId::Root(attested_state_id))
        .await?
        .current_version;
    let genesis_validators_root = client.get_genesis_details().await?.genesis_validators_root;
    let fork_data = ForkData {
        genesis_validators_root,
        fork_version,
    };
    let domain = compute_domain(DomainType::SyncCommittee, &fork_data)?;

    let execution_payload_root = finality_update
        .finalized_header
        .execution
        .clone()
        .hash_tree_root()?
        .to_vec();
    let execution_payload_branch = finality_update
        .finalized_header
        .execution_branch
        .iter()
        .map(|n| n.0.to_vec())
        .collect_vec();

    assert!(
        ssz_rs::is_valid_merkle_branch(
            Node::try_from(execution_payload_root.as_slice())?,
            &execution_payload_branch,
            S::EXECUTION_STATE_ROOT_DEPTH,
            S::EXECUTION_STATE_ROOT_INDEX,
            finality_update.finalized_header.beacon.body_root,
        )
        .is_ok(),
        "Execution payload merkle proof verification failed"
    );
    assert!(
        ssz_rs::is_valid_merkle_branch(
            finality_update
                .finalized_header
                .beacon
                .clone()
                .hash_tree_root()
                .unwrap(),
            &finality_update
                .finality_branch
                .iter()
                .map(|n| n.as_ref())
                .collect_vec(),
            S::FINALIZED_HEADER_DEPTH,
            S::FINALIZED_HEADER_INDEX,
            finality_update.attested_header.beacon.state_root,
        )
        .is_ok(),
        "Finality merkle proof verification failed"
    );

    Ok(SyncStepArgs {
        signature_compressed: finality_update
            .sync_aggregate
            .sync_committee_signature
            .to_bytes()
            .iter()
            .copied()
            .rev()
            .collect_vec(),
        pubkeys_uncompressed,
        pariticipation_bits: finality_update
            .sync_aggregate
            .sync_committee_bits
            .iter()
            .by_vals()
            .collect_vec(),
        attested_header: finality_update.attested_header.beacon,
        finalized_header: finality_update.finalized_header.beacon,
        finality_branch: finality_update
            .finality_branch
            .iter()
            .map(|n| n.0.to_vec())
            .collect_vec(),
        execution_payload_root: finality_update
            .finalized_header
            .execution
            .clone()
            .hash_tree_root()
            .unwrap()
            .to_vec(),
        execution_payload_branch: finality_update
            .finalized_header
            .execution_branch
            .iter()
            .map(|n| n.0.to_vec())
            .collect_vec(),
        domain,
        _spec: PhantomData,
    })
}

pub async fn read_step_args<S: Spec>(path: String) -> eyre::Result<SyncStepArgs<S>> {
    serde_json::from_slice(
        &fs::read(path)
            .await
            .map_err(|e| eyre::eyre!("Error reading witness file {}", e))?,
    )
    .map_err(|e| eyre::eyre!("Errror decoding witness {}", e))
}

#[cfg(test)]
mod tests {
    use eth_types::Testnet;
    use halo2_base::gates::builder::CircuitBuilderStage;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;
    use lightclient_circuits::{
        sync_step_circuit::SyncStepCircuit,
        util::{gen_srs, AppCircuit, Eth2ConfigPinning, Halo2ConfigPinning},
    };
    use snark_verifier_sdk::CircuitExt;

    use super::*;

    #[tokio::test]
    async fn test_sync_circuit_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/sync_step.json";
        const K: u32 = 21;

        let witness = fetch_step_args::<Testnet>("http://65.109.55.120:9596".to_string())
            .await
            .unwrap();
        let pinning = Eth2ConfigPinning::from_path(CONFIG_PATH);

        let circuit = SyncStepCircuit::<Testnet, Fr>::create_circuit(
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
    async fn test_sync_step_snark_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/sync_step.json";
        const K: u32 = 21;
        let params = gen_srs(K);

        let pk = SyncStepCircuit::<Testnet, Fr>::read_or_create_pk(
            &params,
            "../build/sync_step.pkey",
            CONFIG_PATH,
            false,
            &SyncStepArgs::<Testnet>::default(),
        );

        let witness = fetch_step_args::<Testnet>("http://65.109.55.120:9596".to_string())
            .await
            .unwrap();

        SyncStepCircuit::<Testnet, Fr>::gen_snark_shplonk(
            &params,
            &pk,
            CONFIG_PATH,
            None::<String>,
            &witness,
        )
        .unwrap();
    }
}
