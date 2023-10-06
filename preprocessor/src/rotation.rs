use std::marker::PhantomData;

use eth_types::Spec;
use halo2curves::bn256::Fr;
use itertools::Itertools;
use lightclient_circuits::{gadget::crypto, witness::CommitteeRotationArgs};
use ssz_rs::Merkleized;
use sync_committee_primitives::consensus_types::BeaconBlockHeader;
use sync_committee_prover::SyncCommitteeProver;
use tokio::fs;

pub async fn fetch_rotation_args<S: Spec>(
    node_url: String,
) -> eyre::Result<CommitteeRotationArgs<S, Fr>> {
    let client = SyncCommitteeProver::new(node_url);
    let finalized_header = client.fetch_header("finalized").await.unwrap();
    let mut finalized_state = client
        .fetch_beacon_state(&finalized_header.state_root.to_string())
        .await
        .unwrap();
    let pubkeys_compressed = finalized_state
        .next_sync_committee
        .public_keys
        .iter()
        .map(|pk| pk.to_vec())
        .collect_vec();

    let mut sync_committee_branch =
        ssz_rs::generate_proof(&mut finalized_state, &[S::SYNC_COMMITTEE_ROOT_INDEX * 2]).unwrap();

    sync_committee_branch.insert(
        0,
        finalized_state
            .next_sync_committee
            .aggregate_public_key
            .hash_tree_root()
            .unwrap(),
    );
    assert!(
        ssz_rs::verify_merkle_proof(
            &finalized_state
                .next_sync_committee
                .public_keys
                .hash_tree_root()
                .unwrap(),
            &sync_committee_branch,
            &ssz_rs::GeneralizedIndex(S::SYNC_COMMITTEE_ROOT_INDEX * 2),
            &finalized_header.state_root,
        ),
        "Execution payload merkle proof verification failed"
    );
    let args = CommitteeRotationArgs::<S, Fr> {
        pubkeys_compressed,
        randomness: crypto::constant_randomness(),
        finalized_header,
        sync_committee_branch: sync_committee_branch
            .iter()
            .map(|n| n.as_bytes().to_vec())
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
    use eth_types::Testnet;
    use halo2_base::gates::builder::CircuitBuilderStage;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;
    use lightclient_circuits::{
        committee_update_circuit::CommitteeUpdateCircuit,
        util::{gen_srs, AppCircuit, Eth2ConfigPinning, Halo2ConfigPinning},
    };
    use snark_verifier_sdk::CircuitExt;

    use super::*;

    #[tokio::test]
    async fn test_rotation_circuit_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/committee_update.json";
        const K: u32 = 21;
        let params = gen_srs(K);

        let witness = fetch_rotation_args::<Testnet>("http://3.128.78.74:5052".to_string())
            .await
            .unwrap();
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

        let witness = fetch_rotation_args::<Testnet>("http://3.128.78.74:5052".to_string())
            .await
            .unwrap();

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
