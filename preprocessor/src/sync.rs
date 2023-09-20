use std::marker::PhantomData;

use eth_types::Spec;
use halo2curves::{bls12_381::G1Affine, group::GroupEncoding, group::UncompressedEncoding};
use itertools::Itertools;
use lightclient_circuits::witness::SyncStepArgs;
use ssz_rs::Merkleized;
use sync_committee_primitives::{
    consensus_types::BeaconBlockHeader,
    domains::DomainType,
    util::{compute_domain, compute_signing_root},
};
use sync_committee_prover::SyncCommitteeProver;
use sync_committee_verifier::{
    signature_verification::verify_aggregate_signature, LightClientState,
};
use tokio::fs;

pub async fn fetch_step_args<S: Spec>(node_url: String) -> eyre::Result<SyncStepArgs<S>> {
    let client = SyncCommitteeProver::new(node_url);
    let state_id = "head";
    let mut state = client
        .fetch_beacon_state(state_id)
        .await
        .map_err(|e| eyre::eyre!("Error fetching state from node. Error: {}", e))?;

    let mut finalized_block = client.fetch_block("finalized").await.unwrap();

    let finalized_header = BeaconBlockHeader {
        slot: finalized_block.slot,
        proposer_index: finalized_block.proposer_index,
        parent_root: finalized_block.parent_root,
        state_root: finalized_block.state_root,
        body_root: finalized_block.body.hash_tree_root().unwrap(),
    };

    let client_state = LightClientState {
        finalized_header: finalized_header.clone(),
        latest_finalized_epoch: 0,
        current_sync_committee: state.current_sync_committee.clone(),
        next_sync_committee: state.next_sync_committee.clone(),
    };

    let mut light_client_update = client
        .fetch_light_client_update(
            client_state.clone(),
            state.finalized_checkpoint.clone(),
            "prover",
        )
        .await
        .map_err(|e| eyre::eyre!("Error fetching light client update. Error: {}", e))?
        .expect("Light client update should be present");

    let pubkeys_uncompressed = client_state
        .current_sync_committee
        .public_keys
        .iter()
        .take(S::SYNC_COMMITTEE_SIZE)
        .map(|pk| {
            let pk_rev = pk.iter().copied().rev().collect_vec();
            G1Affine::from_bytes_unchecked(&pk_rev.try_into().unwrap())
                .unwrap()
                .to_uncompressed()
                .as_ref()
                .to_vec()
        })
        .collect_vec();

    let domain = compute_domain(
        DomainType::SyncCommittee,
        Some(state.fork.current_version),
        Some(state.genesis_validators_root),
        [0u8; 4],
    )
    .map_err(|e| eyre::eyre!("domain computation error: {:?}", e))?;

    {
        let sig_root =
            compute_signing_root(&mut light_client_update.attested_header, domain).unwrap();
        let sync_committee_apk = state.current_sync_committee.aggregate_public_key.clone();
        let non_participant_pubkeys = light_client_update
            .sync_aggregate
            .sync_committee_bits
            .iter()
            .zip(state.current_sync_committee.public_keys.iter())
            .filter_map(|(bit, key)| if !(*bit) { Some(key.clone()) } else { None })
            .collect::<Vec<_>>();
        verify_aggregate_signature(
            &sync_committee_apk,
            &non_participant_pubkeys,
            sig_root.0.to_vec(),
            &light_client_update.sync_aggregate.sync_committee_signature,
        )
        .unwrap();
    }

    let beacon_state_root = state
        .hash_tree_root()
        .map_err(|e| eyre::eyre!("merkleization error: {:?}", e))?;

    let finality_branch = light_client_update
        .finality_proof
        .finality_branch
        .iter()
        .map(|n| n.as_bytes().to_vec())
        .collect_vec();

    let execution_state_root = light_client_update
        .execution_payload
        .state_root
        .as_bytes()
        .to_vec();

    let execution_payload_branch = light_client_update
        .execution_payload
        .execution_payload_branch
        .iter()
        .map(|n| n.as_bytes().to_vec())
        .collect_vec();

    let mut signature_compressed = light_client_update
        .sync_aggregate
        .sync_committee_signature
        .to_vec();

    // reverse beacouse it's big endian
    signature_compressed.reverse();

    let args = SyncStepArgs::<S> {
        signature_compressed,
        pubkeys_uncompressed,
        pariticipation_bits: light_client_update
            .sync_aggregate
            .sync_committee_bits
            .iter()
            .by_vals()
            .take(S::SYNC_COMMITTEE_SIZE)
            .collect_vec(),
        attested_header: light_client_update.attested_header,
        finalized_header: light_client_update.finalized_header,
        domain,
        execution_payload_branch,
        execution_state_root,
        finality_branch,
        beacon_state_root: beacon_state_root.as_bytes().to_vec(),
        _spec: PhantomData,
    };

    Ok(args)
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
        let params = gen_srs(K);

        let witness = fetch_step_args::<Testnet>("http://3.128.78.74:5052".to_string())
            .await
            .unwrap();
        let pinning = Eth2ConfigPinning::from_path(CONFIG_PATH);

        let circuit = SyncStepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            Some(pinning),
            &params,
            &witness,
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

        let witness = fetch_step_args::<Testnet>("http://3.128.78.74:5052".to_string())
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
