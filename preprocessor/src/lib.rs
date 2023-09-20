use std::marker::PhantomData;

use eth_types::Spec;
use halo2curves::{
    bls12_381::G1Affine, bn256::Fr, group::GroupEncoding, group::UncompressedEncoding,
};
use itertools::Itertools;
use lightclient_circuits::{
    gadget::crypto,
    witness::{CommitteeRotationArgs, SyncStepArgs},
};
use ssz_rs::Merkleized;
use sync_committee_primitives::{consensus_types::BeaconBlockHeader, util::compute_domain};
use sync_committee_prover::SyncCommitteeProver;
use tokio::fs;

pub async fn fetch_step_args<S: Spec>(node_url: String) -> eyre::Result<SyncStepArgs<S>> {
    let client = SyncCommitteeProver::new(node_url);
    let mut beacon_state = client.fetch_beacon_state("head").await.unwrap();

    let mut beacon_block = client.fetch_block("head").await.unwrap();

    let mut finalized_block = client.fetch_block("finalized").await.unwrap();
    let pubkeys_uncompressed = beacon_state
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
        sync_committee_primitives::domains::DomainType::SyncCommittee,
        Some(beacon_state.fork.current_version),
        Some(beacon_state.genesis_validators_root),
        [0u8; 4],
    )
    .map_err(|e| eyre::eyre!("domain computation error: {:?}", e))?;

    let beacon_state_root = beacon_state
        .hash_tree_root()
        .map_err(|e| eyre::eyre!("merkleization error: {:?}", e))?;

    let finality_merkle_branch =
        ssz_rs::generate_proof(&mut beacon_state, &[S::FINALIZED_HEADER_INDEX])
            .map(|branch| branch.iter().map(|n| n.as_bytes().to_vec()).collect_vec())
            .map_err(|e| eyre::eyre!("merkleization error: {:?}", e))?;

    let execution_state_root = finalized_block.body.execution_payload.state_root.to_vec();

    let execution_merkle_branch =
        ssz_rs::generate_proof(&mut finalized_block, &[S::EXECUTION_STATE_ROOT_INDEX])
            .map(|branch| branch.iter().map(|n| n.as_bytes().to_vec()).collect_vec())
            .map_err(|e| eyre::eyre!("merkleization error: {:?}", e))?;

    let mut signature_compressed = beacon_block
        .body
        .sync_aggregate
        .sync_committee_signature
        .to_vec();

    // reverse beacouse it's big endian
    signature_compressed.reverse();

    let args = SyncStepArgs::<S> {
        signature_compressed,
        pubkeys_uncompressed,
        pariticipation_bits: beacon_block
            .body
            .sync_aggregate
            .sync_committee_bits
            .iter()
            .by_vals()
            .take(S::SYNC_COMMITTEE_SIZE)
            .collect_vec(),
        attested_header: BeaconBlockHeader {
            slot: beacon_block.slot,
            proposer_index: beacon_block.proposer_index,
            parent_root: beacon_block.parent_root,
            state_root: beacon_block.state_root,
            body_root: beacon_block.body.hash_tree_root().unwrap(),
        },
        finalized_header: BeaconBlockHeader {
            slot: finalized_block.slot,
            proposer_index: finalized_block.proposer_index,
            parent_root: finalized_block.parent_root,
            state_root: finalized_block.state_root,
            body_root: finalized_block.body.hash_tree_root().unwrap(),
        },
        domain,
        execution_merkle_branch,
        execution_state_root,
        finality_merkle_branch,
        beacon_state_root: beacon_state_root.as_bytes().to_vec(),
        _spec: PhantomData,
    };

    Ok(args)
}

pub async fn fetch_rotation_args<S: Spec>(
    node_url: String,
) -> eyre::Result<CommitteeRotationArgs<S, Fr>> {
    let client = SyncCommitteeProver::new(node_url);
    let beacon_state = client.fetch_beacon_state("head").await.unwrap();

    let pubkeys_compressed = beacon_state
        .current_sync_committee
        .public_keys
        .iter()
        .take(S::SYNC_COMMITTEE_SIZE)
        .map(|pk| pk.to_vec())
        .collect_vec();

    let args = CommitteeRotationArgs::<S, Fr> {
        pubkeys_compressed,
        randomness: crypto::constant_randomness(),
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

pub async fn read_rotation_args<S: Spec>(
    path: String,
) -> eyre::Result<CommitteeRotationArgs<S, Fr>> {
    let pubkeys_compressed = serde_json::from_slice(
        &fs::read(path)
            .await
            .map_err(|e| eyre::eyre!("Error reading witness file {}", e))?,
    )
    .map_err(|e| eyre::eyre!("Errror decoding witness {}", e))?;

    Ok(CommitteeRotationArgs::<S, Fr> {
        pubkeys_compressed,
        randomness: crypto::constant_randomness(),
        _spec: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use eth_types::Testnet;
    use lightclient_circuits::{
        sync_step_circuit::SyncStepCircuit,
        util::{gen_srs, AppCircuit},
    };

    use super::*;

    #[tokio::test]
    async fn test_sync_step_snark_sepolia() {
        const K: u32 = 21;
        let params = gen_srs(K);

        let pk = SyncStepCircuit::<Testnet, Fr>::read_or_create_pk(
            &params,
            "../build/sync_step.pkey",
            "./config/sync_step.json",
            false,
            &SyncStepArgs::<Testnet>::default(),
        );

        let witness = fetch_step_args::<Testnet>("http://3.128.78.74:5052".to_string())
            .await
            .unwrap();

        SyncStepCircuit::<Testnet, Fr>::gen_snark_shplonk(
            &params,
            &pk,
            "../lightclient-circuits/config/sync_step.json",
            None::<String>,
            &witness,
        )
        .unwrap();
    }
}
