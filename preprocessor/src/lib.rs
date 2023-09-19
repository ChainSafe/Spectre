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

pub async fn fetch_step_args<S: Spec>(node_url: String) -> eyre::Result<SyncStepArgs<S>> {
    let client = SyncCommitteeProver::new(node_url);
    let mut beacon_state = client.fetch_beacon_state("head").await.unwrap();

    let mut beacon_block = client.fetch_block("head").await.unwrap();

    let mut finalized_block = client.fetch_block("finalized").await.unwrap();
    let pubkeys_uncompressed = beacon_state
        .current_sync_committee
        .public_keys
        .iter()
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

    let args = SyncStepArgs::<S> {
        signature_compressed: vec![],
        pubkeys_uncompressed,
        pariticipation_bits: vec![],
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
        .map(|pk| pk.to_vec())
        .collect_vec();

    let args = CommitteeRotationArgs::<S, Fr> {
        pubkeys_compressed,
        randomness: crypto::constant_randomness(),
        _spec: PhantomData,
    };

    Ok(args)
}

// #[tokio::test]
// async fn fetch_step_args() {
//     let client = BeaconClient::new("http://localhost:80");
//     let args = client.fetch_step_args::<Testnet>().await.unwrap();

//     println!("{:x?}", args);
// }
