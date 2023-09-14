use std::marker::PhantomData;

use eth_types::{Spec, Test};
use halo2curves::{bls12_381::G1Affine, group::GroupEncoding, group::UncompressedEncoding};
use itertools::Itertools;
use lightclient_circuits::witness::SyncStepArgs;
use ssz_rs::Merkleized;
use sync_committee_primitives::{consensus_types::BeaconBlockHeader, util::compute_domain};
use sync_committee_prover::SyncCommitteeProver;

pub async fn fetch_step_args<S: Spec>() -> anyhow::Result<SyncStepArgs<Test>> {
    const NODE_URL: &str = "http://localhost:5052";
    let daemon = SyncCommitteeProver::new(NODE_URL.to_string());

    let mut beacon_state = daemon.fetch_beacon_state("head").await.unwrap();

    let mut beacon_block = daemon.fetch_block("head").await.unwrap();

    let mut finalized_block = daemon.fetch_block("finalized").await.unwrap();
    let pubkeys_uncompressed = beacon_state
        .current_sync_committee
        .public_keys
        .iter()
        .map(|pk| {
            let pk_rev = pk.to_vec().into_iter().rev().collect_vec();
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
    )?;

    let beacon_state_root = beacon_state
        .hash_tree_root()
        .map_err(|e| anyhow::anyhow!("merkleization error: {:?}", e))?;

    let finality_merkle_branch =
        ssz_rs::generate_proof(&mut beacon_state, &[S::FINALIZED_HEADER_INDEX])
            .map(|branch| branch.iter().map(|n| n.as_bytes().to_vec()).collect_vec())
            .map_err(|e| anyhow::anyhow!("merkleization error: {:?}", e))?;

    let execution_state_root = finalized_block.body.execution_payload.state_root.to_vec();

    let execution_merkle_branch =
        ssz_rs::generate_proof(&mut finalized_block, &[S::EXECUTION_STATE_ROOT_INDEX])
            .map(|branch| branch.iter().map(|n| n.as_bytes().to_vec()).collect_vec())
            .map_err(|e| anyhow::anyhow!("merkleization error: {:?}", e))?;

    let args = SyncStepArgs::<Test> {
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

#[tokio::test]
async fn run_daemon() {
    let args = fetch_step_args::<Test>().await.unwrap();

    println!("{:?}", args);
}
