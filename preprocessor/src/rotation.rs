use std::marker::PhantomData;

use eth_types::Spec;
use halo2curves::bn256::Fr;
use itertools::Itertools;
use lightclient_circuits::{gadget::crypto, witness::CommitteeRotationArgs};
use sync_committee_prover::SyncCommitteeProver;
use tokio::fs;

pub async fn fetch_rotation_args<S: Spec>(
    node_url: String,
) -> eyre::Result<CommitteeRotationArgs<S, Fr>> {
    let client = SyncCommitteeProver::new(node_url);
    let beacon_state = client.fetch_beacon_state("head").await.unwrap();
    let finalized_header_root = beacon_state.finalized_checkpoint.root;
    let mut finalized_header = client
        .fetch_header(&finalized_header_root.to_string())
        .await
        .unwrap();
    let pubkeys_compressed = beacon_state
        .current_sync_committee
        .public_keys
        .iter()
        .take(S::SYNC_COMMITTEE_SIZE)
        .map(|pk| pk.to_vec())
        .collect_vec();

    let sync_committee_branch =
        ssz_rs::generate_proof(&mut finalized_header, &[S::SYNC_COMMITTEE_ROOT_INDEX])
            .unwrap()
            .iter()
            .map(|n| n.as_bytes().to_vec())
            .collect_vec();
    assert!(sync_committee_branch.len() == S::FINALIZED_HEADER_DEPTH);
    // // FIXME: `ssz_rs::generate_proof` generates branch without leaf. Why?
    // sync_committee_branch.insert(
    //     0,
    //     state.finalized_checkpoint.epoch.hash_tree_root().unwrap(),
    // );
    let args = CommitteeRotationArgs::<S, Fr> {
        pubkeys_compressed,
        randomness: crypto::constant_randomness(),
        finalized_header,
        sync_committee_branch,
        _spec: PhantomData,
    };

    Ok(args)
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
        finalized_header: todo!(),
        sync_committee_branch: todo!(),
        _spec: PhantomData,
    })
}
