#![cfg(test)]
use ethereum_consensus_types::presets::minimal::{LightClientBootstrap, LightClientUpdate};
use rstest::rstest;
use ssz_rs::prelude::*;
use std::path::PathBuf;
use test_utils::{load_snappy_ssz, load_yaml};

#[derive(Debug, serde::Deserialize)]
struct TestMeta {
    genesis_validators_root: String,
    trusted_block_root: String,
    bootstrap_fork_digest: String,
    store_fork_digest: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TestStep {
    ProcessUpdate {
        update_fork_digest: String,
        update: String,
        current_slot: u64,
        checks: Checks,
    },
    ForceUpdate {
        current_slot: u64,
        checks: Checks,
    },
}

#[derive(Debug, serde::Deserialize)]
struct Checks {
    finalized_header: RootAtSlot,
    optimistic_header: RootAtSlot,
}

#[derive(Debug, serde::Deserialize)]
struct RootAtSlot {
    slot: u64,
    beacon_root: String,
}
#[rstest]
fn test_verify(
    #[files("../consensus-spec-tests/tests/minimal/altair/light_client/sync/pyspec_tests/**")] path: PathBuf,
) {
    let bootstrap: LightClientBootstrap =
        load_snappy_ssz(&path.join("bootstrap.ssz_snappy").to_str().unwrap()).unwrap();
    let meta: TestMeta = load_yaml(&path.join("meta.yaml").to_str().unwrap());
    let steps: Vec<TestStep> = load_yaml(&path.join("steps.yaml").to_str().unwrap());

    // let genesis_validators_root = Node::try_from(
    //     hex::decode(meta.genesis_validators_root.trim_start_matches("0x"))
    //         .unwrap()
    //         .as_slice(),
    // )
    // .unwrap();
    // let fork_data = ForkData {
    //     fork_version: [1, 0, 0, 1],
    //     genesis_validators_root: genesis_validators_root.clone(),
    // };
    // println!("fork_data: 0x{:?}", hex::encode(fork_data.fork_digest()));

    // let updates = steps
    //     .iter()
    //     .filter_map(|step| match step {
    //         TestStep::ProcessUpdate { update, .. } => {
    //             let update: LightClientUpdate = load_snappy_ssz(
    //                 &path
    //                     .join(format!("{}.ssz_snappy", update))
    //                     .to_str()
    //                     .unwrap(),
    //             )
    //             .unwrap();
    //             Some(update)
    //         }
    //         _ => None,
    //     })
    //     .collect::<Vec<_>>();

    // // pretend we are in the prior sync period and therefore the bootstrap current_sync_committee is actually the next_sync_committee
    // let pre_state = ZiplineLightClientState {
    //     sync_period: slot_to_sync_period(bootstrap.header.beacon.slot),
    //     next_sync_committee_root: bootstrap
    //         .current_sync_committee
    //         .clone()
    //         .hash_tree_root()
    //         .unwrap(),
    // };

    // let post_state = ZiplineLightClientState {
    //     sync_period: slot_to_sync_period(bootstrap.header.beacon.slot) + 1,
    //     next_sync_committee_root: updates[0]
    //         .next_sync_committee
    //         .clone()
    //         .hash_tree_root()
    //         .unwrap(),
    // };

    // let witness = ZiplineWitness {
    //     committee: bootstrap.current_sync_committee.clone(),
    //     light_client_update: updates[0].clone(),
    // };

    // verify(&fork_data, &pre_state, &post_state, &witness).unwrap();
}
