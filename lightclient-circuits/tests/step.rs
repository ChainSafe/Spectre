use eth_types::Test;
use ethereum_consensus_types::presets::minimal::{LightClientBootstrap, LightClientUpdate};
use ethereum_consensus_types::signing::{compute_domain, DomainType};
use ethereum_consensus_types::{ForkData, Root};
use halo2curves::bn256::{self, Bn256};
use light_client_verifier::ZiplineWitness;
use lightclient_circuits::sync_step_circuit::SyncStepCircuit;
use lightclient_circuits::witness::SyncStepArgs;
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

fn to_witness<
    const SYNC_COMMITTEE_SIZE: usize,
    const NEXT_SYNC_COMMITTEE_GINDEX: usize,
    const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
    const FINALIZED_ROOT_GINDEX: usize,
    const FINALIZED_ROOT_PROOF_SIZE: usize,
>(
    zipline_witness: &ZiplineWitness<
        SYNC_COMMITTEE_SIZE,
        NEXT_SYNC_COMMITTEE_GINDEX,
        NEXT_SYNC_COMMITTEE_PROOF_SIZE,
        FINALIZED_ROOT_GINDEX,
        FINALIZED_ROOT_PROOF_SIZE,
    >,
    genesis_validators_root: Root,
) -> SyncStepArgs<Test> {
    let mut args = SyncStepArgs::<Test>::default();
    args.signature_compressed = zipline_witness
        .light_client_update
        .sync_aggregate
        .sync_committee_signature
        .to_bytes()
        .to_vec();
    args.pubkeys_uncompressed = zipline_witness
        .committee
        .pubkeys
        .iter()
        .map(|pk| pk.to_bytes().to_vec())
        .collect();
    args.pariticipation_bits = zipline_witness
        .light_client_update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .map(|b| *b)
        .collect();
    args.attested_block = ethereum_consensus::phase0::BeaconBlockHeader {
        slot: zipline_witness.light_client_update.attested_header.slot,
        proposer_index: zipline_witness
            .light_client_update
            .attested_header
            .proposer_index,
        parent_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .parent_root
                .as_ref(),
        )
        .unwrap(),
        state_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .state_root
                .as_ref(),
        )
        .unwrap(),
        body_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .body_root
                .as_ref(),
        )
        .unwrap(),
    };
    args.finalized_block = ethereum_consensus::phase0::BeaconBlockHeader {
        slot: zipline_witness.light_client_update.finalized_header.slot,
        proposer_index: zipline_witness
            .light_client_update
            .finalized_header
            .proposer_index,
        parent_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .parent_root
                .as_ref(),
        )
        .unwrap(),
        state_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .state_root
                .as_ref(),
        )
        .unwrap(),
        body_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .body_root
                .as_ref(),
        )
        .unwrap(),
    };
    let fork_data = ForkData {
        fork_version: [1, 0, 0, 1],
        genesis_validators_root: genesis_validators_root.clone(),
    };
    let signing_domain = compute_domain(DomainType::SyncCommittee, &fork_data).unwrap();
    args.domain = signing_domain;
    args.execution_merkle_branch = vec![vec![]];
    args.execution_state_root = vec![];
    args.finality_merkle_branch = zipline_witness
        .light_client_update
        .finality_branch
        .iter()
        .map(|b| b.as_ref().to_vec())
        .collect();
    args.beacon_state_root = args.attested_block.state_root.as_ref().to_vec();

    args
}
#[rstest]
fn test_verify(
    #[files("../consensus-spec-tests/tests/minimal/altair/light_client/sync/pyspec_tests/**")] path: PathBuf,
) {
    let bootstrap: LightClientBootstrap =
        load_snappy_ssz(&path.join("bootstrap.ssz_snappy").to_str().unwrap()).unwrap();
    let meta: TestMeta = load_yaml(&path.join("meta.yaml").to_str().unwrap());
    let steps: Vec<TestStep> = load_yaml(&path.join("steps.yaml").to_str().unwrap());

    let genesis_validators_root = Root::try_from(
        hex::decode(meta.genesis_validators_root.trim_start_matches("0x"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let fork_data = ForkData {
        fork_version: [1, 0, 0, 1],
        genesis_validators_root: genesis_validators_root.clone(),
    };
    println!("fork_data: 0x{:?}", hex::encode(fork_data.fork_digest()));

    let circuit = SyncStepCircuit::<Test, bn256::Fr>::default();
    let updates = steps
        .iter()
        .filter_map(|step| match step {
            TestStep::ProcessUpdate { update, .. } => {
                let update: LightClientUpdate = load_snappy_ssz(
                    &path
                        .join(format!("{}.ssz_snappy", update))
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
                Some(update)
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    let witness = ZiplineWitness {
        committee: bootstrap.current_sync_committee.clone(),
        light_client_update: updates[0].clone(),
    };

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

    // verify(&fork_data, &pre_state, &post_state, &witness).unwrap();
}
