use eth_types::Minimal;
use ethereum_consensus_types::presets::minimal::{LightClientBootstrap, LightClientUpdateCapella};
use ethereum_consensus_types::signing::{compute_domain, DomainType};
use ethereum_consensus_types::{ForkData, Root};
use halo2curves::bn256::Fr;
use itertools::Itertools;
use light_client_verifier::ZiplineUpdateWitnessCapella;
use lightclient_circuits::gadget::crypto;
use lightclient_circuits::witness::{CommitteeRotationArgs, SyncStepArgs};
use ssz_rs::prelude::*;
use ssz_rs::Merkleized;
use ssz_rs::Node;
use std::path::PathBuf;
use sync_committee_primitives::consensus_types::BeaconBlockHeader;
use zipline_test_utils::{load_snappy_ssz, load_yaml};

use crate::execution_payload_header::ExecutionPayloadHeader;
use crate::test_types::{ByteVector, TestMeta, TestStep};

mod execution_payload_header;
mod test_types;

pub fn read_test_files_and_gen_witness(
    path: PathBuf,
) -> (SyncStepArgs<Minimal>, CommitteeRotationArgs<Minimal, Fr>) {
    let bootstrap: LightClientBootstrap =
        load_snappy_ssz(path.join("bootstrap.ssz_snappy").to_str().unwrap()).unwrap();
    let meta: TestMeta = load_yaml(path.join("meta.yaml").to_str().unwrap());
    let steps: Vec<TestStep> = load_yaml(path.join("steps.yaml").to_str().unwrap());

    let genesis_validators_root = Root::try_from(
        hex::decode(meta.genesis_validators_root.trim_start_matches("0x"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let updates = steps
        .iter()
        .filter_map(|step| match step {
            TestStep::ProcessUpdate { update, .. } => {
                let update: LightClientUpdateCapella = load_snappy_ssz(
                    path.join(format!("{}.ssz_snappy", update))
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
                Some(update)
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    let zipline_witness = light_client_verifier::ZiplineUpdateWitnessCapella {
        committee: bootstrap.current_sync_committee,
        light_client_update: updates[0].clone(),
    };
    let sync_wit = to_sync_ciruit_witness(&zipline_witness, genesis_validators_root);

    let mut sync_committee_branch = zipline_witness
        .light_client_update
        .next_sync_committee_branch
        .iter()
        .map(|n| n.as_ref().to_vec())
        .collect_vec();

    let agg_pubkeys_compressed = zipline_witness
        .light_client_update
        .next_sync_committee
        .aggregate_pubkey
        .to_bytes()
        .to_vec();

    let mut agg_pk: ByteVector<48> = ByteVector(Vector::try_from(agg_pubkeys_compressed).unwrap());

    sync_committee_branch.insert(0, agg_pk.hash_tree_root().unwrap().as_ref().to_vec());

    let rotation_wit = CommitteeRotationArgs::<Minimal, Fr> {
        pubkeys_compressed: zipline_witness
            .light_client_update
            .next_sync_committee
            .pubkeys
            .iter()
            .cloned()
            .map(|pk| pk.to_bytes().to_vec())
            .collect_vec(),
        randomness: crypto::constant_randomness(),
        _spec: Default::default(),
        finalized_header: sync_wit.attested_header.clone(),
        sync_committee_branch,
    };
    (sync_wit, rotation_wit)
}

fn to_sync_ciruit_witness<
    const SYNC_COMMITTEE_SIZE: usize,
    const NEXT_SYNC_COMMITTEE_GINDEX: usize,
    const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
    const FINALIZED_ROOT_GINDEX: usize,
    const FINALIZED_ROOT_PROOF_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    zipline_witness: &ZiplineUpdateWitnessCapella<
        SYNC_COMMITTEE_SIZE,
        NEXT_SYNC_COMMITTEE_GINDEX,
        NEXT_SYNC_COMMITTEE_PROOF_SIZE,
        FINALIZED_ROOT_GINDEX,
        FINALIZED_ROOT_PROOF_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
    genesis_validators_root: Root,
) -> SyncStepArgs<Minimal> {
    let mut args = SyncStepArgs::<Minimal> {
        signature_compressed: zipline_witness
            .light_client_update
            .sync_aggregate
            .sync_committee_signature
            .to_bytes()
            .to_vec(),
        ..Default::default()
    };

    args.signature_compressed.reverse();
    let pubkeys_uncompressed = zipline_witness
        .committee
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
    args.pubkeys_uncompressed = pubkeys_uncompressed;
    args.pariticipation_bits = zipline_witness
        .light_client_update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .map(|b| *b)
        .collect();
    args.attested_header = BeaconBlockHeader {
        slot: zipline_witness
            .light_client_update
            .attested_header
            .beacon
            .slot,
        proposer_index: zipline_witness
            .light_client_update
            .attested_header
            .beacon
            .proposer_index as u64,
        parent_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .beacon
                .parent_root
                .as_ref(),
        )
        .unwrap(),
        state_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .beacon
                .state_root
                .as_ref(),
        )
        .unwrap(),
        body_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .beacon
                .body_root
                .as_ref(),
        )
        .unwrap(),
    };
    args.finalized_header = BeaconBlockHeader {
        slot: zipline_witness
            .light_client_update
            .finalized_header
            .beacon
            .slot,
        proposer_index: zipline_witness
            .light_client_update
            .finalized_header
            .beacon
            .proposer_index as u64,
        parent_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .beacon
                .parent_root
                .as_ref(),
        )
        .unwrap(),
        state_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .beacon
                .state_root
                .as_ref(),
        )
        .unwrap(),
        body_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .beacon
                .body_root
                .as_ref(),
        )
        .unwrap(),
    };
    let fork_data = ForkData {
        fork_version: [3, 0, 0, 1],
        genesis_validators_root,
    };
    let signing_domain = compute_domain(DomainType::SyncCommittee, &fork_data).unwrap();
    args.domain = signing_domain;
    args.execution_payload_branch = zipline_witness
        .light_client_update
        .finalized_header
        .execution_branch
        .iter()
        .map(|b| b.0.as_ref().to_vec())
        .collect();
    args.execution_payload_root = {
        let mut execution_payload_header: ExecutionPayloadHeader<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        > = zipline_witness
            .light_client_update
            .finalized_header
            .execution
            .clone()
            .into();

        execution_payload_header
            .hash_tree_root()
            .unwrap()
            .as_ref()
            .to_vec()
    };
    args.finality_branch = zipline_witness
        .light_client_update
        .finality_branch
        .iter()
        .map(|b| b.as_ref().to_vec())
        .collect();
    args
}
