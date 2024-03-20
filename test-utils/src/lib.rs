// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod test_types;
use crate::test_types::{TestMeta, TestStep};
use blst::min_pk as bls;
use eth_types::{Minimal, LIMB_BITS};
use ethereum_types::{
    BeaconBlockHeader, Domain, EthSpec, ExecutionPayloadHeader, ForkData, Hash256,
    LightClientBootstrapCapella, LightClientUpdateCapella, MinimalEthSpec, SyncCommittee,
};
use ethers::types::H256;
use itertools::Itertools;
use lightclient_circuits::poseidon::poseidon_committee_commitment_from_uncompressed;
use lightclient_circuits::witness::{CommitteeUpdateArgs, SyncStepArgs};
use serde::Deserialize;
use tree_hash::TreeHash;

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

// loads the boostrap on the path and return the initial sync committee poseidon and sync period
pub fn get_initial_sync_committee_poseidon<const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: usize>(
    path: &Path,
) -> anyhow::Result<(usize, ethers::prelude::U256)> {
    let bootstrap: LightClientBootstrapCapella<MinimalEthSpec> =
        load_snappy_ssz(path.join("bootstrap.ssz_snappy").to_str().unwrap()).unwrap();
    let pubkeys_uncompressed = bootstrap
        .current_sync_committee
        .pubkeys
        .iter()
        .map(|pk| {
            bls::PublicKey::uncompress(&pk.serialize())
                .unwrap()
                .serialize()
                .to_vec()
        })
        .collect_vec();
    let committee_poseidon =
        poseidon_committee_commitment_from_uncompressed(&pubkeys_uncompressed, LIMB_BITS);
    let committee_poseidon =
        ethers::prelude::U256::from_little_endian(&committee_poseidon.to_bytes());
    let sync_period = (usize::try_from(bootstrap.header.beacon.slot).expect("truncated"))
        / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    Ok((sync_period, committee_poseidon))
}

pub fn validators_root_from_test_path(path: &Path) -> H256 {
    let meta: TestMeta = load_yaml(path.join("meta.yaml").to_str().unwrap());
    H256(
        hex::decode(meta.genesis_validators_root.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

// Load the updates for a given test and only includes the first sequence of steps that Spectre can perform
// e.g. the the steps are cut at the first `ForceUpdate` step
pub fn valid_updates_from_test_path(path: &Path) -> Vec<LightClientUpdateCapella<MinimalEthSpec>> {
    let steps: Vec<TestStep> = load_yaml(path.join("steps.yaml").to_str().unwrap());
    let updates = steps
        .iter()
        .take_while(|step| matches!(step, TestStep::ProcessUpdate { .. }))
        .filter_map(|step| match step {
            TestStep::ProcessUpdate { update, .. } => {
                let update: LightClientUpdateCapella<MinimalEthSpec> = load_snappy_ssz(
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
    updates
}

pub fn load_yaml<T: for<'de> Deserialize<'de>>(path: &str) -> T {
    let mut file = File::open(path).unwrap_or_else(|_| {
        panic!(
            "File {} does not exist from dir {:?}",
            path,
            std::env::current_dir().unwrap()
        )
    });
    let deserializer = serde_yaml::Deserializer::from_reader(&mut file);
    let test_case: Result<T, _> =
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer);
    match test_case {
        Ok(test_case) => test_case,
        Err(err) => {
            let content = std::fs::read_to_string(path).unwrap();
            panic!("{err} from {content} at {path:?}")
        }
    }
}

pub fn load_snappy_ssz_bytes(path: &Path) -> Vec<u8> {
    let mut file = File::open(path).unwrap();
    let mut data = vec![];
    file.read_to_end(&mut data).unwrap();

    let mut decoder = snap::raw::Decoder::new();
    decoder.decompress_vec(&data).unwrap()
}

pub fn load_snappy_ssz<T: ssz::Decode>(path: &str) -> Option<T> {
    let path = Path::new(path);
    if !path.exists() {
        // panic!("Path to snappy_ssz file does not exist: {:?} from dir {:?}", path, std::env::current_dir());
        return None;
    }
    let buffer = load_snappy_ssz_bytes(path);

    let result = <T as ssz::Decode>::from_ssz_bytes(&buffer).unwrap();

    Some(result)
}

pub fn read_test_files_and_gen_witness(
    path: &Path,
) -> (SyncStepArgs<Minimal>, CommitteeUpdateArgs<Minimal>) {
    let bootstrap: LightClientBootstrapCapella<MinimalEthSpec> =
        load_snappy_ssz(path.join("bootstrap.ssz_snappy").to_str().unwrap()).unwrap();

    let genesis_validators_root = validators_root_from_test_path(path);
    let updates = valid_updates_from_test_path(path);

    let sync_wit = to_sync_ciruit_witness(
        bootstrap.current_sync_committee,
        &updates[0],
        genesis_validators_root,
    );

    let mut sync_committee_branch = updates[0]
        .next_sync_committee_branch
        .iter()
        .map(|n| n.0.to_vec())
        .collect_vec();

    let agg_pk = updates[0]
        .next_sync_committee
        .aggregate_pubkey
        .tree_hash_root()
        .0
        .to_vec();

    sync_committee_branch.insert(0, agg_pk);

    let rotation_wit = CommitteeUpdateArgs::<Minimal> {
        pubkeys_compressed: updates[0]
            .next_sync_committee
            .pubkeys
            .iter()
            .cloned()
            .map(|pk| pk.serialize().to_vec())
            .collect_vec(),
        finalized_header: sync_wit.attested_header.clone(),
        sync_committee_branch,
        _spec: Default::default(),
    };
    (sync_wit, rotation_wit)
}

fn to_sync_ciruit_witness(
    committee: Arc<SyncCommittee<MinimalEthSpec>>,
    light_client_update: &LightClientUpdateCapella<MinimalEthSpec>,
    genesis_validators_root: Hash256,
) -> SyncStepArgs<Minimal> {
    let mut args = SyncStepArgs::<Minimal> {
        signature_compressed: light_client_update
            .sync_aggregate
            .sync_committee_signature
            .serialize()
            .to_vec(),
        ..Default::default()
    };

    let pubkeys_uncompressed = committee
        .pubkeys
        .iter()
        .map(|pk| {
            bls::PublicKey::uncompress(&pk.serialize())
                .unwrap()
                .serialize()
                .to_vec()
        })
        .collect_vec();
    args.pubkeys_uncompressed = pubkeys_uncompressed;
    args.pariticipation_bits = light_client_update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .map(|b| b)
        .collect();
    args.attested_header = BeaconBlockHeader {
        slot: light_client_update.attested_header.beacon.slot,
        proposer_index: light_client_update.attested_header.beacon.proposer_index,
        parent_root: light_client_update.attested_header.beacon.parent_root,
        state_root: light_client_update.attested_header.beacon.state_root,
        body_root: light_client_update.attested_header.beacon.body_root,
    };
    args.finalized_header = BeaconBlockHeader {
        slot: light_client_update.finalized_header.beacon.slot,
        proposer_index: light_client_update.finalized_header.beacon.proposer_index,
        parent_root: light_client_update.finalized_header.beacon.parent_root,
        state_root: light_client_update.finalized_header.beacon.state_root,
        body_root: light_client_update.finalized_header.beacon.body_root,
    };
    let fork_data = ForkData {
        current_version: [3, 0, 0, 1],
        genesis_validators_root,
    };

    let domain = MinimalEthSpec::default_spec().compute_domain(
        Domain::SyncCommittee,
        [3, 0, 0, 1],
        genesis_validators_root,
    );
    args.domain = domain.into();
    args.execution_payload_branch = light_client_update
        .finalized_header
        .execution_branch
        .iter()
        .map(|b| b.0.as_ref().to_vec())
        .collect();
    args.execution_payload_root = {
        let mut execution_payload_header: ExecutionPayloadHeader<MinimalEthSpec> =
            light_client_update
                .finalized_header
                .execution
                .clone()
                .into();

        execution_payload_header.tree_hash_root().0.to_vec()
    };
    args.finality_branch = light_client_update
        .finality_branch
        .iter()
        .map(|b| b.0.to_vec())
        .collect();
    args
}
