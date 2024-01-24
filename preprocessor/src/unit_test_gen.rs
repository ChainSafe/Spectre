// NOT FOR USE IN PROD!
// Used to generate files for circuit unit tests
use ethereum_consensus::capella::mainnet::{
    BeaconBlockBody, BeaconBlockHeader, BeaconState, Validator,
};
use ethereum_consensus::crypto::{self, eth_aggregate_public_keys, SecretKey};
use ethereum_consensus::primitives::DomainType;
use ethereum_consensus::signing::compute_signing_root;
use ethereum_consensus::state_transition::Context;
use itertools::Itertools as _;
use lightclient_circuits::witness::{
    block_header_to_leaves, get_helper_indices, merkle_tree, parent, CommitteeUpdateArgs,
    SyncStepArgs,
};
use ssz_rs::{MerkleizationError, Merkleized, Node};
use std::fs::File;
use std::io::Read;
use std::ops::Deref;

use eth_types::{Mainnet, Spec as _};

fn main() {
    const PRIVATE_KEYS_PATH: &str = "../test_data/private_keys.json";
    const BEACON_STATE_PATH: &str = "../test_data/beacon_state_2915750";
    const N_VALIDATORS: usize = 512;

    let priv_key_hex: Vec<[u8; 32]> = {
        let deser =
            serde_json::from_reader::<_, Vec<String>>(File::open(PRIVATE_KEYS_PATH).unwrap())
                .unwrap()
                .into_iter();
        deser
            .map(|x| {
                hex::decode(x.trim_start_matches("0x"))
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<[u8; 32]>>()
    };
    let priv_key = priv_key_hex
        .iter()
        .map(|sk| SecretKey::try_from(sk.as_slice()).unwrap());

    let mut beacon_state: BeaconState = {
        let mut file = File::open(BEACON_STATE_PATH).unwrap();
        let mut buf = vec![];
        file.read_to_end(&mut buf).unwrap();
        ssz_rs::Deserialize::deserialize(&buf).unwrap()
    };

    let validators = (0..N_VALIDATORS)
        .map(|i| {
            let sk = SecretKey::try_from(priv_key_hex[i].as_slice()).unwrap();
            let pubkey = sk.public_key();
            let bls_public_key = pubkey;

            Validator {
                public_key: bls_public_key.clone(),
                withdrawal_credentials: Default::default(),
                effective_balance: 32_000_000,
                slashed: false,
                activation_eligibility_epoch: i as u64,
                activation_epoch: i as u64 + 1,
                exit_epoch: 100,
                withdrawable_epoch: 0,
            }
        })
        .collect::<Vec<_>>();

    let pubkeys = validators
        .iter()
        .map(|x| x.public_key.clone())
        .collect::<Vec<_>>();

    beacon_state.validators = validators.try_into().unwrap();
    beacon_state.current_sync_committee.public_keys = pubkeys.clone().try_into().unwrap();
    beacon_state.next_sync_committee.public_keys = pubkeys.clone().try_into().unwrap();
    beacon_state.current_sync_committee.aggregate_public_key =
        eth_aggregate_public_keys(&pubkeys).unwrap();

    let mut beacon_block_body = BeaconBlockBody {
        eth1_data: beacon_state.eth1_data.clone(),
        ..Default::default()
    };

    let exec_payload_merkle_proof =
        exec_payload_merkle_proof(&mut beacon_block_body.clone()).unwrap();
    let exec_payload_root = beacon_block_body
        .execution_payload
        .hash_tree_root()
        .unwrap();

    let mut finalized_block = BeaconBlockHeader {
        body_root: beacon_block_body.hash_tree_root().unwrap(),
        ..Default::default()
    };

    beacon_state.finalized_checkpoint.root = finalized_block.hash_tree_root().unwrap();

    let beacon_state_root = beacon_state.hash_tree_root().unwrap();
    let mut attested_block = BeaconBlockHeader {
        slot: 32,
        proposer_index: 0,
        parent_root: Default::default(),
        state_root: beacon_state_root,
        body_root: beacon_state.finalized_checkpoint.root,
    };
    let context = Context::for_mainnet();

    let domain = ethereum_consensus::capella::compute_domain(
        DomainType::SyncCommittee,
        None,
        Some(beacon_state.genesis_validators_root),
        &context,
    )
    .unwrap();

    let data_root = compute_signing_root(&mut attested_block, domain).unwrap();

    let sigs = priv_key
        .map(|sk| {
            let sig = sk.sign(data_root.as_ref());
            sig
        })
        .collect::<Vec<_>>();
    let agg_sig = crypto::aggregate(&sigs).unwrap();

    // Sanity check
    crypto::eth_fast_aggregate_verify(
        pubkeys.iter().collect_vec().as_slice(),
        &data_root,
        &agg_sig,
    )
    .unwrap();

    let finalized_block_merkle_proof =
        finalized_checkpoint_block_root_proof(&mut beacon_state.clone()).unwrap();

    let committee_root_merkle_proof =
        committee_root_merkle_proof(&mut beacon_state.clone()).unwrap();

    // Conversion from ethereum_consensus block header to ours
    let attested_header = ethereum_consensus_types::BeaconBlockHeader {
        slot: attested_block.slot,
        proposer_index: attested_block.proposer_index,
        parent_root: attested_block.parent_root,
        state_root: attested_block.state_root,
        body_root: attested_block.body_root,
    };
    let finalized_header = ethereum_consensus_types::BeaconBlockHeader {
        slot: finalized_block.slot,
        proposer_index: finalized_block.proposer_index,
        parent_root: finalized_block.parent_root,
        state_root: finalized_block.state_root,
        body_root: finalized_block.body_root,
    };

    let beacon_header_multiproof_and_helper_indices =
        |header: &mut ethereum_consensus_types::BeaconBlockHeader, gindices: &[usize]| {
            let header_leaves = block_header_to_leaves(header).unwrap();
            let merkle_tree = merkle_tree(&header_leaves);
            let helper_indices = get_helper_indices(gindices);
            let proof = helper_indices
                .iter()
                .copied()
                .map(|i| merkle_tree[i])
                .collect_vec();
            assert_eq!(proof.len(), helper_indices.len());
            (proof, helper_indices)
        };

    // Proof length is 3
    let (attested_header_multiproof, attested_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &mut attested_header.clone(),
            &[Mainnet::HEADER_SLOT_INDEX, Mainnet::HEADER_STATE_ROOT_INDEX],
        );
    // Proof length is 4
    let (finalized_header_multiproof, finalized_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &mut finalized_header.clone(),
            &[Mainnet::HEADER_SLOT_INDEX, Mainnet::HEADER_BODY_ROOT_INDEX],
        );

    let sync_args: SyncStepArgs<Mainnet> = SyncStepArgs {
        signature_compressed: {
            ethereum_consensus_types::BlsSignature::try_from(hex::encode(agg_sig.deref()))
                .unwrap()
                .to_bytes()
                .to_vec()
        },
        pubkeys_uncompressed: beacon_state
            .validators
            .iter()
            .map(|v| {
                ethereum_consensus_types::BlsPublicKey::try_from(hex::encode(v.public_key.deref()))
                    .unwrap()
                    .decompressed_bytes()
            })
            .collect_vec(),
        pariticipation_bits: beacon_state.validators.iter().map(|_| true).collect_vec(),
        attested_header: attested_header.clone(),
        finalized_header,
        finality_branch: finalized_block_merkle_proof
            .iter()
            .map(|x| x.to_vec())
            .collect_vec(),
        execution_payload_root: exec_payload_root.to_vec(),
        execution_payload_branch: exec_payload_merkle_proof
            .iter()
            .map(|x| x.to_vec())
            .collect_vec(),
        domain,
        _spec: std::marker::PhantomData,

        attested_header_multiproof: attested_header_multiproof
            .into_iter()
            .map(|n| n.as_ref().to_vec())
            .collect_vec(),
        attested_header_helper_indices,
        finalized_header_multiproof: finalized_header_multiproof
            .into_iter()
            .map(|n| n.as_ref().to_vec())
            .collect_vec(),
        finalized_header_helper_indices,
    };

    let (attested_header_multiproof, attested_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &mut attested_header.clone(),
            &[Mainnet::HEADER_STATE_ROOT_INDEX],
        );

    let rotation_args: CommitteeUpdateArgs<Mainnet> = CommitteeUpdateArgs {
        pubkeys_compressed: pubkeys.iter().map(|x| x.deref().to_vec()).collect_vec(),
        finalized_header: attested_header,
        sync_committee_branch: committee_root_merkle_proof
            .iter()
            .map(|x| x.to_vec())
            .collect_vec(),
        _spec: std::marker::PhantomData,
        finalized_header_multiproof: attested_header_multiproof
            .into_iter()
            .map(|n| n.as_ref().to_vec())
            .collect_vec(),
        finalized_header_helper_indices: attested_header_helper_indices,
    };

    std::fs::write(
        "../test_data/sync_step_512.json",
        serde_json::to_string(&sync_args).unwrap(),
    )
    .unwrap();
    std::fs::write(
        "../test_data/rotation_512.json",
        serde_json::to_string(&rotation_args).unwrap(),
    )
    .unwrap();
}

pub fn committee_root_merkle_proof(
    beacon_state: &mut BeaconState,
) -> Result<Vec<Node>, MerkleizationError> {
    let leaves = beacon_state_to_leaves(beacon_state)?;
    let merkle_tree = merkle_tree(&leaves);
    let helper_indices = get_helper_indices(&[parent(Mainnet::SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX)]);
    let mut proof = helper_indices
        .iter()
        .copied()
        .map(|i| merkle_tree[i])
        .collect_vec();
    assert_eq!(proof.len(), helper_indices.len());
    proof.insert(
        0,
        beacon_state
            .next_sync_committee
            .aggregate_public_key
            .hash_tree_root()?,
    );
    assert_eq!(proof.len(), Mainnet::SYNC_COMMITTEE_PUBKEYS_DEPTH);
    Ok(proof)
}

pub fn exec_payload_merkle_proof(
    body: &mut BeaconBlockBody,
) -> Result<Vec<Node>, MerkleizationError> {
    let leaves = block_body_to_leaves(body)?;
    let merkle_tree = merkle_tree(&leaves);
    let helper_indices = get_helper_indices(&[Mainnet::EXECUTION_STATE_ROOT_INDEX]);
    let proof = helper_indices
        .iter()
        .copied()
        .map(|i| merkle_tree[i])
        .collect_vec();
    assert_eq!(proof.len(), helper_indices.len());
    Ok(proof)
}

fn finalized_checkpoint_block_root_proof(
    beacon_state: &mut BeaconState,
) -> Result<Vec<Node>, MerkleizationError> {
    let leaves = beacon_state_to_leaves(beacon_state)?;
    let merkle_tree = merkle_tree(&leaves);
    let helper_indices = get_helper_indices(&[parent(Mainnet::FINALIZED_HEADER_INDEX)]);
    let mut proof = helper_indices
        .iter()
        .copied()
        .map(|i| merkle_tree[i])
        .collect_vec();
    assert_eq!(proof.len(), helper_indices.len());
    proof.insert(0, beacon_state.finalized_checkpoint.epoch.hash_tree_root()?);
    assert_eq!(proof.len(), Mainnet::FINALIZED_HEADER_DEPTH);
    Ok(proof)
}

fn block_body_to_leaves(body: &mut BeaconBlockBody) -> Result<[Node; 11], MerkleizationError> {
    Ok([
        body.randao_reveal.hash_tree_root()?,
        body.eth1_data.hash_tree_root()?,
        body.graffiti.hash_tree_root()?,
        body.proposer_slashings.hash_tree_root()?,
        body.attester_slashings.hash_tree_root()?,
        body.attestations.hash_tree_root()?,
        body.deposits.hash_tree_root()?,
        body.voluntary_exits.hash_tree_root()?,
        body.sync_aggregate.hash_tree_root()?,
        body.execution_payload.hash_tree_root()?,
        body.bls_to_execution_changes.hash_tree_root()?,
    ])
}

fn beacon_state_to_leaves(state: &mut BeaconState) -> Result<[Node; 28], MerkleizationError> {
    Ok([
        state.genesis_time.hash_tree_root()?,
        state.genesis_validators_root.hash_tree_root()?,
        state.slot.hash_tree_root()?,
        state.fork.hash_tree_root()?,
        state.latest_block_header.hash_tree_root()?,
        state.block_roots.hash_tree_root()?,
        state.state_roots.hash_tree_root()?,
        state.historical_roots.hash_tree_root()?,
        state.eth1_data.hash_tree_root()?,
        state.eth1_data_votes.hash_tree_root()?,
        state.eth1_deposit_index.hash_tree_root()?,
        state.validators.hash_tree_root()?,
        state.balances.hash_tree_root()?,
        state.randao_mixes.hash_tree_root()?,
        state.slashings.hash_tree_root()?,
        state.previous_epoch_participation.hash_tree_root()?,
        state.current_epoch_participation.hash_tree_root()?,
        state.justification_bits.hash_tree_root()?,
        state.previous_justified_checkpoint.hash_tree_root()?,
        state.current_justified_checkpoint.hash_tree_root()?,
        state.finalized_checkpoint.hash_tree_root()?,
        state.inactivity_scores.hash_tree_root()?,
        state.current_sync_committee.hash_tree_root()?,
        state.next_sync_committee.hash_tree_root()?,
        state.latest_execution_payload_header.hash_tree_root()?,
        state.next_withdrawal_index.hash_tree_root()?,
        state.next_withdrawal_validator_index.hash_tree_root()?,
        state.historical_summaries.hash_tree_root()?,
    ])
}
