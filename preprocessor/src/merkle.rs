// TODO: A lot if not all/most of this code is copy pasta from: https://github.com/ralexstokes/ssz-rs/pull/118
// TODO: Remove this once the above PR lands in ssz-rs

use std::collections::HashSet;

use beacon_api_client::{mainnet::Client as MainnetClient, BlockId, ClientTypes};
use ethereum_consensus_types::BeaconBlockHeader;
use sha2::{Digest, Sha256};
use ssz_rs::{MerkleizationError, Merkleized, Node, SimpleSerialize};

// From: https://users.rust-lang.org/t/logarithm-of-integers/8506/5
const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

const fn log_2(x: usize) -> u32 {
    assert!(x > 0);
    num_bits::<usize>() as u32 - x.leading_zeros() - 1
}

pub const fn get_power_of_two_ceil(x: usize) -> usize {
    match x {
        x if x <= 1 => 1,
        2 => 2,
        x => 2 * get_power_of_two_ceil((x + 1) / 2),
    }
}

pub type GeneralizedIndex = usize;

pub const fn get_path_length(index: GeneralizedIndex) -> usize {
    log_2(index) as usize
}

pub const fn get_bit(index: GeneralizedIndex, position: usize) -> bool {
    index & (1 << position) > 0
}

pub const fn sibling(index: GeneralizedIndex) -> GeneralizedIndex {
    index ^ 1
}

pub const fn child_left(index: GeneralizedIndex) -> GeneralizedIndex {
    index * 2
}

pub const fn child_right(index: GeneralizedIndex) -> GeneralizedIndex {
    index * 2 + 1
}

pub const fn parent(index: GeneralizedIndex) -> GeneralizedIndex {
    index / 2
}

fn get_branch_indices(tree_index: GeneralizedIndex) -> Vec<GeneralizedIndex> {
    let mut focus = sibling(tree_index);
    let mut result = vec![focus.clone()];
    while focus > 1 {
        focus = sibling(parent(focus));
        result.push(focus);
    }
    result.truncate(result.len() - 1);
    result
}

fn get_path_indices(tree_index: GeneralizedIndex) -> Vec<GeneralizedIndex> {
    let mut focus = tree_index;
    let mut result = vec![focus];
    while focus > 1 {
        focus = parent(focus);
        result.push(focus.clone());
    }
    result.truncate(result.len() - 1);
    result
}

fn get_helper_indices(indices: &[GeneralizedIndex]) -> Vec<GeneralizedIndex> {
    let mut all_helper_indices = HashSet::new();
    let mut all_path_indices = HashSet::new();

    for index in indices {
        all_helper_indices.extend(get_branch_indices(*index).iter());
        all_path_indices.extend(get_path_indices(*index).iter());
    }

    let mut all_branch_indices = all_helper_indices
        .difference(&all_path_indices)
        .cloned()
        .collect::<Vec<_>>();
    all_branch_indices.sort_by(|a: &GeneralizedIndex, b: &GeneralizedIndex| b.cmp(a));
    all_branch_indices
}

pub fn calculate_merkle_root(leaf: Node, proof: &[Node], index: GeneralizedIndex) -> Node {
    debug_assert_eq!(proof.len(), get_path_length(index));
    let mut result = leaf;

    let mut hasher = Sha256::new();
    for (i, next) in proof.iter().enumerate() {
        if get_bit(index, i) {
            hasher.update(next.as_ref());
            hasher.update(result.as_ref());
        } else {
            hasher.update(result.as_ref());
            hasher.update(next.as_ref());
        }
        result.as_mut().copy_from_slice(&hasher.finalize_reset());
    }
    result
}

pub fn block_header_to_leaves(
    obj: &mut BeaconBlockHeader,
) -> Result<Vec<Node>, MerkleizationError> {
    Ok(vec![
        obj.slot.hash_tree_root()?,
        obj.proposer_index.hash_tree_root()?,
        obj.parent_root.hash_tree_root()?,
        obj.state_root.hash_tree_root()?,
        obj.body_root.hash_tree_root()?,
    ])
}

// From: https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md
// def merkle_tree(leaves: Sequence[Bytes32]) -> Sequence[Bytes32]:
//     """
//     Return an array representing the tree nodes by generalized index:
//     [0, 1, 2, 3, 4, 5, 6, 7], where each layer is a power of 2. The 0 index is ignored. The 1 index is the root.
//     The result will be twice the size as the padded bottom layer for the input leaves.
//     """
//     bottom_length = get_power_of_two_ceil(len(leaves))
//     o = [Bytes32()] * bottom_length + list(leaves) + [Bytes32()] * (bottom_length - len(leaves))
//     for i in range(bottom_length - 1, 0, -1):
//         o[i] = hash(o[i * 2] + o[i * 2 + 1])
//     return o

pub fn merkle_tree(leaves: &[Node]) -> Vec<Node> {
    let bottom_length = get_power_of_two_ceil(leaves.len());
    let mut o = vec![Node::default(); bottom_length * 2];
    o[bottom_length..bottom_length + leaves.len()].copy_from_slice(leaves);
    for i in (1..bottom_length).rev() {
        let left = o[i * 2].as_ref();
        let right = o[i * 2 + 1].as_ref();
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        o[i].as_mut().copy_from_slice(&hasher.finalize_reset());
    }
    o
}

#[cfg(test)]
mod test {
    use crate::{get_block_body, get_light_client_finality_update};

    use super::*;
    use beacon_api_client::{mainnet::Client as MainnetClient, BlockId};
    use eth_types::{Spec, Testnet};
    use ethereum_consensus_types::beacon_block_header;
    use itertools::Itertools;
    use reqwest::Url;
    use ssz_rs::prelude::*;

    #[test]
    fn test_merkle_tree() {
        let mut test_block = BeaconBlockHeader::default();
        let leaves = block_header_to_leaves(&mut test_block).unwrap();
        println!("leaves count: {:?}", leaves.len());
        assert!(
            leaves.len() == 5,
            "Leaf count should equal number of fields"
        );
        let expected_merkle_root = test_block.hash_tree_root().unwrap();
        let merkle_tree = merkle_tree(&leaves);
        println!("merkle tree count: {:?}", merkle_tree.len());
        assert!(
            expected_merkle_root == merkle_tree[1],
            "Merkle root should equal root of merkle tree"
        );
    }

    #[tokio::test]
    async fn test_proof_generation() {
        let client =
            MainnetClient::new(Url::parse("https://lodestar-sepolia.chainsafe.io").unwrap());

        let finality_update = get_light_client_finality_update::<Testnet, _>(&client)
            .await
            .unwrap();
        let execution_payload_root = finality_update
            .finalized_header
            .execution
            .clone()
            .hash_tree_root()
            .unwrap()
            .to_vec();
        let execution_payload_branch = finality_update
            .finalized_header
            .execution_branch
            .iter()
            .map(|n| n.0.to_vec())
            .collect_vec();
        assert!(
            ssz_rs::is_valid_merkle_branch(
                Node::try_from(execution_payload_root.as_slice()).unwrap(),
                &execution_payload_branch,
                Testnet::EXECUTION_STATE_ROOT_DEPTH,
                Testnet::EXECUTION_STATE_ROOT_INDEX,
                finality_update.finalized_header.beacon.body_root,
            )
            .is_ok(),
            "Execution payload merkle proof verification failed"
        );

        let mut beacon_header = finality_update.finalized_header.beacon.clone();
        let mut block_body = get_block_body(
            &client,
            BlockId::Root(beacon_header.hash_tree_root().unwrap()),
        )
        .await
        .unwrap()
        .capella()
        .unwrap()
        .message
        .body
        .clone();

        // block body to leaves
        let leaves = vec![
            block_body.randao_reveal.hash_tree_root().unwrap(),
            block_body.eth1_data.hash_tree_root().unwrap(),
            block_body.graffiti.hash_tree_root().unwrap(),
            block_body.proposer_slashings.hash_tree_root().unwrap(),
            block_body.attester_slashings.hash_tree_root().unwrap(),
            block_body.attestations.hash_tree_root().unwrap(),
            block_body.deposits.hash_tree_root().unwrap(),
            block_body.voluntary_exits.hash_tree_root().unwrap(),
            block_body.sync_aggregate.hash_tree_root().unwrap(),
            block_body.execution_payload.hash_tree_root().unwrap(),
            block_body
                .bls_to_execution_changes
                .hash_tree_root()
                .unwrap(),
        ];

        let header_as_merkle_tree = merkle_tree(&leaves);

        assert!(
            get_path_length(Testnet::EXECUTION_STATE_ROOT_INDEX)
                == Testnet::EXECUTION_STATE_ROOT_DEPTH
        );

        println!("Merkle tree count: {}", header_as_merkle_tree.len());
        for (i, node) in header_as_merkle_tree.iter().enumerate() {
            println!("{}: {:?}", i, node);
        }
        println!("Expected Merkle Proof");
        for (i, node) in finality_update
            .finalized_header
            .execution_branch
            .iter()
            .enumerate()
        {
            println!("{}: {:?}", i, Node::try_from(node.as_ref()).unwrap());
        }
        println!(
            "helper indices: {:?}",
            get_helper_indices(&[Testnet::EXECUTION_STATE_ROOT_INDEX])
        );
        let proof = get_helper_indices(&[Testnet::EXECUTION_STATE_ROOT_INDEX])
            .iter()
            .map(|i| header_as_merkle_tree[*i].clone())
            .map(|n| n.as_ref().to_vec())
            .collect_vec();
        println!("Proof");
        for (i, node) in proof.iter().enumerate() {
            println!("{}: {:?}", i, Node::try_from(node.as_slice()).unwrap());
        }
        assert_eq!(proof, execution_payload_branch);
    }
}
