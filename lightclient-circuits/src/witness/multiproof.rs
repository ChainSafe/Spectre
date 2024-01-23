// TODO: A lot if not all/most of this code is copy pasta from: https://github.com/ralexstokes/ssz-rs/pull/118 which is mostly implemented w.r.t. the spec
// TODO: Remove this once the above PR lands in ssz-rs

use sha2::{Digest, Sha256};
use ssz_rs::Node;
use std::collections::{HashMap, HashSet};

pub type GeneralizedIndex = usize;

// From: https://users.rust-lang.org/t/logarithm-of-integers/8506/5
pub const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

pub const fn log_2(x: usize) -> u32 {
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

/// Get the generalized indices of the sister chunks along the path from the chunk with the
/// given tree index to the root.
pub fn get_branch_indices(tree_index: GeneralizedIndex) -> Vec<GeneralizedIndex> {
    let mut focus = sibling(tree_index);
    let mut result = vec![focus];
    while focus > 1 {
        focus = sibling(parent(focus));
        result.push(focus);
    }
    result.truncate(result.len() - 1);
    result
}
/// Get the generalized indices of the chunks along the path from the chunk with the
/// given tree index to the root.
pub fn get_path_indices(tree_index: GeneralizedIndex) -> Vec<GeneralizedIndex> {
    let mut focus = tree_index;
    let mut result = vec![focus];
    while focus > 1 {
        focus = parent(focus);
        result.push(focus);
    }
    result.truncate(result.len() - 1);
    result
}
/// Get the generalized indices of all "extra" chunks in the tree needed to prove the chunks with the given
/// generalized indices. Note that the decreasing order is chosen deliberately to ensure equivalence to the
/// order of hashes in a regular single-item Merkle proof in the single-item case.
pub fn get_helper_indices(indices: &[GeneralizedIndex]) -> Vec<GeneralizedIndex> {
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

/// Calculate the Merkle root of a set of leaves and their corresponding proofs.
/// Note: `indices` and `leaves` must be in the same order as they correspond to each other.
pub fn calculate_multi_merkle_root(
    leaves: &[Node],
    proof: &[Node],
    indices: &[GeneralizedIndex],
) -> Node {
    assert_eq!(leaves.len(), indices.len());
    let helper_indices = get_helper_indices(indices);
    assert_eq!(proof.len(), helper_indices.len());

    let mut objects: HashMap<usize, Node> = indices
        .iter()
        .chain(helper_indices.iter())
        .copied()
        .zip(leaves.iter().chain(proof.iter()).copied())
        .collect();

    let mut keys = objects.keys().copied().collect::<Vec<_>>();
    keys.sort_by(|a, b| b.cmp(a));

    let mut hasher = Sha256::new();
    let mut pos = 0;
    while pos < keys.len() {
        let key = keys.get(pos).unwrap();
        let key_present = objects.contains_key(key);
        let sibling_present = objects.contains_key(&sibling(*key));
        let parent_index = parent(*key);
        let parent_missing = !objects.contains_key(&parent_index);
        let should_compute = key_present && sibling_present && parent_missing;
        if should_compute {
            let right_index = key | 1;
            let left_index = sibling(right_index);
            let left_input = objects.get(&left_index).unwrap();
            let right_input = objects.get(&right_index).unwrap();
            hasher.update(left_input.as_ref());
            hasher.update(right_input.as_ref());

            let parent = objects.entry(parent_index).or_default();
            parent.as_mut().copy_from_slice(&hasher.finalize_reset());
            keys.push(parent_index);
        }
        pos += 1;
    }

    *objects.get(&1).unwrap()
}

/// From: https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md
/// Return an array representing the tree nodes by generalized index:
/// [0, 1, 2, 3, 4, 5, 6, 7], where each layer is a power of 2. The 0 index is ignored. The 1 index is the root.
/// The result will be twice the size as the padded bottom layer for the input leaves.
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

pub fn create_multiproof(merkle_tree: &[Node], indices_to_prove: &[GeneralizedIndex]) -> Vec<Node> {
    get_helper_indices(indices_to_prove)
        .into_iter()
        .map(|i| merkle_tree[i])
        .collect()
}
