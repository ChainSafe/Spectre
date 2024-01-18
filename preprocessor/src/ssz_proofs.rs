use ethereum_consensus_types::BeaconBlockHeader;
use ssz_rs::{MerkleizationError, Merkleized, Node};

/// Returns nodes representing the leaves a BeaconBlockHeader in merkleized representation.
pub fn block_header_to_leaves(
    header: &mut BeaconBlockHeader,
) -> Result<[Node; 5], MerkleizationError> {
    Ok([
        header.slot.hash_tree_root()?,
        header.proposer_index.hash_tree_root()?,
        header.parent_root.hash_tree_root()?,
        header.state_root.hash_tree_root()?,
        header.body_root.hash_tree_root()?,
    ])
}
