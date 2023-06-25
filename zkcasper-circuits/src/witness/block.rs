use super::{Committee, MerkleTrace, Validator};

// TODO: Remove fields that are duplicated in`eth_block`
/// Block is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default)]
pub struct Block<F> {
    /// The randomness for random linear combination
    pub randomness: F,

    /// The target epoch
    pub target_epoch: u64,

    pub validators: Vec<Validator>,

    pub committees: Vec<Committee>,

    pub merkle_trace: MerkleTrace,
}
