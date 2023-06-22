use gadgets::impl_expr;
use strum_macros::EnumIter;
use serde::{Deserialize, Serialize};

pub type MerkleTrace = Vec<MerkleTraceStep>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MerkleTraceStep {
    pub sibling: Vec<u8>,
    pub sibling_index: u64,
    pub node: Vec<u8>,
    pub index: u64,
    pub into_left: bool,
    pub is_left: bool,
    pub is_right: bool,
    pub parent: Vec<u8>,
    pub parent_index: u64,
    pub depth: usize,
}
