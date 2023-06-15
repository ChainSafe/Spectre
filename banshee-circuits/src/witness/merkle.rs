use gadgets::impl_expr;
use strum_macros::EnumIter;

pub type MerkleTrace<F> = Vec<MerkleTraceStep<F>>;

#[derive(Clone, Debug)]
pub struct MerkleTraceStep<F> {
    pub sibling: F,
    pub sibling_index: F,
    pub node: F,
    pub index: F,
    pub into_left: F,
    pub is_left: F,
    pub is_right: F,
    pub parent: F,
    pub parent_index: F,
    pub depth: F,
}

// #[derive(Debug, Clone, PartialEq, Eq, Copy, EnumIter, Hash)]
// pub enum LevelTag {
//     PubKeys = 0,
//     Validators
// }
// impl_expr!(LevelTag);

// impl From<LevelTag> for usize {
//     fn from(value: LevelTag) -> usize {
//         value as usize
//     }
// }
