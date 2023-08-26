use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;

use crate::witness::HashInputChunk;

use super::HashInput;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MerkleTrace(pub Vec<MerkleTraceStep>);

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MerkleTraceStep {
    pub sibling: Vec<u8>,
    pub sibling_index: u64,
    pub node: Vec<u8>,
    pub index: u64,
    pub into_left: bool,
    pub is_left: bool,
    pub is_right: bool,
    pub is_rlc: [bool; 2],
    pub parent: Vec<u8>,
    pub parent_index: u64,
    pub depth: usize,
}

impl MerkleTrace {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn root(&self) -> [u8; 32] {
        self.0
            .last()
            .expect("root is expected")
            .node
            .clone()
            .try_into()
            .unwrap()
    }

    pub fn sorted(&self) -> Vec<MerkleTraceStep> {
        self.0
            .clone()
            .into_iter()
            .sorted_by_key(|e| e.depth)
            .rev()
            .collect_vec()
    }

    pub fn sha256_inputs(&self) -> Vec<HashInput<u8>> {
        let mut steps_sorted = self.sorted();

        // filter out the first (root) level as it require no hashing.
        if steps_sorted.last().unwrap().depth == 1 {
            steps_sorted.pop();
        }
        steps_sorted
            .into_iter()
            .map(|step| {
                assert_eq!(
                    sha2::Sha256::digest(vec![step.node.clone(), step.sibling.clone()].concat())
                        .to_vec(),
                    step.parent
                );

                HashInput::TwoToOne(
                    HashInputChunk::new(step.node, step.is_rlc[0]),
                    HashInputChunk::new(step.sibling, step.is_rlc[1]),
                )
            })
            .collect_vec()
    }
}
