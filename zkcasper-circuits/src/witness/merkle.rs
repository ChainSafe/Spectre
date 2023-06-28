use std::collections::HashMap;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sha2::Digest;

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
    pub parent: Vec<u8>,
    pub parent_index: u64,
    pub depth: usize,
}

impl MerkleTrace {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn trace_by_levels(&self) -> Vec<Vec<&MerkleTraceStep>> {
        self.0
            .iter()
            .group_by(|step| step.depth)
            .into_iter()
            .sorted_by_key(|(depth, _steps)| *depth)
            .map(|(_depth, steps)| steps.collect_vec())
            .collect_vec()
    }

    pub fn trace_by_level_map(&self) -> HashMap<usize, Vec<&MerkleTraceStep>> {
        self.0.iter().into_group_map_by(|step| step.depth)
    }

    pub fn sha256_inputs(&self) -> Vec<HashInput> {
        let mut steps_sorted = self
            .0
            .clone()
            .into_iter()
            .sorted_by_key(|e| e.depth)
            .rev()
            .collect_vec();
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
                HashInput::MerklePair(step.node, step.sibling)
            })
            .collect_vec()
    }
}
