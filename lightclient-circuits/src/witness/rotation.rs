// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use eth_types::Spec;
use ethereum_consensus_types::BeaconBlockHeader;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{iter, marker::PhantomData};

/// Input datum for the `CommitteeUpdateCircuit` to map next sync committee SSZ root in the finalized state root to the corresponding Poseidon commitment to the public keys.
///
/// Assumes that public keys are BLS12-381 points on G1; `sync_committee_branch` is exactly `S::SYNC_COMMITTEE_PUBKEYS_DEPTH` hashes in lenght.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeUpdateArgs<S: Spec> {
    pub pubkeys_compressed: Vec<Vec<u8>>,

    pub finalized_header: BeaconBlockHeader,

    pub sync_committee_branch: Vec<Vec<u8>>,

    #[serde(skip)]
    pub _spec: PhantomData<S>,
}

// This default witness is intended for circuit setup and testing purposes only.
impl<S: Spec> Default for CommitteeUpdateArgs<S> {
    fn default() -> Self {
        let dummy_x_bytes = iter::once(192).pad_using(48, |_| 0).rev().collect_vec();

        let sync_committee_branch = vec![vec![0; 32]; S::SYNC_COMMITTEE_PUBKEYS_DEPTH];

        let hashed_pk = sha2::Sha256::digest(
            &dummy_x_bytes
                .iter()
                .copied()
                .pad_using(64, |_| 0)
                .collect_vec(),
        )
        .to_vec();

        assert!(S::SYNC_COMMITTEE_SIZE.is_power_of_two());

        let mut chunks = vec![hashed_pk; S::SYNC_COMMITTEE_SIZE];

        while chunks.len() > 1 {
            chunks = chunks
                .into_iter()
                .tuples()
                .map(|(left, right)| sha2::Sha256::digest(&[left, right].concat()).to_vec())
                .collect();
        }

        let committee_root = chunks.pop().unwrap();

        let state_root = mock_root(
            committee_root,
            &sync_committee_branch,
            S::SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX,
        );

        Self {
            pubkeys_compressed: iter::repeat(dummy_x_bytes)
                .take(S::SYNC_COMMITTEE_SIZE)
                .collect_vec(),
            sync_committee_branch,
            finalized_header: BeaconBlockHeader {
                state_root: state_root.as_slice().try_into().unwrap(),
                ..Default::default()
            },
            _spec: PhantomData,
        }
    }
}

pub(crate) fn mock_root(leaf: Vec<u8>, branch: &[Vec<u8>], mut gindex: usize) -> Vec<u8> {
    let mut last_hash = leaf;

    for i in 0..branch.len() {
        last_hash = Sha256::digest(
            &if gindex % 2 == 0 {
                [last_hash, branch[i].clone()]
            } else {
                [branch[i].clone(), last_hash]
            }
            .concat(),
        )
        .to_vec();
        gindex /= 2;
    }

    last_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{committee_update_circuit::CommitteeUpdateCircuit, util::AppCircuit};
    use eth_types::Testnet;
    use halo2_base::{
        gates::circuit::CircuitBuilderStage,
        halo2_proofs::dev::MockProver,
        halo2_proofs::{
            halo2curves::bn256::{Bn256, Fr},
            poly::kzg::commitment::ParamsKZG,
        },
        utils::fs::gen_srs,
    };
    use snark_verifier_sdk::CircuitExt;

    #[test]
    fn test_committee_update_default_witness() {
        const K: u32 = 18;
        let witness = CommitteeUpdateArgs::<Testnet>::default();
        let params: ParamsKZG<Bn256> = gen_srs(K);

        let circuit = CommitteeUpdateCircuit::<Testnet, Fr>::mock_circuit(
            &params,
            CircuitBuilderStage::Mock,
            None,
            &witness,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied_par();
    }
}
