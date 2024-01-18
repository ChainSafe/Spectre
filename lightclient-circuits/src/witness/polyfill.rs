// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use eth_types::Spec;
use ethereum_consensus_types::signing::compute_signing_root;
use ethereum_consensus_types::BeaconBlockHeader;
use halo2curves::bls12_381::hash_to_curve::ExpandMsgXmd;
use halo2curves::bls12_381::{hash_to_curve, Fr, G1, G2};
use halo2curves::group::Curve;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use ssz_rs::{Merkleized, Node};
use std::iter;
use std::marker::PhantomData;
use std::ops::Deref;

use super::mock_root;

/// Input datum for the `StepCircuit` to verify `attested_header` singed by the lightclient sync committee,
/// and the `execution_payload_root` via Merkle `finality_branch` against the `finalized_header` root.
///
/// Assumes that aggregated BLS signarure is represented as a compressed G2 point and the public keys are uncompressed G1 points;
/// `pariticipation_bits` vector has exactly `S::SYNC_COMMITTEE_SIZE`` bits;
/// `finality_branch` and `execution_payload_branch` are exactly `S::FINALIZED_HEADER_DEPTH` and `S::EXECUTION_STATE_ROOT_DEPTH` long respectively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolyfillArgs<S: Spec> {
    pub verified_header: BeaconBlockHeader,
    pub parent_header: BeaconBlockHeader,
    pub parent_slot_proof: Vec<Vec<u8>>,

    // Not actually withness data but used for verifying multiproof
    pub helper_indices: Vec<usize>,
    pub _p: PhantomData<S>,
}

// This default witness is intended for circuit setup and testing purposes only.
impl<S: Spec> Default for PolyfillArgs<S> {
    fn default() -> Self {
        const DOMAIN: [u8; 32] = [
            7, 0, 0, 0, 48, 83, 175, 74, 95, 250, 246, 166, 104, 40, 151, 228, 42, 212, 194, 8, 48,
            56, 232, 147, 61, 9, 41, 204, 88, 234, 56, 134,
        ];

        let execution_root = vec![0; 32];
        let execution_branch = vec![vec![0; 32]; S::EXECUTION_STATE_ROOT_DEPTH];
        let beacon_block_body_root = mock_root(
            execution_root.clone(),
            &execution_branch,
            S::EXECUTION_STATE_ROOT_INDEX,
        );

        let mut parent_header = BeaconBlockHeader {
            body_root: Node::try_from(beacon_block_body_root.as_slice()).unwrap(),
            slot: 0,
            ..Default::default()
        };

        let parent_header_root = parent_header.hash_tree_root().unwrap();

        let finality_branch = vec![vec![0; 32]; S::FINALIZED_HEADER_DEPTH];

        let attested_state_root = mock_root(
            parent_header_root.deref().to_vec(),
            &finality_branch,
            S::FINALIZED_HEADER_INDEX,
        );

        let current_header = BeaconBlockHeader {
            parent_root: parent_header_root,
            slot: 0,
            state_root: Node::try_from(attested_state_root.as_slice()).unwrap(),
            ..Default::default()
        };
        Self {
            verified_header: current_header,
            parent_header,
            parent_slot_proof: vec![vec![0; 32]; 3],
            helper_indices: todo!(),
            // helper_indices: vec![0; 3],
            _p: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        polyfill_circuit::PolyfillCircuit, sync_step_circuit::StepCircuit, util::AppCircuit,
    };
    use eth_types::Testnet;
    use halo2_base::{
        gates::circuit::CircuitBuilderStage,
        halo2_proofs::halo2curves::bn256::Fr,
        halo2_proofs::{
            dev::MockProver, halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG,
        },
        utils::fs::gen_srs,
    };
    use snark_verifier_sdk::CircuitExt;

    #[test]
    fn test_polyfill_default_witness() {
        const K: u32 = 17;
        let witness = PolyfillArgs::<Testnet>::default();
        let params: ParamsKZG<Bn256> = gen_srs(K);

        let circuit = PolyfillCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            None,
            &witness,
            &params,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied_par();
    }
}
