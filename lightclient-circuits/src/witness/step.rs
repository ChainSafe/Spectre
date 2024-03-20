// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use eth_types::Spec;
use ethereum_consensus_types::signing::compute_signing_root;
use ethereum_consensus_types::BeaconBlockHeader;
use ff::Field;
use halo2curves::bls12_381::hash_to_curve::ExpandMsgXmd;
use halo2curves::bls12_381::{hash_to_curve, Fr, G1, G2};
use halo2curves::group::Curve;
use itertools::Itertools;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use ssz_rs::{Merkleized, Node};
use std::marker::PhantomData;
use std::ops::Deref;

use crate::witness::beacon_header_multiproof_and_helper_indices;

use super::mock_root;

/// Input datum for the `StepCircuit` to verify `attested_header` singed by the lightclient sync committee,
/// and the `execution_payload_root` via Merkle `finality_branch` against the `finalized_header` root.
///
/// Assumes that aggregated BLS signarure is represented as a compressed G2 point and the public keys are uncompressed G1 points;
/// `pariticipation_bits` vector has exactly `S::SYNC_COMMITTEE_SIZE`` bits;
/// `finality_branch` and `execution_payload_branch` are exactly `S::FINALIZED_HEADER_DEPTH` and `S::EXECUTION_STATE_ROOT_DEPTH` long respectively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStepArgs<S: Spec> {
    pub signature_compressed: Vec<u8>,

    pub pubkeys_uncompressed: Vec<Vec<u8>>,

    pub pariticipation_bits: Vec<bool>,

    pub attested_header: BeaconBlockHeader,

    pub finalized_header: BeaconBlockHeader,

    pub finality_branch: Vec<Vec<u8>>,

    pub execution_payload_root: Vec<u8>,

    pub execution_payload_branch: Vec<Vec<u8>>,

    pub domain: [u8; 32],

    pub attested_header_multiproof: Vec<Vec<u8>>,
    pub attested_header_helper_indices: Vec<usize>,
    pub finalized_header_multiproof: Vec<Vec<u8>>,
    pub finalized_header_helper_indices: Vec<usize>,

    #[serde(skip)]
    pub _spec: PhantomData<S>,
}

// This default witness is intended for circuit setup and testing purposes only.
impl<S: Spec> Default for SyncStepArgs<S> {
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

        let mut finalized_header = BeaconBlockHeader {
            body_root: Node::try_from(beacon_block_body_root.as_slice()).unwrap(),
            ..Default::default()
        };

        let finality_header_root = finalized_header.hash_tree_root().unwrap();

        let finality_branch = vec![vec![0; 32]; S::FINALIZED_HEADER_DEPTH];

        let attested_state_root = mock_root(
            finality_header_root.deref().to_vec(),
            &finality_branch,
            S::FINALIZED_HEADER_INDEX,
        );

        let mut attested_header = BeaconBlockHeader {
            state_root: Node::try_from(attested_state_root.as_slice()).unwrap(),
            ..Default::default()
        };

        let signing_root =
            compute_signing_root(attested_header.hash_tree_root().unwrap(), DOMAIN).unwrap();

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);

        let sks = (0..S::SYNC_COMMITTEE_SIZE)
            .map(|_| Fr::random(&mut rng))
            .collect_vec();
        let msg = <G2 as hash_to_curve::HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
            signing_root.deref(),
            S::DST,
        )
        .to_affine();

        let aggregated_signature = sks
            .iter()
            .map(|sk| msg * sk)
            .fold(G2::identity(), |acc, x| acc + x)
            .to_affine();

        let signature_compressed = aggregated_signature.to_compressed_be().to_vec();

        let pubkeys_uncompressed = sks
            .iter()
            .map(|sk| {
                (G1::generator() * sk)
                    .to_affine()
                    .to_uncompressed_be()
                    .to_vec()
            })
            .collect_vec();

        // Proof length is 3
        let (attested_header_multiproof, attested_header_helper_indices) =
            beacon_header_multiproof_and_helper_indices(
                &mut attested_header.clone(),
                &[S::HEADER_SLOT_INDEX, S::HEADER_STATE_ROOT_INDEX],
            );
        // Proof length is 4
        let (finalized_header_multiproof, finalized_header_helper_indices) =
            beacon_header_multiproof_and_helper_indices(
                &mut finalized_header.clone(),
                &[S::HEADER_SLOT_INDEX, S::HEADER_BODY_ROOT_INDEX],
            );

        Self {
            signature_compressed,
            pubkeys_uncompressed,
            pariticipation_bits: vec![true; S::SYNC_COMMITTEE_SIZE],
            domain: DOMAIN,
            attested_header,
            finalized_header,
            finality_branch,
            execution_payload_branch: execution_branch,
            execution_payload_root: execution_root,
            _spec: PhantomData,

            attested_header_multiproof,
            attested_header_helper_indices,
            finalized_header_multiproof,
            finalized_header_helper_indices,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sync_step_circuit::StepCircuit, util::AppCircuit};
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
    fn test_step_default_witness() {
        const K: u32 = 20;
        let witness = SyncStepArgs::<Testnet>::default();
        let params: ParamsKZG<Bn256> = gen_srs(K);

        let circuit = StepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            None,
            &witness,
            &params,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied();
    }
}
