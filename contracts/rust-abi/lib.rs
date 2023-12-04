#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
use ethers::contract::abigen;
use itertools::Itertools;
use lightclient_circuits::{
    poseidon::poseidon_committee_commitment_from_compressed,
    witness::{CommitteeRotationArgs, SyncStepArgs},
};
use ssz_rs::{Merkleized, Vector};
use std::ops::Deref;
abigen!(
    Spectre,
    "./out/Spectre.sol/Spectre.json";
    StepVerifier,
    "./out/sync_step.sol/Verifier.json";
    CommitteeUpdateVerifier,
    "./out/committee_update_verifier.sol/Verifier.json";
    StepMockVerifier,
    "./out/SyncStepMockVerifier.sol/SyncStepMockVerifier.json";
    CommitteeUpdateMockVerifier,
    "./out/CommitteeUpdateMockVerifier.sol/CommitteeUpdateMockVerifier.json";
    RotateExternal,
    "./out/RotateExternal.sol/RotateExternal.json";
    SyncStepExternal,
    "./out/SyncStepExternal.sol/SyncStepExternal.json";
);

// SyncStepInput type produced by abigen macro matches the solidity struct type
impl<Spec: eth_types::Spec> From<SyncStepArgs<Spec>> for SyncStepInput {
    fn from(args: SyncStepArgs<Spec>) -> Self {
        let participation = args
            .pariticipation_bits
            .iter()
            .map(|v| *v as u64)
            .sum::<u64>();

        let finalized_header_root: [u8; 32] = args
            .finalized_header
            .clone()
            .hash_tree_root()
            .unwrap()
            .deref()
            .try_into()
            .unwrap();

        let execution_payload_root: [u8; 32] = args.execution_payload_root.try_into().unwrap();

        SyncStepInput {
            attested_slot: args.attested_header.slot,
            finalized_slot: args.finalized_header.slot,
            participation,
            finalized_header_root,
            execution_payload_root,
        }
    }
}

// CommitteeRotationArgs type produced by abigen macro matches the solidity struct type
impl<Spec: eth_types::Spec> From<CommitteeRotationArgs<Spec>> for RotateInput
where
    [(); Spec::SYNC_COMMITTEE_SIZE]:,
{
    fn from(args: CommitteeRotationArgs<Spec>) -> Self {
        let poseidon_commitment_le = poseidon_committee_commitment_from_compressed(
            &args.pubkeys_compressed.iter().cloned().collect_vec(),
        )
        .unwrap();

        let mut pk_vector: Vector<Vector<u8, 48>, { Spec::SYNC_COMMITTEE_SIZE }> = args
            .pubkeys_compressed
            .iter()
            .cloned()
            .map(|v| v.try_into().unwrap())
            .collect_vec()
            .try_into()
            .unwrap();

        let sync_committee_ssz = pk_vector
            .hash_tree_root()
            .unwrap()
            .deref()
            .try_into()
            .unwrap();

        RotateInput {
            sync_committee_ssz,
            sync_committee_poseidon: poseidon_commitment_le,
        }
    }
}

// pub fn poseidon_committee_commitment_from_compressed(pubkeys_compressed: &[Vec<u8>]) -> [u8; 32] {
//     let pubkeys_x = pubkeys_compressed.iter().cloned().map(|mut bytes| {
//         bytes[0] &= 0b00011111;
//         bls12_381::Fq::from_bytes_be(&bytes.try_into().unwrap())
//             .expect("bad bls12_381::Fq encoding")
//     });
//     let poseidon_commitment = fq_array_poseidon_native::<Fr>(pubkeys_x, LIMB_BITS).unwrap();
//     poseidon_commitment.to_bytes()
// }
