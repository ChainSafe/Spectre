use crate::poseidon_committee_commitment_from_compressed;
use contracts::{RotateInput, SyncStepInput};
use itertools::Itertools;
use lightclient_circuits::witness::{CommitteeRotationArgs, SyncStepArgs};
use ssz_rs::prelude::*;

pub fn sync_input_from_args<Spec: eth_types::Spec>(args: SyncStepArgs<Spec>) -> SyncStepInput {
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
        .as_bytes()
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

pub fn rotate_input_from_args<Spec: eth_types::Spec, Fr: eth_types::Field>(
    args: CommitteeRotationArgs<Spec, Fr>,
) -> RotateInput
where
    [(); Spec::SYNC_COMMITTEE_SIZE]:,
{
    let poseidon_commitment_le = poseidon_committee_commitment_from_compressed(
        &args
            .pubkeys_compressed
            .iter()
            .cloned()
            // .map(|mut b| {
            //     b.reverse();
            //     b
            // })
            .collect_vec(),
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
        .as_bytes()
        .try_into()
        .unwrap();

    RotateInput {
        sync_committee_ssz,
        sync_committee_poseidon: poseidon_commitment_le,
    }
}
