#![feature(generic_const_exprs)]

use std::path::PathBuf;

use contract_tests::make_client;
use eth_types::Minimal;
use ethers::contract::abigen;
use halo2_base::safe_types::ScalarField;
use halo2curves::{bls12_381, bn256::{self, Fr}};
use itertools::Itertools;
use lightclient_circuits::committee_update_circuit::CommitteeUpdateCircuit;
use lightclient_circuits::poseidon::fq_array_poseidon_native;
use lightclient_circuits::witness::CommitteeRotationArgs;
use rstest::rstest;
use ssz_rs::prelude::*;
use ssz_rs::Merkleized;
use test_utils::read_test_files_and_gen_witness;

abigen!(
    RotateExternal,
    "../contracts/out/RotateExternal.sol/RotateExternal.json"
);

#[rstest]
#[tokio::test]
async fn test_rotate_public_input_evm_equivalence(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) -> anyhow::Result<()> {
    let (_, witness) = read_test_files_and_gen_witness(path);
    let instance = CommitteeUpdateCircuit::<Minimal, bn256::Fr>::instance(&witness);
    let finalized_block_root = witness
        .finalized_header
        .clone()
        .hash_tree_root()
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();

    let (_anvil_instance, ethclient) = make_client();
    let contract = RotateExternal::deploy(ethclient, ())?.send().await?;

    let result = contract
        .to_public_inputs(RotateInput::from(witness), finalized_block_root)
        .call()
        .await?;

    // convert each of the returned values to a field element
    let result_decoded: Vec<_> = result
        .iter()
        .map(|v| {
            let mut b = [0_u8; 32];
            v.to_little_endian(&mut b);
            bn256::Fr::from_bytes(&b).unwrap()
        })
        .collect();

    assert_eq!(result_decoded.len(), instance[0].len());
    assert_eq!(vec![result_decoded], instance);
    Ok(())
}

fn poseidon_committee_commitment_from_compressed(
    pubkeys_compressed: &Vec<Vec<u8>>,
) -> anyhow::Result<[u8; 32]> {
    let pubkeys_x = pubkeys_compressed.iter().cloned().map(|mut bytes| {
        bytes[47] &= 0b00011111;
        bls12_381::Fq::from_bytes_le(&bytes)
    });
    let poseidon_commitment = fq_array_poseidon_native::<bn256::Fr>(pubkeys_x).unwrap();
    Ok(poseidon_commitment.to_bytes_le().try_into().unwrap())
}

// CommitteeRotationArgs type produced by abigen macro matches the solidity struct type
impl<Spec: eth_types::Spec> From<CommitteeRotationArgs<Spec, Fr>> for RotateInput
where
    [(); Spec::SYNC_COMMITTEE_SIZE]:,
{
    fn from(args: CommitteeRotationArgs<Spec, Fr>) -> Self {
        let poseidon_commitment_le = poseidon_committee_commitment_from_compressed(
            &args
                .pubkeys_compressed
                .iter()
                .cloned()
                .map(|mut b| {
                    b.reverse();
                    b
                })
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
}
