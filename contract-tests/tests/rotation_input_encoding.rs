#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use std::path::PathBuf;

use contract_tests::make_client;
use eth_types::Minimal;
use eth_types::LIMB_BITS;
use ethers::contract::abigen;
use itertools::Itertools;
use lightclient_circuits::committee_update_circuit::CommitteeUpdateCircuit;
use lightclient_circuits::halo2_proofs::halo2curves::bn256;
use lightclient_circuits::poseidon::poseidon_committee_commitment_from_compressed;
use lightclient_circuits::witness::CommitteeRotationArgs;
use rstest::rstest;
use ssz_rs::prelude::*;
use ssz_rs::Merkleized;
use std::ops::Deref;
use test_utils::read_test_files_and_gen_witness;

abigen!(
    RotateExternal,
    "../contracts/out/RotateExternal.sol/RotateExternal.json"
);

// CommitteeRotationArgs type produced by abigen macro matches the solidity struct type
impl<Spec: eth_types::Spec> From<CommitteeRotationArgs<Spec>> for RotateInput
where
    [(); Spec::SYNC_COMMITTEE_SIZE]:,
{
    fn from(args: CommitteeRotationArgs<Spec>) -> Self {
        let poseidon_commitment = poseidon_committee_commitment_from_compressed(
            &args.pubkeys_compressed.iter().cloned().collect_vec(),
        );
        let sync_committee_poseidon =
            ethers::prelude::U256::from_little_endian(&poseidon_commitment.to_bytes());

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
            sync_committee_poseidon,
            // this can be anything.. The test is just checking it gets correctly concatenated to the start of the encoded input
            accumulator: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest]
    #[tokio::test]
    async fn test_rotate_public_input_evm_equivalence(
        #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
        #[exclude("deneb*")]
        path: PathBuf,
    ) -> anyhow::Result<()> {
        use contract_tests::decode_solidity_u256_array;

        let (_, witness) = read_test_files_and_gen_witness(&path);

        let instance =
            CommitteeUpdateCircuit::<Minimal, bn256::Fr>::get_instances(&witness, LIMB_BITS);
        let finalized_block_root = witness
            .finalized_header
            .clone()
            .hash_tree_root()
            .unwrap()
            .deref()
            .try_into()
            .unwrap();

        let (_anvil_instance, ethclient) = make_client();
        let contract = RotateExternal::deploy(ethclient, ())?.send().await?;

        let rotate_input = RotateInput::from(witness);
        let result = contract
            .to_public_inputs(rotate_input.clone(), finalized_block_root)
            .call()
            .await?;

        let result_decoded = decode_solidity_u256_array(&result);
        let accumulator = decode_solidity_u256_array(&rotate_input.accumulator);
        // The expected result is the concatenation of the accumulator and the instance
        let expected: Vec<_> = accumulator.iter().chain(instance[0].iter()).collect();
        assert_eq!(result_decoded.iter().collect::<Vec<_>>(), expected);
        Ok(())
    }
}
