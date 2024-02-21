// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::ops::Deref;
use std::path::PathBuf;

use contract_tests::make_client;
use eth_types::{Minimal, LIMB_BITS};
use ethers::contract::abigen;
use lightclient_circuits::halo2_proofs::halo2curves::bn256;
use lightclient_circuits::witness::SyncStepArgs;
use rstest::rstest;
use ssz_rs::Merkleized;
use test_utils::read_test_files_and_gen_witness;

abigen!(
    StepExternal,
    "../contracts/out/StepExternal.sol/StepExternal.json";
);

// SyncStepInput type produced by abigen macro matches the solidity struct type
impl<Spec: eth_types::Spec> From<SyncStepArgs<Spec>> for StepInput {
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

        StepInput {
            attested_slot: args.attested_header.slot,
            finalized_slot: args.finalized_header.slot,
            participation,
            finalized_header_root,
            execution_payload_root,
        }
    }
}

#[rstest]
#[tokio::test]
async fn test_step_instance_commitment_evm_equivalence(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) -> anyhow::Result<()> {
    use contract_tests::decode_solidity_u256_array;

    let (witness, _) = read_test_files_and_gen_witness(&path);
    let instance = lightclient_circuits::sync_step_circuit::StepCircuit:: <Minimal,bn256::Fr> ::get_instances(&witness, LIMB_BITS);

    let (_anvil_instance, ethclient) = make_client();
    let contract = StepExternal::deploy(ethclient, ())?.send().await?;

    let result = contract
        .to_public_inputs_commitment(
            StepInput::from(witness),
        )
        .call()
        .await?;
    let result_decoded = decode_solidity_u256_array(&[result]);

    assert_eq!(result_decoded[0], instance[0][0]); // public input commitment

    Ok(())
}
