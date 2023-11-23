use std::path::PathBuf;

use contract_tests::make_client;
use eth_types::Minimal;
use ethers::contract::abigen;
use lightclient_circuits::halo2_proofs::halo2curves::bn256;
use lightclient_circuits::witness::SyncStepArgs;
use lightclient_circuits::{sync_step_circuit::StepCircuit, LIMB_BITS};
use rstest::rstest;
use ssz_rs::Merkleized;
use test_utils::{
    poseidon_committee_commitment_from_uncompressed, read_test_files_and_gen_witness,
};

abigen!(
    SyncStepExternal,
    "../contracts/out/SyncStepExternal.sol/SyncStepExternal.json"
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
}

#[rstest]
#[tokio::test]
async fn test_step_instance_commitment_evm_equivalence(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) -> anyhow::Result<()> {
    let (witness, _) = read_test_files_and_gen_witness(&path);
    let instance = StepCircuit::<Minimal, bn256::Fr>::instance_commitment(&witness, LIMB_BITS);
    let poseidon_commitment_le =
        poseidon_committee_commitment_from_uncompressed(&witness.pubkeys_uncompressed)?;

    let (_anvil_instance, ethclient) = make_client();
    let contract = SyncStepExternal::deploy(ethclient, ())?.send().await?;

    let result = contract
        .to_input_commitment(SyncStepInput::from(witness), poseidon_commitment_le)
        .call()
        .await?;
    let mut result_bytes = [0_u8; 32];
    result.to_little_endian(&mut result_bytes);

    assert_eq!(bn256::Fr::from_bytes(&result_bytes).unwrap(), instance);
    Ok(())
}
