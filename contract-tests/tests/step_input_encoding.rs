use std::path::PathBuf;

use contract_tests::make_client;
use eth_types::Minimal;
use ethers::contract::abigen;
use halo2_base::safe_types::ScalarField;
use halo2curves::bn256;
use halo2curves::group::UncompressedEncoding;
use itertools::Itertools;
use lightclient_circuits::poseidon::fq_array_poseidon_native;
use lightclient_circuits::sync_step_circuit::SyncStepCircuit;
use lightclient_circuits::witness::SyncStepArgs;
use rstest::rstest;
use ssz_rs::Merkleized;
use test_utils::read_test_files_and_gen_witness;

abigen!(
    SyncStepExternal,
    "../contracts/out/SyncStepExternal.sol/SyncStepExternal.json"
);

#[rstest]
#[tokio::test]
async fn test_step_instance_commitment_evm_equivalence(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) -> anyhow::Result<()> {
    let (witness, _) = read_test_files_and_gen_witness(path);
    let instance = SyncStepCircuit::<Minimal, bn256::Fr>::instance_commitment(&witness);
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

fn poseidon_committee_commitment_from_uncompressed(
    pubkeys_uncompressed: &Vec<Vec<u8>>,
) -> anyhow::Result<[u8; 32]> {
    let pubkey_affines = pubkeys_uncompressed
        .iter()
        .cloned()
        .map(|bytes| {
            halo2curves::bls12_381::G1Affine::from_uncompressed_unchecked(
                &bytes.as_slice().try_into().unwrap(),
            )
            .unwrap()
        })
        .collect_vec();
    let poseidon_commitment =
        fq_array_poseidon_native::<bn256::Fr>(pubkey_affines.iter().map(|p| p.x)).unwrap();
    Ok(poseidon_commitment.to_bytes_le().try_into().unwrap())
}

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
            participation: participation,
            finalized_header_root,
            execution_payload_root,
        }
    }
}
