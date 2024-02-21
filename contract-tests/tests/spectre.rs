// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * These are the highest level integration tests for the Spectre protocol
 * They treat the Spectre contract as an ethereum light-client and test against the spec
 */
use std::path::PathBuf;
use std::sync::Arc;

use contract_tests::make_client;
use contracts::{MockVerifier, Spectre};
use eth_types::{Minimal, LIMB_BITS};
use ethers::core::types::U256;
use ethers::providers::Middleware;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use lightclient_circuits::sync_step_circuit::StepCircuit;
use rstest::rstest;
use test_utils::{get_initial_sync_committee_poseidon, read_test_files_and_gen_witness};

const SLOTS_PER_EPOCH: usize = 8;
const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: usize = 8;
const SLOTS_PER_SYNC_COMMITTEE_PERIOD: usize = EPOCHS_PER_SYNC_COMMITTEE_PERIOD * SLOTS_PER_EPOCH;
const FINALITY_THRESHOLD: usize = 20; // ~ 2/3 of 32

#[tokio::test]
async fn test_deploy_spectre() -> anyhow::Result<()> {
    let (_anvil_instance, ethclient) = make_client();
    let _contract = deploy_spectre_mock_verifiers(ethclient, 0, U256::zero(), 0).await?;
    Ok(())
}

#[rstest]
#[tokio::test]
async fn test_contract_initialization_and_first_step(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) -> anyhow::Result<()> {
    let (_anvil_instance, ethclient) = make_client();

    let (initial_period, initial_poseidon) =
        get_initial_sync_committee_poseidon::<SLOTS_PER_SYNC_COMMITTEE_PERIOD>(&path)?;

    let (witness, _) = read_test_files_and_gen_witness(&path);

    let contract = deploy_spectre_mock_verifiers(
        ethclient,
        initial_period,
        initial_poseidon,
        SLOTS_PER_SYNC_COMMITTEE_PERIOD,
    )
    .await?;

    // pre conditions
    assert_eq!(contract.head().call().await?, U256::from(0));

    let instances = StepCircuit::<Minimal, Fr>::get_instances(&witness, LIMB_BITS);

    // call step with the input and proof
    let step_input: contracts::StepInput = witness.into();
    let mut proof = vec![0; 384];
    proof.extend(instances[0][0].to_bytes().into_iter().rev());
    proof.extend(instances[0][1].to_bytes().into_iter().rev());
    let step_call = contract.step(step_input.clone(), proof.into());
    let _receipt = step_call.send().await?.confirmations(1).await?;

    // post conditions
    let head = U256::from(step_input.finalized_slot);
    assert_eq!(contract.head().call().await?, head);
    assert_eq!(
        contract.block_header_roots(head).call().await?,
        step_input.finalized_header_root
    );
    assert_eq!(
        contract.execution_payload_roots(head).call().await?,
        step_input.execution_payload_root
    );

    Ok(())
}

//////////// deployment helpers //////////////////

/// Deploy the Spectre contract using the given ethclient
/// Also deploys the step verifier and the update verifier contracts
/// and passes their addresses along with the other params to the constructor
async fn deploy_spectre_mock_verifiers<M: Middleware + 'static>(
    ethclient: Arc<M>,
    initial_sync_period: usize,
    initial_sync_committee_poseidon: U256,
    slots_per_period: usize,
) -> anyhow::Result<Spectre<M>> {
    let step_verifier = MockVerifier::deploy(ethclient.clone(), ())?.send().await?;
    let update_verifier = MockVerifier::deploy(ethclient.clone(), ())?.send().await?;
    Ok(Spectre::deploy(
        ethclient,
        (
            step_verifier.address(),
            update_verifier.address(),
            U256::from(initial_sync_period),
            initial_sync_committee_poseidon,
            U256::from(slots_per_period),
            U256::from(FINALITY_THRESHOLD)
        ),
    )?
    .send()
    .await?)
}
