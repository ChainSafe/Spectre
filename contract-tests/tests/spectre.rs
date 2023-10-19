/**
 * These are the highest level integration tests for the Spectre protocol
 * They treat the Spectre contract as an ethereum light-client and test against the spec
 */
use std::path::PathBuf;
use std::sync::Arc;

use eth_types::Minimal;
use contract_tests::make_client;
use ethers::contract::abigen;
use ethers::core::types::U256;
use ethers::providers::Middleware;
use rstest::rstest;
use lightclient_circuits::sync_step_circuit::SyncStepCircuit;
use lightclient_circuits::util::{Eth2ConfigPinning, Halo2ConfigPinning, AppCircuit, full_prover, gen_srs};
use halo2curves::bn256;
use halo2_base::gates::builder::CircuitBuilderStage;
use lightclient_circuits::witness::SyncStepArgs;
use test_utils::abis::{CommitteeUpdateVerifier, CommitteeUpdateMockVerifier, Spectre, StepVerifier, StepMockVerifier, SyncStepInput};
use test_utils::{get_initial_sync_committee_poseidon, read_test_files_and_gen_witness};
use snark_verifier_sdk::CircuitExt;

const SLOTS_PER_EPOCH: usize = 8;
const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: usize = 8;
const SLOTS_PER_SYNC_COMMITTEE_PERIOD: usize = EPOCHS_PER_SYNC_COMMITTEE_PERIOD * SLOTS_PER_EPOCH;

/// Deploy the Spectre contract using the given ethclient
/// Also deploys the step verifier and the update verifier contracts
/// and passes their addresses along with the other params to the constructor
async fn deploy_spectre<M: Middleware + 'static>(
    ethclient: Arc<M>,
    initial_sync_period: usize,
    initial_sync_committee_poseidon: [u8; 32],
    slots_per_period: usize,
) -> anyhow::Result<Spectre<M>> {
    let step_verifier = StepVerifier::deploy(ethclient.clone(), ())?.send().await?;
    let update_verifier = CommitteeUpdateVerifier::deploy(ethclient.clone(), ())?
        .send()
        .await?;
    Ok(Spectre::deploy(
        ethclient,
        (
            step_verifier.address(),
            update_verifier.address(),
            U256::from(initial_sync_period),
            initial_sync_committee_poseidon,
            U256::from(slots_per_period),
        ),
    )?
    .send()
    .await?)
}

/// Deploy the Spectre contract using the given ethclient
/// Also deploys the step verifier and the update verifier contracts
/// and passes their addresses along with the other params to the constructor
async fn deploy_spectre_mock_verifiers<M: Middleware + 'static>(
    ethclient: Arc<M>,
    initial_sync_period: usize,
    initial_sync_committee_poseidon: [u8; 32],
    slots_per_period: usize,
) -> anyhow::Result<Spectre<M>> {
    let step_verifier = StepMockVerifier::deploy(ethclient.clone(), ())?.send().await?;
    let update_verifier = CommitteeUpdateMockVerifier::deploy(ethclient.clone(), ())?
        .send()
        .await?;
    Ok(Spectre::deploy(
        ethclient,
        (
            step_verifier.address(),
            update_verifier.address(),
            U256::from(initial_sync_period),
            initial_sync_committee_poseidon,
            U256::from(slots_per_period),
        ),
    )?
    .send()
    .await?)
}

#[tokio::test]
async fn test_deploy_spectre() -> anyhow::Result<()> {
    let (_anvil_instance, ethclient) = make_client();
    let contract = deploy_spectre_mock_verifiers(ethclient, 0, [0; 32], 0).await?;
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

    // call step with the input and proof!
    let step_input = SyncStepInput::from(witness);
    let result = contract.step(step_input.clone(), Vec::new().into()).call().await?;

    // post conditions
    assert_eq!(contract.head().call().await?, U256::from(step_input.finalized_slot));

    Ok(())
}
