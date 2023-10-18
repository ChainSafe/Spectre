/**
 * These are the highest level integration tests for the Spectre protocol
 * They treat the Spectre contract as an ethereum light-client and test against the spec
 */
use std::path::PathBuf;
use std::sync::Arc;

use contract_tests::make_client;
use ethers::contract::abigen;
use ethers::core::types::U256;
use ethers::providers::Middleware;
use rstest::rstest;
use test_utils::{get_initial_sync_committee_poseidon, read_test_files_and_gen_witness};

abigen!(Spectre, "../contracts/out/Spectre.sol/Spectre.json");

abigen!(StepVerifier, "../contracts/out/sync_step.sol/Verifier.json");

abigen!(
    CommitteeUpdateVerifier,
    "../contracts/out/committee_update_aggregated.sol/Verifier.json"
);

const SLOTS_PER_PERIOD: usize = 32;

/// Deploy the Spectre contract using the given ethclient
/// Also deploys the step verifier and the update verifier contracts
/// and passes their addresses along with the other params to the constructor
async fn deploy_spectre_contracts<M: Middleware + 'static>(
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

#[tokio::test]
async fn test_deploy_spectre() -> anyhow::Result<()> {
    let (_anvil_instance, ethclient) = make_client();
    let contract = deploy_spectre_contracts(ethclient, 0, [0; 32], 0).await?;
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
        get_initial_sync_committee_poseidon::<SLOTS_PER_PERIOD>(&path)?;
    let (witness, _) = read_test_files_and_gen_witness(&path);
    // let step_input = SyncStepInput::from(witness);

    let contract = deploy_spectre_contracts(
        ethclient,
        initial_period,
        initial_poseidon,
        SLOTS_PER_PERIOD,
    )
    .await?;

    Ok(())
}
