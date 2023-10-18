use std::path::PathBuf;
use std::sync::Arc;

use contract_tests::make_client;
use ethers::contract::abigen;
use ethers::core::types::U256;
use ethers::providers::Middleware;
use rstest::rstest;

abigen!(Spectre, "../contracts/out/Spectre.sol/Spectre.json");

abigen!(StepVerifier, "../contracts/out/sync_step.sol/Verifier.json");

abigen!(
    CommitteeUpdateVerifier,
    "../contracts/out/committee_update_aggregated.sol/Verifier.json"
);

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

#[rstest]
#[tokio::test]
async fn test_deploy_spectre(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) -> anyhow::Result<()> {
    let (_anvil_instance, ethclient) = make_client();
    let contract = deploy_spectre(ethclient).await?;
    Ok(())
}
