use std::sync::Arc;
use ethers::{
    core::utils::{Anvil, AnvilInstance},
    middleware::SignerMiddleware,
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
};

/// Return a fresh ethereum anvil instance and client to test against
pub fn make_client() -> (AnvilInstance, Arc<SignerMiddleware<Provider<Http>, LocalWallet>>) {
    let anvil = Anvil::new().spawn();
    let provider = Provider::<Http>::try_from(anvil.endpoint())
        .unwrap()
        .interval(std::time::Duration::from_millis(10u64));
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    let client: SignerMiddleware<Provider<Http>, _> =
        SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id()));
    (anvil, Arc::new(client))
}
