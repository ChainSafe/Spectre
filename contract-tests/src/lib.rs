use ethers::{
    core::utils::{Anvil, AnvilInstance},
    middleware::SignerMiddleware,
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
};
use lightclient_circuits::halo2_proofs::halo2curves::bn256;
use std::sync::Arc;

/// Return a fresh ethereum anvil instance and client to test against
pub fn make_client() -> (
    AnvilInstance,
    Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) {
    let anvil = Anvil::new().spawn();
    let provider = Provider::<Http>::try_from(anvil.endpoint())
        .unwrap()
        .interval(std::time::Duration::from_millis(10u64));
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    let client: SignerMiddleware<Provider<Http>, _> =
        SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id()));
    (anvil, Arc::new(client))
}

pub fn decode_solidity_u256_array(uints: &[ethers::types::U256]) -> Vec<bn256::Fr> {
    uints
        .iter()
        .map(|v| {
            let mut b = [0_u8; 32];
            v.to_little_endian(&mut b);
            bn256::Fr::from_bytes(&b).expect("bad bn256::Fr encoding")
        })
        .collect()
}
