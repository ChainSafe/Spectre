// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod rotation;
mod step;

use eth2::mixin::RequestAccept as _;
use eth2::types::Accept;
// use beacon_api_client::{BlockId, Client, ClientTypes, Value, VersionedValue};
use eth_types::Spec;

use eth2::{types::BlockId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use ethereum_types::{EthSpec, FixedVector, LightClientFinalityUpdate, PublicKey, PublicKeyBytes};
use ethereum_types::{ForkVersionedResponse, LightClientUpdate};
use lightclient_circuits::witness::{CommitteeUpdateArgs, SyncStepArgs};
pub use rotation::*;
pub use step::*;
use url::Url;

pub async fn get_light_client_update_at_period<S: Spec, T: EthSpec>(
    client: &BeaconNodeHttpClient,
    period: u64,
) -> eyre::Result<LightClientUpdate<T>> {
    let mut path = Url::parse(client.as_ref()).unwrap();

    path.path_segments_mut()
        .map_err(|()| eyre::eyre!("Invalid URL: {}", client.as_ref()))?
        .push("eth")
        .push("v1")
        .push("beacon")
        .push("light_client")
        .push("updates");

    path.query_pairs_mut()
        .append_pair("start_period", &period.to_string())
        .append_pair("count", "1");
    println!("Path: {:?}", path);
    let mut resp = client
        .get_response(path, |b| b.accept(Accept::Json))
        .await
        .map_err(|e| eyre::eyre!("Failed to get light client update: {:?}", e))?;
    println!("resp: {:?}", resp);

    let mut updates: Vec<ForkVersionedResponse<LightClientUpdate<T>>> = resp.json().await?;
    println!("Updates: {:?}", updates);

    assert!(updates.len() == 1, "should only get one update");
    Ok(updates.pop().unwrap().data)
}

pub async fn light_client_update_to_args<S: Spec, T: EthSpec>(
    update: &LightClientUpdate<T>,
    pubkeys_compressed: &FixedVector<PublicKeyBytes, T::SyncCommitteeSize>,
    domain: [u8; 32],
) -> eyre::Result<(SyncStepArgs<S>, CommitteeUpdateArgs<S>)>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
    [(); S::SYNC_COMMITTEE_ROOT_INDEX]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::FINALIZED_HEADER_INDEX]:,
{
    let finality_update = LightClientFinalityUpdate {
        attested_header: update.attested_header.clone(),
        finalized_header: update.finalized_header.clone(),
        finality_branch: update.finality_branch.clone(),
        sync_aggregate: update.sync_aggregate.clone(),
        signature_slot: update.signature_slot,
    };

    let rotation_args = rotation::rotation_args_from_update(update).await?;

    let sync_args =
        step::step_args_from_finality_update(finality_update, pubkeys_compressed, domain).await?;

    Ok((sync_args, rotation_args))
}

#[cfg(test)]
mod tests {
    use eth2::types::StateId;
    // use beacon_api_client::StateId;
    use eth_types::Testnet;
    use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
    use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use halo2_base::utils::fs::gen_srs;
    use lightclient_circuits::committee_update_circuit::CommitteeUpdateCircuit;
    use lightclient_circuits::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use lightclient_circuits::util::{Eth2ConfigPinning, Halo2ConfigPinning};
    use lightclient_circuits::{
        halo2_base::gates::circuit::CircuitBuilderStage, sync_step_circuit::StepCircuit,
        util::AppCircuit,
    };
    use snark_verifier_sdk::CircuitExt;

    use super::*;
    use eth2::BeaconNodeHttpClient;
    use ethereum_types::Domain;
    use ethereum_types::EthSpec;
    use ethereum_types::ForkData;
    use ethereum_types::MainnetEthSpec;
    use reqwest::Url;
    use std::time::Duration;

    #[tokio::test]
    async fn test_both_circuit_sepolia() {
        const K: u32 = 20;
        const URL: &str = "https://lodestar-sepolia.chainsafe.io";
        let client = BeaconNodeHttpClient::new(
            SensitiveUrl::parse(URL).unwrap(),
            Timeouts::set_all(Duration::from_secs(10)),
        );

        let block = client
            .get_beacon_headers_block_id(BlockId::Finalized)
            .await
            .unwrap()
            .unwrap()
            .data
            .header
            .message;

        let slot = block.slot;
        let period = slot / (32 * 256);
        const ROTATE_CONFIG_PATH: &str = "../lightclient-circuits/config/committee_update_20.json";
        const STEP_CONFIG_PATH: &str = "../lightclient-circuits/config/sync_step_20.json";
        println!(
            "Fetching light client update at current Slot: {} at Period: {}",
            slot, period
        );

        // Fetch light client update and create circuit arguments
        let (s, mut c) = {
            let update = get_light_client_update_at_period::<Testnet, MainnetEthSpec>(
                &client,
                period.into(),
            )
            .await
            .unwrap();

            let block_root = block.canonical_root();

            let bootstrap = client
                .get_light_client_bootstrap::<MainnetEthSpec>(block_root)
                .await
                .unwrap()
                .unwrap()
                .data;

            let pubkeys_compressed = &bootstrap.current_sync_committee.pubkeys;

            let fork_version = client
                .get_beacon_states_fork(StateId::Head)
                .await
                .unwrap()
                .unwrap()
                .data
                .current_version;

            let genesis_validators_root = client
                .get_beacon_genesis()
                .await
                .unwrap()
                .data
                .genesis_validators_root;

            let domain = MainnetEthSpec::default_spec().compute_domain(
                Domain::SyncCommittee,
                fork_version,
                genesis_validators_root,
            );

            light_client_update_to_args::<Testnet, MainnetEthSpec>(
                &update,
                pubkeys_compressed,
                domain.into(),
            )
            .await
            .unwrap()
        };

        let mut finalized_sync_committee_branch = {
            let block_root = s.finalized_header.canonical_root();

            let k = client
                .get_light_client_bootstrap::<MainnetEthSpec>(block_root)
                .await
                .unwrap()
                .unwrap()
                .data
                .current_sync_committee_branch
                .into_iter()
                .map(|n| n.0.to_vec())
                .collect_vec();
            k
        };

        // Magic swap of sync committee branch
        finalized_sync_committee_branch.insert(0, c.sync_committee_branch[0].clone());
        finalized_sync_committee_branch[1] = c.sync_committee_branch[1].clone();
        c.sync_committee_branch = finalized_sync_committee_branch;

        let params: ParamsKZG<Bn256> = gen_srs(K);
        let pinning = Eth2ConfigPinning::from_path(STEP_CONFIG_PATH);
        let circuit = StepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            Some(pinning),
            &s,
            &params,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied();

        let pinning = Eth2ConfigPinning::from_path(ROTATE_CONFIG_PATH);
        let circuit = CommitteeUpdateCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            Some(pinning),
            &c,
            &params,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied();
    }
}
