// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::marker::PhantomData;

use eth_types::Spec;
use itertools::Itertools;
use lightclient_circuits::witness::SyncStepArgs;

use blst::min_pk as bls;
use eth2::types::StateId;
use eth2::BeaconNodeHttpClient;
use ethereum_types::Domain;
use ethereum_types::{EthSpec, FixedVector, LightClientFinalityUpdate, PublicKeyBytes};
use tree_hash::TreeHash;

/// Fetches the latest `LightClientFinalityUpdate`` and the current sync committee (from LightClientBootstrap) and converts it to a [`SyncStepArgs`] witness.
pub async fn fetch_step_args<S: Spec, T: EthSpec>(
    client: &BeaconNodeHttpClient,
) -> eyre::Result<SyncStepArgs<S>>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
{
    //TODO Should probably parameterise SyncStepArgs<S> as <S,T>
    let finality_update = client
        .get_beacon_light_client_finality_update::<T>()
        .await
        .map_err(|e| eyre::eyre!("Failed to get finality update: {:?}", e))?
        .ok_or(eyre::eyre!("Failed to get finality update: None"))?
        .data;

    let block_root = match &finality_update {
        LightClientFinalityUpdate::Altair(_) => unimplemented!(),
        LightClientFinalityUpdate::Capella(header) => {
            header.finalized_header.beacon.canonical_root()
        }
        LightClientFinalityUpdate::Deneb(header) => header.finalized_header.beacon.canonical_root(),
    };

    let bootstrap = client
        .get_light_client_bootstrap::<T>(block_root)
        .await
        .map_err(|e| eyre::eyre!("Failed to get bootstrap: {:?}", e))?
        .ok_or(eyre::eyre!("Failed to get bootstrap: None"))?
        .data;

    let pubkeys_compressed = &bootstrap.current_sync_committee().pubkeys;

    let attested_state_id = match &finality_update {
        LightClientFinalityUpdate::Altair(_) => unimplemented!(),
        LightClientFinalityUpdate::Capella(header) => header.attested_header.beacon.state_root,
        LightClientFinalityUpdate::Deneb(header) => header.attested_header.beacon.state_root,
    };

    let fork_version = client
        .get_beacon_states_fork(StateId::Root(attested_state_id))
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

    let domain = T::default_spec().compute_domain(
        Domain::SyncCommittee,
        fork_version,
        genesis_validators_root,
    );

    step_args_from_finality_update(finality_update, pubkeys_compressed, domain.into()).await
}

/// Converts a [`LightClientFinalityUpdate`] to a [`SyncStepArgs`] witness.
pub async fn step_args_from_finality_update<S: Spec, T: EthSpec>(
    finality_update: LightClientFinalityUpdate<T>,
    pubkeys_compressed: &FixedVector<PublicKeyBytes, T::SyncCommitteeSize>,
    domain: [u8; 32],
) -> eyre::Result<SyncStepArgs<S>> {
    let pubkeys_uncompressed = pubkeys_compressed
        .iter()
        .map(|pk| {
            bls::PublicKey::uncompress(&pk.serialize())
                .unwrap()
                .serialize()
                .to_vec()
        })
        .collect_vec();

    let (execution_payload_root, execution_payload_branch) = match &finality_update {
        LightClientFinalityUpdate::Altair(_) => unimplemented!(),
        LightClientFinalityUpdate::Capella(header) => {
            let finalized_header = &header.finalized_header;

            (
                finalized_header.execution.tree_hash_root().0.to_vec(),
                finalized_header
                    .execution_branch
                    .iter()
                    .map(|n| n.0.to_vec())
                    .collect_vec(),
            )
        }
        LightClientFinalityUpdate::Deneb(header) => {
            let finalized_header = &header.finalized_header;

            (
                finalized_header.execution.tree_hash_root().0.to_vec(),
                finalized_header
                    .execution_branch
                    .iter()
                    .map(|n| n.0.to_vec())
                    .collect_vec(),
            )
        }
    };

    // assert!(
    //     ssz_rs::is_valid_merkle_branch(
    //         Node::try_from(execution_payload_root.as_slice())?,
    //         &execution_payload_branch,
    //         S::EXECUTION_STATE_ROOT_DEPTH,
    //         S::EXECUTION_STATE_ROOT_INDEX,
    //         finality_update.finalized_header.beacon.body_root,
    //     )
    //     .is_ok(),
    //     "Execution payload merkle proof verification failed"
    // );
    // assert!(
    //     ssz_rs::is_valid_merkle_branch(
    //         finality_update
    //             .finalized_header
    //             .beacon
    //             .clone()
    //             .hash_tree_root()
    //             .unwrap(),
    //         &finality_update
    //             .finality_branch
    //             .iter()
    //             .map(|n| n.as_ref())
    //             .collect_vec(),
    //         S::FINALIZED_HEADER_DEPTH,
    //         S::FINALIZED_HEADER_INDEX,
    //         finality_update.attested_header.beacon.state_root,
    //     )
    //     .is_ok(),
    //     "Finality merkle proof verification failed"
    // );

    let attested_header_beacon = match &finality_update {
        LightClientFinalityUpdate::Altair(_) => unimplemented!(),
        LightClientFinalityUpdate::Capella(update) => update.attested_header.beacon.clone(),

        LightClientFinalityUpdate::Deneb(update) => update.attested_header.beacon.clone(),
    };

    let finalized_header_beacon = match &finality_update {
        LightClientFinalityUpdate::Altair(_) => unimplemented!(),
        LightClientFinalityUpdate::Capella(update) => update.finalized_header.beacon.clone(),

        LightClientFinalityUpdate::Deneb(update) => update.finalized_header.beacon.clone(),
    };

    Ok(SyncStepArgs {
        signature_compressed: finality_update
            .sync_aggregate()
            .sync_committee_signature
            .serialize()
            .to_vec(),
        pubkeys_uncompressed,
        pariticipation_bits: finality_update
            .sync_aggregate()
            .sync_committee_bits
            .iter()
            // .by_vals()
            .collect_vec(),
        attested_header: attested_header_beacon,
        finalized_header: finalized_header_beacon,
        finality_branch: finality_update
            .finality_branch()
            .iter()
            .map(|n| n.0.to_vec())
            .collect_vec(),
        execution_payload_root,
        execution_payload_branch,
        domain,
        _spec: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use eth2::{SensitiveUrl, Timeouts};
    use eth_types::Testnet;
    use ethereum_types::MainnetEthSpec;
    use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
    use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use halo2_base::utils::fs::gen_srs;
    use lightclient_circuits::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use lightclient_circuits::{
        halo2_base::gates::circuit::CircuitBuilderStage, sync_step_circuit::StepCircuit,
        util::AppCircuit,
    };
    use snark_verifier_sdk::CircuitExt;

    use super::*;

    #[tokio::test]
    async fn test_sync_circuit_sepolia() {
        const K: u32 = 21;
        const URL: &str = "https://lodestar-sepolia.chainsafe.io";
        let client = BeaconNodeHttpClient::new(
            SensitiveUrl::parse(URL).unwrap(),
            Timeouts::set_all(Duration::from_secs(10)),
        );
        let witness = fetch_step_args::<Testnet, MainnetEthSpec>(&client)
            .await
            .unwrap();
        let params: ParamsKZG<Bn256> = gen_srs(K);

        let circuit = StepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            None,
            &witness,
            &params,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied();
    }

    #[tokio::test]
    async fn test_sync_step_snark_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/sync_step_21.json";
        const K: u32 = 21;
        let params = gen_srs(K);

        let pk = StepCircuit::<Testnet, Fr>::create_pk(
            &params,
            "../build/sync_step_21.pkey",
            CONFIG_PATH,
            &SyncStepArgs::<Testnet>::default(),
            None,
        );
        const URL: &str = "https://lodestar-sepolia.chainsafe.io";
        let client = BeaconNodeHttpClient::new(
            SensitiveUrl::parse(URL).unwrap(),
            Timeouts::set_all(Duration::from_secs(10)),
        );
        let witness = fetch_step_args::<Testnet, MainnetEthSpec>(&client)
            .await
            .unwrap();

        StepCircuit::<Testnet, Fr>::gen_snark_shplonk(
            &params,
            &pk,
            CONFIG_PATH,
            None::<String>,
            &witness,
        )
        .unwrap();
    }
}
