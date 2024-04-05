// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::marker::PhantomData;

use eth_types::Spec;
use itertools::Itertools;
use lightclient_circuits::witness::{beacon_header_multiproof_and_helper_indices, SyncStepArgs};

use blst::min_pk as bls;
use eth2::types::StateId;
use eth2::BeaconNodeHttpClient;
use ethereum_types::Domain;
use ethereum_types::{EthSpec, FixedVector, LightClientFinalityUpdate, PublicKeyBytes};
use tree_hash::{Hash256, TreeHash};

/// Fetches the latest `LightClientFinalityUpdate`` and the current sync committee (from LightClientBootstrap) and converts it to a [`SyncStepArgs`] witness.
pub async fn fetch_step_args<S: Spec>(
    client: &BeaconNodeHttpClient,
) -> eyre::Result<SyncStepArgs<S>> {
    let finality_update = client
        .get_beacon_light_client_finality_update::<S::EthSpec>()
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
        .get_light_client_bootstrap::<S::EthSpec>(block_root)
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
        .map_err(|e| eyre::eyre!("Failed to get fork version: {:?}", e))?
        .ok_or(eyre::eyre!("Failed to get fork version: None"))?
        .data
        .current_version;

    let genesis_validators_root = client
        .get_beacon_genesis()
        .await
        .map_err(|e| eyre::eyre!("Failed to get genesis validators root: {:?}", e))?
        .data
        .genesis_validators_root;

    let domain = S::EthSpec::default_spec().compute_domain(
        Domain::SyncCommittee,
        fork_version,
        genesis_validators_root,
    );

    step_args_from_finality_update(finality_update, pubkeys_compressed, domain.into()).await
}

/// Converts a [`LightClientFinalityUpdate`] to a [`SyncStepArgs`] witness.
pub async fn step_args_from_finality_update<S: Spec>(
    finality_update: LightClientFinalityUpdate<S::EthSpec>,
    pubkeys_compressed: &FixedVector<PublicKeyBytes, <S::EthSpec as EthSpec>::SyncCommitteeSize>,
    domain: [u8; 32],
) -> eyre::Result<SyncStepArgs<S>> {
    let pubkeys_uncompressed = pubkeys_compressed
        .iter()
        .map(|pk| {
            bls::PublicKey::uncompress(&pk.serialize())
                .map_err(|e| eyre::eyre!("Failed to uncompress public key: {:?}", e))
                .map(|k| bls::PublicKey::serialize(&k))
                .map(|b| b.to_vec())
        })
        .collect::<Result<Vec<Vec<u8>>, _>>()?;

    let (execution_payload_root, execution_payload_branch) = match finality_update {
        LightClientFinalityUpdate::Altair(_) => unimplemented!(),
        LightClientFinalityUpdate::Capella(ref header) => {
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
        LightClientFinalityUpdate::Deneb(ref header) => {
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

    assert!(
        merkle_proof::verify_merkle_proof(
            Hash256::from_slice(&execution_payload_root),
            &execution_payload_branch
                .iter()
                .map(|n| Hash256::from_slice(n))
                .collect_vec(),
            S::EXECUTION_STATE_ROOT_DEPTH,
            S::EXECUTION_STATE_ROOT_INDEX,
            finalized_header_beacon.body_root,
        ),
        "Execution payload merkle proof verification failed"
    );
    assert!(
        merkle_proof::verify_merkle_proof(
            finalized_header_beacon.tree_hash_root(),
            finality_update.finality_branch(),
            S::FINALIZED_HEADER_DEPTH,
            S::FINALIZED_HEADER_INDEX,
            attested_header_beacon.state_root,
        ),
        "Finality merkle proof verification failed"
    );

    // Proof length is 3
    let (attested_header_multiproof, attested_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &attested_header_beacon,
            &[S::HEADER_SLOT_INDEX, S::HEADER_STATE_ROOT_INDEX],
        );
    // Proof length is 4
    let (finalized_header_multiproof, finalized_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &finalized_header_beacon,
            &[S::HEADER_SLOT_INDEX, S::HEADER_BODY_ROOT_INDEX],
        );

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
        attested_header_multiproof,
        attested_header_helper_indices,
        finalized_header_multiproof,
        finalized_header_helper_indices,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use eth2::{SensitiveUrl, Timeouts};
    use eth_types::Testnet;
    use halo2_base::gates::circuit::CircuitBuilderStage;
    use halo2_base::halo2_proofs::dev::MockProver;
    use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
    use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use halo2_base::utils::fs::gen_srs;
    use lightclient_circuits::halo2_proofs::halo2curves::bn256::Fr;
    use lightclient_circuits::{sync_step_circuit::StepCircuit, util::AppCircuit};
    use snark_verifier_sdk::CircuitExt;

    #[tokio::test]
    async fn test_sync_circuit_sepolia() {
        const K: u32 = 21;
        const URL: &str = "https://lodestar-sepolia.chainsafe.io";
        let client = BeaconNodeHttpClient::new(
            SensitiveUrl::parse(URL).unwrap(),
            Timeouts::set_all(Duration::from_secs(10)),
        );
        let witness = fetch_step_args::<Testnet>(&client).await.unwrap();
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
        let witness = fetch_step_args::<Testnet>(&client).await.unwrap();

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
