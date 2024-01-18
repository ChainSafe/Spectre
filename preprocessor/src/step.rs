// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::marker::PhantomData;

use beacon_api_client::Client;
use beacon_api_client::{BlockId, ClientTypes, StateId};
use eth_types::Spec;
use ethereum_consensus_types::bls::BlsPublicKey;
use ethereum_consensus_types::signing::{compute_domain, DomainType};
use ethereum_consensus_types::{
    BeaconBlockHeader, ForkData, LightClientBootstrap, LightClientFinalityUpdate,
};
use itertools::Itertools;
use lightclient_circuits::witness::{get_helper_indices, merkle_tree, SyncStepArgs};
use ssz_rs::Vector;
use ssz_rs::{Merkleized, Node};

use crate::{block_header_to_leaves, get_light_client_bootstrap, get_light_client_finality_update};

/// Fetches the latest `LightClientFinalityUpdate`` and the current sync committee (from LightClientBootstrap) and converts it to a [`SyncStepArgs`] witness.
pub async fn fetch_step_args<S: Spec, C: ClientTypes>(
    client: &Client<C>,
) -> eyre::Result<SyncStepArgs<S>>
where
    [(); S::SYNC_COMMITTEE_SIZE]:,
    [(); S::FINALIZED_HEADER_DEPTH]:,
    [(); S::SYNC_COMMITTEE_DEPTH]:,
    [(); S::BYTES_PER_LOGS_BLOOM]:,
    [(); S::MAX_EXTRA_DATA_BYTES]:,
{
    let finality_update = get_light_client_finality_update(client).await?;
    let block_root = client
        .get_beacon_block_root(BlockId::Slot(finality_update.finalized_header.beacon.slot))
        .await
        .unwrap();
    let bootstrap: LightClientBootstrap<
        { S::SYNC_COMMITTEE_SIZE },
        { S::SYNC_COMMITTEE_DEPTH },
        { S::BYTES_PER_LOGS_BLOOM },
        { S::MAX_EXTRA_DATA_BYTES },
    > = get_light_client_bootstrap(client, block_root).await?;

    let pubkeys_compressed = bootstrap.current_sync_committee.pubkeys;

    let attested_state_id = finality_update.attested_header.beacon.state_root;

    let fork_version = client
        .get_fork(StateId::Root(attested_state_id))
        .await?
        .current_version;
    let genesis_validators_root = client.get_genesis_details().await?.genesis_validators_root;
    let fork_data = ForkData {
        genesis_validators_root,
        fork_version,
    };
    let domain = compute_domain(DomainType::SyncCommittee, &fork_data)?;

    step_args_from_finality_update(finality_update, pubkeys_compressed, domain).await
}

/// Converts a [`LightClientFinalityUpdate`] to a [`SyncStepArgs`] witness.
pub async fn step_args_from_finality_update<S: Spec>(
    finality_update: LightClientFinalityUpdate<
        { S::SYNC_COMMITTEE_SIZE },
        { S::FINALIZED_HEADER_DEPTH },
        { S::BYTES_PER_LOGS_BLOOM },
        { S::MAX_EXTRA_DATA_BYTES },
    >,
    pubkeys_compressed: Vector<BlsPublicKey, { S::SYNC_COMMITTEE_SIZE }>,
    domain: [u8; 32],
) -> eyre::Result<SyncStepArgs<S>> {
    let pubkeys_uncompressed = pubkeys_compressed
        .iter()
        .map(|pk| pk.decompressed_bytes())
        .collect_vec();

    let execution_payload_root = finality_update
        .finalized_header
        .execution
        .clone()
        .hash_tree_root()?
        .to_vec();
    let execution_payload_branch = finality_update
        .finalized_header
        .execution_branch
        .iter()
        .map(|n| n.0.to_vec())
        .collect_vec();

    assert!(
        ssz_rs::is_valid_merkle_branch(
            Node::try_from(execution_payload_root.as_slice())?,
            &execution_payload_branch,
            S::EXECUTION_STATE_ROOT_DEPTH,
            S::EXECUTION_STATE_ROOT_INDEX,
            finality_update.finalized_header.beacon.body_root,
        )
        .is_ok(),
        "Execution payload merkle proof verification failed"
    );
    assert!(
        ssz_rs::is_valid_merkle_branch(
            finality_update
                .finalized_header
                .beacon
                .clone()
                .hash_tree_root()
                .unwrap(),
            &finality_update
                .finality_branch
                .iter()
                .map(|n| n.as_ref())
                .collect_vec(),
            S::FINALIZED_HEADER_DEPTH,
            S::FINALIZED_HEADER_INDEX,
            finality_update.attested_header.beacon.state_root,
        )
        .is_ok(),
        "Finality merkle proof verification failed"
    );

    let beacon_header_multiproof_and_helper_indices =
        |header: &mut BeaconBlockHeader, gindices: &[usize]| {
            let header_leaves = block_header_to_leaves(header).unwrap();
            let merkle_tree = merkle_tree(&header_leaves);
            let helper_indices = get_helper_indices(gindices);
            let proof = helper_indices
                .iter()
                .copied()
                .map(|i| merkle_tree[i])
                .collect_vec();
            // println!("Proof length: {}", proof.len());
            assert_eq!(proof.len(), helper_indices.len());
            (proof, helper_indices)
        };

    // Proof length is 3
    let (attested_header_multiproof, attested_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &mut finality_update.attested_header.beacon.clone(),
            &[S::HEADER_SLOT_INDEX, S::HEADER_STATE_ROOT_INDEX],
        );
    // Proof length is 4
    let (finalized_header_multiproof, finalized_header_helper_indices) =
        beacon_header_multiproof_and_helper_indices(
            &mut finality_update.finalized_header.beacon.clone(),
            &[S::HEADER_SLOT_INDEX, S::HEADER_BODY_ROOT_INDEX],
        );

    Ok(SyncStepArgs {
        signature_compressed: finality_update
            .sync_aggregate
            .sync_committee_signature
            .to_bytes()
            .to_vec(),
        pubkeys_uncompressed,
        pariticipation_bits: finality_update
            .sync_aggregate
            .sync_committee_bits
            .iter()
            .by_vals()
            .collect_vec(),
        attested_header: finality_update.attested_header.beacon,
        finalized_header: finality_update.finalized_header.beacon,
        finality_branch: finality_update
            .finality_branch
            .iter()
            .map(|n| n.0.to_vec())
            .collect_vec(),
        execution_payload_root: finality_update
            .finalized_header
            .execution
            .clone()
            .hash_tree_root()
            .unwrap()
            .to_vec(),
        execution_payload_branch: finality_update
            .finalized_header
            .execution_branch
            .iter()
            .map(|n| n.0.to_vec())
            .collect_vec(),
        domain,
        _spec: PhantomData,
        attested_header_multiproof: attested_header_multiproof
            .into_iter()
            .map(|n| n.as_ref().to_vec())
            .collect_vec(),
        attested_header_helper_indices,
        finalized_header_multiproof: finalized_header_multiproof
            .into_iter()
            .map(|n| n.as_ref().to_vec())
            .collect_vec(),
        finalized_header_helper_indices,
    })
}

#[cfg(test)]
mod tests {
    use eth_types::Testnet;
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
    use beacon_api_client::mainnet::Client as MainnetClient;
    use reqwest::Url;

    #[tokio::test]
    async fn test_sync_circuit_sepolia() {
        const K: u32 = 21;
        let client =
            MainnetClient::new(Url::parse("https://lodestar-sepolia.chainsafe.io").unwrap());

        let witness = fetch_step_args::<Testnet, _>(&client).await.unwrap();
        let params: ParamsKZG<Bn256> = gen_srs(K);

        let circuit = StepCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            None,
            &witness,
            &params,
        )
        .unwrap();

        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied_par();
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
        let client =
            MainnetClient::new(Url::parse("https://lodestar-sepolia.chainsafe.io").unwrap());
        let witness = fetch_step_args::<Testnet, _>(&client).await.unwrap();

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
