// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::collections::HashSet;
use std::marker::PhantomData;

use crate::merkle::*;
use crate::{get_block_header, get_light_client_bootstrap, get_light_client_finality_update};
use beacon_api_client::Client;
use beacon_api_client::{BlockId, ClientTypes, StateId};
use eth_types::Spec;
use ethereum_consensus_types::bls::BlsPublicKey;
use ethereum_consensus_types::signing::{compute_domain, DomainType};
use ethereum_consensus_types::{
    BeaconBlockHeader, ForkData, LightClientBootstrap, LightClientFinalityUpdate, Root,
};
use itertools::Itertools;
use lightclient_circuits::witness::SyncStepArgs;
use ssz_rs::Vector;
use ssz_rs::{Merkleized, Node};

// typeName: 'BeaconBlock',
// maxChunkCount: 5,
// depth: 3,
// fieldsEntries: [
//   {
//     fieldName: 'slot',
//     fieldType: [UintNumberType],
//     jsonKey: 'slot',
//     gindex: 8n
//   },
//   {
//     fieldName: 'proposerIndex',
//     fieldType: [UintNumberType],
//     jsonKey: 'proposer_index',
//     gindex: 9n
//   },
//   {
//     fieldName: 'parentRoot',
//     fieldType: [ByteVectorType],
//     jsonKey: 'parent_root',
//     gindex: 10n
//   },
//   {
//     fieldName: 'stateRoot',
//     fieldType: [ByteVectorType],
//     jsonKey: 'state_root',
//     gindex: 11n
//   },
//   {
//     fieldName: 'body',
//     fieldType: [ContainerType],
//     jsonKey: 'body',
//     gindex: 12n
//   }
// ],

// ExecutionPayloadHeader fieldsGindex: {
//     parentHash: 16n,
//     feeRecipient: 17n,
//     stateRoot: 18n,
//     receiptsRoot: 19n,
//     logsBloom: 20n,
//     prevRandao: 21n,
//     blockNumber: 22n,
//     gasLimit: 23n,
//     gasUsed: 24n,
//     timestamp: 25n,
//     extraData: 26n,
//     baseFeePerGas: 27n,
//     blockHash: 28n,
//     transactionsRoot: 29n,
//     withdrawalsRoot: 30n,
//     excessDataGas: 31n
//   },

/// Fetches the latest `LightClientFinalityUpdate`` and the current sync committee (from LightClientBootstrap) and converts it to a [`SyncStepArgs`] witness.
pub async fn fetch_polyfill_args<S: Spec, C: ClientTypes>(
    client: &Client<C>,
    start: Root,
    end: Root,
) -> eyre::Result<Vec<BeaconBlockHeader>> {
    let mut current_block_root = start;
    let mut block_headers = vec![];
    while current_block_root != end {
        let block = get_block_header(&client, BlockId::Root(current_block_root)).await?;
        current_block_root = block.parent_root;
        block_headers.push(block);
    }
    block_headers.push(get_block_header(&client, BlockId::Root(end)).await?);
    Ok(block_headers)
}
pub fn slot_proof_and_indices(header: &mut BeaconBlockHeader) -> (Vec<Node>, Vec<usize>) {
    let SLOT_GINDEX: usize = 8;
    let BODY_GINDEX: usize = 12;
    let PROOF_GINDICES = [SLOT_GINDEX, BODY_GINDEX];

    let header_leaves = block_header_to_leaves(header).unwrap();
    let merkle_tree = merkle_tree(&header_leaves);
    let helper_indices = get_helper_indices(&PROOF_GINDICES);
    let proof = helper_indices
        .iter()
        .copied()
        .map(|i| merkle_tree[i])
        .collect_vec();
    println!("Proof for slot and body length: {}", proof.len());
    println!("helper_indices: {:?}", helper_indices);

    assert_eq!(proof.len(), helper_indices.len());
    (proof, helper_indices)
}
#[cfg(test)]
mod tests {
    use eth_types::Testnet;
    use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
    use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use halo2_base::utils::fs::gen_srs;
    use lightclient_circuits::aggregation_circuit::AggregationConfigPinning;
    use lightclient_circuits::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use lightclient_circuits::polyfill_circuit::PolyfillCircuit;
    use lightclient_circuits::util::Halo2ConfigPinning;
    use lightclient_circuits::witness::PolyfillArgs;
    use lightclient_circuits::{halo2_base::gates::circuit::CircuitBuilderStage, util::AppCircuit};
    use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk};
    use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
    use snark_verifier_sdk::CircuitExt;

    use super::*;
    use beacon_api_client::mainnet::Client as MainnetClient;
    use reqwest::Url;

    #[tokio::test]
    async fn test_polyfill_circuit_sepolia() {
        const K: u32 = 17;
        let client =
            MainnetClient::new(Url::parse("https://lodestar-sepolia.chainsafe.io").unwrap());
        let start_root = client.get_beacon_block_root(BlockId::Head).await.unwrap();
        let end_root = client
            .get_beacon_block_root(BlockId::Finalized)
            .await
            .unwrap();
        println!(
            "Polyfill from Head: {} to Finalized: {}",
            start_root, end_root
        );

        let witness = fetch_polyfill_args::<Testnet, _>(&client, start_root, end_root)
            .await
            .unwrap();
        println!(
            "Filling in {} blocks from Slot: {} to {}",
            witness.len(),
            witness.first().unwrap().slot,
            witness.last().unwrap().slot
        );

        let params: ParamsKZG<Bn256> = gen_srs(K);
        for w in witness.windows(2) {
            let mut parent_header = w.last().unwrap().clone();
            let (parent_slot_proof, helper_indices) = slot_proof_and_indices(&mut parent_header);
            let parent_slot_proof = parent_slot_proof
                .iter()
                .map(|n| n.as_ref().to_vec())
                .collect_vec();

            let arg = PolyfillArgs::<Testnet> {
                verified_header: w.first().unwrap().clone(),
                parent_header,
                parent_slot_proof,
                helper_indices,
                _p: PhantomData,
            };
            let circuit = PolyfillCircuit::<Testnet, Fr>::create_circuit(
                CircuitBuilderStage::Mock,
                None,
                &arg,
                &params,
            )
            .unwrap();

            let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
            prover.assert_satisfied_par();
            println!(
                "Polyfill satisfied for blocks {} to {}",
                w.first().unwrap().slot,
                w.last().unwrap().slot
            );
        }
    }

    #[tokio::test]
    async fn test_polyfill_snark_sepolia() {
        const CONFIG_PATH: &str = "../lightclient-circuits/config/polyfill_17.json";
        const K: u32 = 17;
        let client =
            MainnetClient::new(Url::parse("https://lodestar-sepolia.chainsafe.io").unwrap());
        let params = gen_srs(K);

        let start_root = client.get_beacon_block_root(BlockId::Head).await.unwrap();
        let end_root = {
            let start_block = get_block_header(&client, BlockId::Root(start_root))
                .await
                .unwrap();

            client
                .get_beacon_block_root(BlockId::Slot(start_block.slot - 3))
                .await
                .unwrap()
        };

        let witness = fetch_polyfill_args::<Testnet, _>(&client, start_root, end_root)
            .await
            .unwrap();
        println!(
            "Filling in {} blocks from Slot: {} to {}",
            witness.len(),
            witness.first().unwrap().slot,
            witness.last().unwrap().slot
        );

        let pk = PolyfillCircuit::<Testnet, Fr>::create_pk(
            &params,
            "../build/polyfill_17.pkey",
            CONFIG_PATH,
            &PolyfillArgs::<Testnet>::default(),
            None,
        );
        let mut snarks = vec![];
        for w in witness.windows(2) {
            let mut parent_header = w.last().unwrap().clone();
            let (parent_slot_proof, helper_indices) = slot_proof_and_indices(&mut parent_header);
            let parent_slot_proof = parent_slot_proof
                .iter()
                .map(|n| n.as_ref().to_vec())
                .collect_vec();

            let arg = PolyfillArgs::<Testnet> {
                verified_header: w.first().unwrap().clone(),
                parent_header,
                parent_slot_proof,
                helper_indices,
                _p: PhantomData,
            };
            let snark = PolyfillCircuit::<Testnet, Fr>::gen_snark_shplonk(
                &params,
                &pk,
                CONFIG_PATH,
                None::<String>,
                &arg,
            )
            .unwrap();
            println!(
                "Polyfill snark gen for blocks {} to {}",
                w.first().unwrap().slot,
                w.last().unwrap().slot
            );
            snarks.push(snark);
        }

        const AGG_K: u32 = 23;
        const AGG_PK_PATH: &str = "../build/polyfill_verifier_23.pkey";
        const AGG_CONFIG_PATH: &str = "./config/polyfill_verifier_23.json";

        let agg_params = gen_srs(AGG_K);

        let pk = AggregationCircuit::create_pk(
            &agg_params,
            AGG_PK_PATH,
            AGG_CONFIG_PATH,
            &snarks,
            Some(AggregationConfigPinning::new(AGG_K, 19)),
        );

        let agg_config = AggregationConfigPinning::from_path(AGG_CONFIG_PATH);

        let agg_circuit = AggregationCircuit::create_circuit(
            CircuitBuilderStage::Prover,
            Some(agg_config),
            &snarks,
            &agg_params,
        )
        .unwrap();

        let instances = agg_circuit.instances();
        let num_instances = agg_circuit.num_instance();

        println!("num_instances: {:?}", num_instances);
        println!("instances: {:?}", instances);

        let proof = gen_evm_proof_shplonk(&agg_params, &pk, agg_circuit, instances.clone());
        println!("proof size: {}", proof.len());
        let deployment_code =
            AggregationCircuit::gen_evm_verifier_shplonk(&agg_params, &pk, None::<String>, &snarks)
                .unwrap();
        println!("deployment_code size: {}", deployment_code.len());
        evm_verify(deployment_code, instances, proof);
    }
}
