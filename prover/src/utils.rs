// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use std::{sync::Arc, time::Duration};

use crate::args::UtilsCmd;
use blst::min_pk as bls;
use eth2::{types::BlockId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use eth_types::LIMB_BITS;
use ethereum_types::{LightClientBootstrap, MainnetEthSpec};
use itertools::Itertools;
use lightclient_circuits::poseidon::poseidon_committee_commitment_from_uncompressed;
use tree_hash::TreeHash;

pub(crate) async fn utils_cli(method: UtilsCmd) -> eyre::Result<()> {
    match method {
        UtilsCmd::CommitteePoseidon { beacon_api } => {
            let beacon_client = Arc::new(BeaconNodeHttpClient::new(
                SensitiveUrl::parse(&beacon_api).unwrap(),
                Timeouts::set_all(Duration::from_secs(10)),
            ));

            let block_root = beacon_client
                .get_beacon_blocks_root(BlockId::Head)
                .await
                .unwrap()
                .unwrap()
                .data
                .root;

            let bootstrap = beacon_client
                .get_light_client_bootstrap::<MainnetEthSpec>(block_root)
                .await
                .map_err(|e| eyre::eyre!("Failed to get bootstrap: {:?}", e))?
                .ok_or(eyre::eyre!("Failed to get bootstrap: None"))?
                .data;

            let sync_period = match bootstrap {
                LightClientBootstrap::Altair(_) => unimplemented!("Altair not implemented"),
                LightClientBootstrap::Capella(ref bootstrap) => bootstrap.header.beacon.slot,
                LightClientBootstrap::Deneb(ref bootstrap) => bootstrap.header.beacon.slot,
            } / (32 * 256);

            println!("Sync period: {}", sync_period);

            let pubkeys_uncompressed = bootstrap
                .current_sync_committee()
                .pubkeys
                .iter()
                .map(|pk| {
                    bls::PublicKey::uncompress(&pk.serialize())
                        .unwrap()
                        .serialize()
                        .to_vec()
                })
                .collect_vec();

            // let pubkeys_uncompressed = bootstrap
            //     .current_sync_committee()
            //     .pubkeys
            //     .iter()
            //     .map(|pk| pk.decompressed_bytes())
            //     .collect_vec();

            let ssz_root = bootstrap.current_sync_committee().pubkeys.tree_hash_root();

            println!("SSZ root: {:?}", hex::encode(ssz_root.0));

            let mut committee_poseidon =
                poseidon_committee_commitment_from_uncompressed(&pubkeys_uncompressed, LIMB_BITS)
                    .to_bytes();
            committee_poseidon.reverse();
            println!("Poseidon commitment: {}", hex::encode(committee_poseidon));

            Ok(())
        }
    }
}
