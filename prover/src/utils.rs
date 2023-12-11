use std::{ops::Deref, sync::Arc};

use beacon_api_client::{BlockId, VersionedValue};
use ethereum_consensus_types::LightClientBootstrap;
use itertools::Itertools;
use lightclient_circuits::poseidon::poseidon_committee_commitment_from_uncompressed;
use ssz_rs::Merkleized;
use url::Url;

use beacon_api_client::mainnet::Client as MainnetBeaconClient;

use crate::args::UtilsCmd;

pub(crate) async fn utils_cli(method: UtilsCmd) -> eyre::Result<()> {
    match method {
        UtilsCmd::CommitteePoseidon { beacon_api } => {
            let reqwest_client = reqwest::Client::new();
            let beacon_client = Arc::new(MainnetBeaconClient::new_with_client(
                reqwest_client.clone(),
                Url::parse(&beacon_api).unwrap(),
            ));
            let block = beacon_client
                .get_beacon_block_root(BlockId::Head)
                .await
                .unwrap();
            let route = format!("eth/v1/beacon/light_client/bootstrap/{block:?}");
            let mut bootstrap = match beacon_client
                .get::<VersionedValue<LightClientBootstrap<512, 5, 256, 32>>>(&route)
                .await
            {
                Ok(v) => v.data,
                Err(e) => {
                    return Err(eyre::eyre!("Failed to fetch bootstrap: {}", e));
                }
            };

            let sync_period = bootstrap.header.beacon.slot / (32 * 256);
            print!("{} \n", sync_period);
            let pubkeys_uncompressed = bootstrap
                .current_sync_committee
                .pubkeys
                .iter()
                .map(|pk| pk.decompressed_bytes())
                .collect_vec();

            let ssz_root = bootstrap
                .current_sync_committee
                .pubkeys
                .hash_tree_root()
                .unwrap();
            println!("ssz root: {:?}", hex::encode(ssz_root.deref()));

            let committee_poseidon =
                poseidon_committee_commitment_from_uncompressed(&pubkeys_uncompressed).to_bytes();
            print!("{}", hex::encode(committee_poseidon));

            Ok(())
        }
    }
}
