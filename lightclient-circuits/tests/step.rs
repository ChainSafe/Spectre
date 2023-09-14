use ark_std::env::set_var;
use ark_std::{end_timer, start_timer};
use eth_types::Minimal;
use ethereum_consensus_types::presets::minimal::{LightClientBootstrap, LightClientUpdate};
use ethereum_consensus_types::signing::{compute_domain, DomainType};
use ethereum_consensus_types::{ForkData, Root};
use halo2_base::gates::range::{RangeConfig, RangeStrategy};
use halo2_base::safe_types::RangeChip;
use halo2_base::AssignedValue;
use halo2_proofs::dev::MockProver;
use halo2curves::bn256::{self, Bn256};
use halo2curves::{bls12_381::G1Affine, group::GroupEncoding, group::UncompressedEncoding};
use itertools::Itertools;
use light_client_verifier::ZiplineWitness;
use lightclient_circuits::builder::Eth2CircuitBuilder;
use lightclient_circuits::gadget::crypto::ShaThreadBuilder;
use lightclient_circuits::sync_step_circuit::SyncStepCircuit;
use lightclient_circuits::util::ThreadBuilderBase;
use lightclient_circuits::witness::SyncStepArgs;
use rstest::rstest;
use snark_verifier_sdk::CircuitExt;
use ssz_rs::prelude::*;
use std::path::PathBuf;
use test_utils::{load_snappy_ssz, load_yaml};
#[derive(Debug, serde::Deserialize)]
struct TestMeta {
    genesis_validators_root: String,
    trusted_block_root: String,
    bootstrap_fork_digest: String,
    store_fork_digest: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TestStep {
    ProcessUpdate {
        update_fork_digest: String,
        update: String,
        current_slot: u64,
        checks: Checks,
    },
    ForceUpdate {
        current_slot: u64,
        checks: Checks,
    },
}

#[derive(Debug, serde::Deserialize)]
struct Checks {
    finalized_header: RootAtSlot,
    optimistic_header: RootAtSlot,
}

#[derive(Debug, serde::Deserialize)]
struct RootAtSlot {
    slot: u64,
    beacon_root: String,
}

fn to_witness<
    const SYNC_COMMITTEE_SIZE: usize,
    const NEXT_SYNC_COMMITTEE_GINDEX: usize,
    const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
    const FINALIZED_ROOT_GINDEX: usize,
    const FINALIZED_ROOT_PROOF_SIZE: usize,
>(
    zipline_witness: &ZiplineWitness<
        SYNC_COMMITTEE_SIZE,
        NEXT_SYNC_COMMITTEE_GINDEX,
        NEXT_SYNC_COMMITTEE_PROOF_SIZE,
        FINALIZED_ROOT_GINDEX,
        FINALIZED_ROOT_PROOF_SIZE,
    >,
    genesis_validators_root: Root,
) -> SyncStepArgs<Minimal> {
    let mut args = SyncStepArgs::<Minimal>::default();
    args.signature_compressed = zipline_witness
        .light_client_update
        .sync_aggregate
        .sync_committee_signature
        .to_bytes()
        .to_vec();
    args.signature_compressed.reverse();
    let pubkeys_uncompressed = zipline_witness
        .committee
        .pubkeys
        .iter()
        .map(|pk| {
            let p = pk.decompressed_bytes();
            let mut x = (&p[0..48]).clone().to_vec();
            let mut y = (&p[48..96]).clone().to_vec();
            x.reverse();
            y.reverse();
            let mut res = vec![];
            res.append(&mut x);
            res.append(&mut y);
            res
        })
        .collect_vec();
    args.pubkeys_uncompressed = pubkeys_uncompressed;
    args.pariticipation_bits = zipline_witness
        .light_client_update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .map(|b| *b)
        .collect();
    args.attested_block = ethereum_consensus::phase0::BeaconBlockHeader {
        slot: zipline_witness.light_client_update.attested_header.slot,
        proposer_index: zipline_witness
            .light_client_update
            .attested_header
            .proposer_index,
        parent_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .parent_root
                .as_ref(),
        )
        .unwrap(),
        state_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .state_root
                .as_ref(),
        )
        .unwrap(),
        body_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .body_root
                .as_ref(),
        )
        .unwrap(),
    };
    args.finalized_block = ethereum_consensus::phase0::BeaconBlockHeader {
        slot: zipline_witness.light_client_update.finalized_header.slot,
        proposer_index: zipline_witness
            .light_client_update
            .finalized_header
            .proposer_index,
        parent_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .parent_root
                .as_ref(),
        )
        .unwrap(),
        state_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .state_root
                .as_ref(),
        )
        .unwrap(),
        body_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .body_root
                .as_ref(),
        )
        .unwrap(),
    };
    let mut p = args.finalized_block.clone();
    let h = p.hash_tree_root().unwrap();
    println!("finalized_block hash_tree_root: {:x?}", h.as_bytes());
    let fork_data = ForkData {
        fork_version: [1, 0, 0, 1],
        genesis_validators_root: genesis_validators_root.clone(),
    };
    let signing_domain = compute_domain(DomainType::SyncCommittee, &fork_data).unwrap();
    args.domain = signing_domain;
    args.execution_merkle_branch = vec![vec![]];
    args.execution_state_root = vec![];
    args.finality_merkle_branch = zipline_witness
        .light_client_update
        .finality_branch
        .iter()
        .map(|b| b.as_ref().to_vec())
        .collect();
    args.beacon_state_root = args.attested_block.state_root.as_ref().to_vec();
    println!("beacon_state_root: {:x?}", args.beacon_state_root);

    args
}
#[rstest]
fn test_verify(
    #[files("../consensus-spec-tests/tests/minimal/altair/light_client/sync/pyspec_tests/deneb_store_with_legacy_data")]
    path: PathBuf,
) {
    let bootstrap: LightClientBootstrap =
        load_snappy_ssz(&path.join("bootstrap.ssz_snappy").to_str().unwrap()).unwrap();
    let meta: TestMeta = load_yaml(&path.join("meta.yaml").to_str().unwrap());
    let steps: Vec<TestStep> = load_yaml(&path.join("steps.yaml").to_str().unwrap());

    let genesis_validators_root = Root::try_from(
        hex::decode(meta.genesis_validators_root.trim_start_matches("0x"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let fork_data = ForkData {
        fork_version: [1, 0, 0, 1],
        genesis_validators_root: genesis_validators_root.clone(),
    };
    println!("fork_data: 0x{:?}", hex::encode(fork_data.fork_digest()));

    // let circuit = SyncStepCircuit::<Minimal, bn256::Fr>::default();
    let updates = steps
        .iter()
        .filter_map(|step| match step {
            TestStep::ProcessUpdate { update, .. } => {
                let update: LightClientUpdate = load_snappy_ssz(
                    &path
                        .join(format!("{}.ssz_snappy", update))
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
                Some(update)
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    let zipline_witness = ZiplineWitness {
        committee: bootstrap.current_sync_committee.clone(),
        light_client_update: updates[0].clone(),
    };

    const K: usize = 20;
    let mut builder = ShaThreadBuilder::mock();
    let spectre_args = to_witness(&zipline_witness, genesis_validators_root.clone());
    let assigned_instances = load_circuit_with_data(&spectre_args, &mut builder, K);

    let circuit = Eth2CircuitBuilder::mock(assigned_instances, builder);

    let timer = start_timer!(|| "sync circuit mock prover");
    let prover = MockProver::<bn256::Fr>::run(K as u32, &circuit, circuit.instances()).unwrap();
    prover.assert_satisfied_par();
    end_timer!(timer);
}

fn load_circuit_with_data(
    args: &SyncStepArgs<Minimal>,
    thread_pool: &mut ShaThreadBuilder<bn256::Fr>,
    k: usize,
) -> Vec<AssignedValue<bn256::Fr>> {
    let circuit = SyncStepCircuit::<Minimal, bn256::Fr>::default();
    let range = RangeChip::<bn256::Fr>::new(RangeStrategy::Vertical, 8);

    let instance = circuit.synthesize(thread_pool, &range, args).unwrap();

    let config = thread_pool.config(k, None);
    set_var("LOOKUP_BITS", (config.k - 1).to_string());
    println!("params used: {:?}", config);

    instance
}

// #[test]
// fn test_sync_circuit() {
//     const K: usize = 20;

//     let mut builder = ShaThreadBuilder::mock();
//     let (assigned_instances, args) = load_circuit_with_data(&mut builder, K);

//     let circuit = Eth2CircuitBuilder::mock(assigned_instances, builder);

//     let timer = start_timer!(|| "sync circuit mock prover");
//     let prover = MockProver::<Fr>::run(K as u32, &circuit, circuit.instances()).unwrap();
//     prover.assert_satisfied_par();
//     end_timer!(timer);
// }

// #[test]
// fn test_sync_proofgen() {
//     const K: usize = 20;

//     let (params, pk, break_points) = SyncStepCircuit::<Test, Fr>::setup(K, None);

//     let mut builder = ShaThreadBuilder::prover();
//     let (assigned_instances, args) = load_circuit_with_data(&mut builder, K);
//     let circuit = Eth2CircuitBuilder::prover(assigned_instances, builder, break_points);

//     let instances = SyncStepCircuit::<Test, bn256::Fr>::instances(args);
//     let proof = full_prover(&params, &pk, circuit, instances.clone());

//     assert!(full_verifier(&params, pk.get_vk(), proof, instances))
// }
