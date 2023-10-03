use ark_std::{end_timer, start_timer};
use eth_types::Minimal;
use ethereum_consensus_types::presets::minimal::{LightClientBootstrap, LightClientUpdateCapella};
use ethereum_consensus_types::signing::{compute_domain, DomainType};
use ethereum_consensus_types::{ForkData, Root};
use halo2_base::gates::builder::CircuitBuilderStage;
use halo2_proofs::dev::MockProver;
use halo2curves::bn256;
use itertools::Itertools;
use light_client_verifier::ZiplineUpdateWitnessCapella;
use lightclient_circuits::sync_step_circuit::SyncStepCircuit;
use lightclient_circuits::util::gen_srs;
use lightclient_circuits::util::AppCircuit;
use lightclient_circuits::util::Eth2ConfigPinning;
use lightclient_circuits::util::Halo2ConfigPinning;
use lightclient_circuits::util::{full_prover, full_verifier};
use lightclient_circuits::witness::SyncStepArgs;
use rstest::rstest;
use snark_verifier_sdk::CircuitExt;
use ssz_rs::prelude::*;
use ssz_rs::Merkleized;
use ssz_rs::Node;
use std::path::PathBuf;
use sync_committee_primitives::consensus_types::BeaconBlockHeader;
use snark_verifier::loader::evm::{deploy_and_call, encode_calldata};

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
    execution_root: String,
}

// TODO: remove this once we have a better way to handle the `ssz_rs` dependency
#[derive(Debug, Default, Clone, PartialEq, SimpleSerialize, Eq)]
pub struct ByteVector<const N: usize>(pub Vector<u8, N>);
#[derive(Default, Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct ByteList<const N: usize>(List<u8, N>);
pub type ExecutionAddress = ByteVector<20>;

#[derive(Default, Debug, Clone, SimpleSerialize, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecutionPayloadHeader<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub parent_hash: Node,
    pub fee_recipient: ExecutionAddress,
    pub state_root: Node,
    pub receipts_root: Node,
    pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
    pub prev_randao: Node,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
    pub base_fee_per_gas: U256,
    pub block_hash: Node,
    pub transactions_root: Node,
    pub withdrawals_root: Node,
}

impl<const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    From<
        ethereum_consensus_types::light_client::ExecutionPayloadHeader<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > for ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn from(
        header: ethereum_consensus_types::light_client::ExecutionPayloadHeader<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> Self {
        Self {
            parent_hash: Node::from_bytes(header.parent_hash.as_ref().try_into().unwrap()),
            fee_recipient: ByteVector(
                Vector::try_from(header.fee_recipient.0.as_ref().to_vec()).unwrap(),
            ),
            state_root: Node::from_bytes(header.state_root.as_ref().try_into().unwrap()),
            receipts_root: Node::from_bytes(header.receipts_root.as_ref().try_into().unwrap()),
            logs_bloom: ByteVector(
                Vector::try_from(header.logs_bloom.0.as_ref().to_vec()).unwrap(),
            ),
            prev_randao: Node::from_bytes(header.prev_randao.as_ref().try_into().unwrap()),
            block_number: header.block_number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            extra_data: ByteList(List::try_from(header.extra_data.0.as_ref().to_vec()).unwrap()),
            base_fee_per_gas: U256::from_bytes_le(
                header.base_fee_per_gas.to_bytes_le().try_into().unwrap(),
            ),
            block_hash: Node::from_bytes(header.block_hash.as_ref().try_into().unwrap()),
            transactions_root: Node::from_bytes(
                header.transactions_root.as_ref().try_into().unwrap(),
            ),
            withdrawals_root: Node::from_bytes(
                header.withdrawals_root.as_ref().try_into().unwrap(),
            ),
        }
    }
}

fn to_witness<
    const SYNC_COMMITTEE_SIZE: usize,
    const NEXT_SYNC_COMMITTEE_GINDEX: usize,
    const NEXT_SYNC_COMMITTEE_PROOF_SIZE: usize,
    const FINALIZED_ROOT_GINDEX: usize,
    const FINALIZED_ROOT_PROOF_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    zipline_witness: &ZiplineUpdateWitnessCapella<
        SYNC_COMMITTEE_SIZE,
        NEXT_SYNC_COMMITTEE_GINDEX,
        NEXT_SYNC_COMMITTEE_PROOF_SIZE,
        FINALIZED_ROOT_GINDEX,
        FINALIZED_ROOT_PROOF_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
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
    args.attested_header = BeaconBlockHeader {
        slot: zipline_witness
            .light_client_update
            .attested_header
            .beacon
            .slot,
        proposer_index: zipline_witness
            .light_client_update
            .attested_header
            .beacon
            .proposer_index as u64,
        parent_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .beacon
                .parent_root
                .as_ref(),
        )
        .unwrap(),
        state_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .beacon
                .state_root
                .as_ref(),
        )
        .unwrap(),
        body_root: Node::try_from(
            zipline_witness
                .light_client_update
                .attested_header
                .beacon
                .body_root
                .as_ref(),
        )
        .unwrap(),
    };
    args.finalized_header = BeaconBlockHeader {
        slot: zipline_witness
            .light_client_update
            .finalized_header
            .beacon
            .slot,
        proposer_index: zipline_witness
            .light_client_update
            .finalized_header
            .beacon
            .proposer_index as u64,
        parent_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .beacon
                .parent_root
                .as_ref(),
        )
        .unwrap(),
        state_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .beacon
                .state_root
                .as_ref(),
        )
        .unwrap(),
        body_root: Node::try_from(
            zipline_witness
                .light_client_update
                .finalized_header
                .beacon
                .body_root
                .as_ref(),
        )
        .unwrap(),
    };
    let fork_data = ForkData {
        fork_version: [3, 0, 0, 1],
        genesis_validators_root: genesis_validators_root.clone(),
    };
    let signing_domain = compute_domain(DomainType::SyncCommittee, &fork_data).unwrap();
    args.domain = signing_domain;
    args.execution_payload_branch = zipline_witness
        .light_client_update
        .finalized_header
        .execution_branch
        .iter()
        .map(|b| b.0.as_ref().to_vec())
        .collect();
    args.execution_payload_root = {
        let mut execution_payload_header: ExecutionPayloadHeader<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        > = zipline_witness
            .light_client_update
            .finalized_header
            .execution
            .clone()
            .into();

        execution_payload_header
            .hash_tree_root()
            .unwrap()
            .as_ref()
            .to_vec()
    };
    args.finality_branch = zipline_witness
        .light_client_update
        .finality_branch
        .iter()
        .map(|b| b.as_ref().to_vec())
        .collect();
    // args.beacon_state_root = zipline_witness.light_client_update.finalized_header.state_root.clone().as_ref().to_vec();
    // args.beacon_state_root = args.attested_block.state_root.as_ref().to_vec();
    args
}

fn read_test_files_and_gen_witness(path: PathBuf) -> SyncStepArgs<Minimal> {
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

    // let circuit = SyncStepCircuit::<Minimal, bn256::Fr>::default();
    let updates = steps
        .iter()
        .filter_map(|step| match step {
            TestStep::ProcessUpdate { update, .. } => {
                let update: LightClientUpdateCapella = load_snappy_ssz(
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

    let zipline_witness = light_client_verifier::ZiplineUpdateWitnessCapella {
        committee: bootstrap.current_sync_committee.clone(),
        light_client_update: updates[0].clone(),
    };
    to_witness(&zipline_witness, genesis_validators_root.clone())
}
#[rstest]
fn test_step_mock(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) {
    const K: u32 = 21;
    let params = gen_srs(K);

    let witness = read_test_files_and_gen_witness(path);
    let pinning = Eth2ConfigPinning::from_path("./config/sync_step.json");

    let circuit = SyncStepCircuit::<Minimal, bn256::Fr>::create_circuit(
        CircuitBuilderStage::Mock,
        Some(pinning),
        &params,
        &witness,
    )
    .unwrap();

    let timer = start_timer!(|| "sync_step mock prover");
    let prover = MockProver::<bn256::Fr>::run(K, &circuit, circuit.instances()).unwrap();
    prover.assert_satisfied_par();
    end_timer!(timer);
}

#[rstest]
fn test_step_proofgen(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) {
    const K: u32 = 20;
    let witness = read_test_files_and_gen_witness(path);

    let params = gen_srs(K);
    let pk = SyncStepCircuit::<Minimal, bn256::Fr>::read_or_create_pk(
        &params,
        "../build/sync_step.pkey",
        "./config/sync_step.json",
        false,
        &SyncStepArgs::<Minimal>::default(),
    );

    let pinning = Eth2ConfigPinning::from_path("./config/sync_step.json");

    let circuit = SyncStepCircuit::<Minimal, bn256::Fr>::create_circuit(
        CircuitBuilderStage::Prover,
        Some(pinning),
        &params,
        &witness,
    )
    .unwrap();

    let instances = circuit.instances();
    let proof = full_prover(&params, &pk, circuit, instances.clone());

    assert!(full_verifier(&params, pk.get_vk(), proof, instances))
}
#[rstest]
fn test_step_evm_verify(
    #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
    #[exclude("deneb*")]
    path: PathBuf,
) {
    const K: u32 = 21;
    let params = gen_srs(K);

    let pk = SyncStepCircuit::<Minimal, bn256::Fr>::read_or_create_pk(
        &params,
        "../build/sync_step.pkey",
        "./config/sync_step.json",
        false,
        &SyncStepArgs::<Minimal>::default(),
    );

    let witness = read_test_files_and_gen_witness(path);

    let pinning = Eth2ConfigPinning::from_path("./config/sync_step.json");

    let circuit = SyncStepCircuit::<Minimal, bn256::Fr>::create_circuit(
        CircuitBuilderStage::Prover,
        Some(pinning),
        &params,
        &witness,
    )
    .unwrap();

    let instances = circuit.instances();
    let proof =
        snark_verifier_sdk::evm::gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());
    println!("proof size: {}", proof.len());
    let deployment_code = SyncStepCircuit::<Minimal, bn256::Fr>::gen_evm_verifier_shplonk(
        &params,
        &pk,
        None::<String>,
        &witness,
    )
    .unwrap();
    println!("deployment_code size: {}", deployment_code.len());
    snark_verifier_sdk::evm::evm_verify(deployment_code, instances, proof);
}

mod solidity_tests {
    use super::*;
    use std::sync::Arc;
    use ethers::{
        contract::abigen,
        core::utils::{Anvil, AnvilInstance},
        middleware::SignerMiddleware,
        providers::{Http, Provider},
        signers::{LocalWallet, Signer},
    };
    use lightclient_circuits::poseidon::g1_array_poseidon_native;
    use halo2_base::safe_types::ScalarField;
    use halo2curves::group::UncompressedEncoding;

    /// Ensure that the instance encoding implemented in Solidity matches exactly the instance encoding expected by the circuit
    #[rstest]
    #[tokio::test]
    async fn test_instance_commitment_evm_equivalence(
        #[files("../consensus-spec-tests/tests/minimal/capella/light_client/sync/pyspec_tests/**")]
        #[exclude("deneb*")]
        path: PathBuf,
    ) -> anyhow::Result<()> {
        let witness = read_test_files_and_gen_witness(path);
        let instance = SyncStepCircuit::<Minimal, bn256::Fr>::instance(witness.clone());
        let poseidon_commitment_le = extract_poseidon_committee_commitment(&witness)?;

        let anvil_instance = Anvil::new().spawn();
        let ethclient: Arc<SignerMiddleware<Provider<Http>, _>> = make_client(&anvil_instance);
        let contract = SyncStepExternal::deploy(ethclient, ())?.send().await?;

        let result = contract.to_input_commitment(SyncStepInput::from(witness), poseidon_commitment_le).call().await?;
        let mut result_bytes = [0_u8;32];
        result.to_little_endian(&mut result_bytes);

        assert_eq!(bn256::Fr::from_bytes(&result_bytes).unwrap(), instance);
        Ok(())
    }

    abigen!(SyncStepExternal, "../contracts/out/SyncStepExternal.sol/SyncStepExternal.json");

    // SyncStepInput type produced by abigen macro matches the solidity struct type
    impl<Spec: eth_types::Spec> From<SyncStepArgs<Spec>> for SyncStepInput {
        fn from(args: SyncStepArgs<Spec>) -> Self {
            let participation = args
                .pariticipation_bits
                .iter()
                .map(|v| *v as u64)
                .sum::<u64>();

            let finalized_header_root: [u8; 32] = args
                .finalized_header
                .clone()
                .hash_tree_root()
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap();

            let execution_payload_root: [u8; 32] = args
                .execution_payload_root
                .try_into()
                .unwrap();

            SyncStepInput {
                attested_slot: args.attested_header.slot,
                finalized_slot: args.finalized_header.slot,
                participation: participation,
                finalized_header_root,
                execution_payload_root,
            }
        }
    }

    fn extract_poseidon_committee_commitment<Spec: eth_types::Spec>(witness: &SyncStepArgs<Spec>) -> anyhow::Result<[u8; 32]> {
        let pubkey_affines = witness
        .pubkeys_uncompressed
        .iter()
        .cloned()
        .map(|bytes| {
            halo2curves::bls12_381::G1Affine::from_uncompressed_unchecked(&bytes.as_slice().try_into().unwrap())
                .unwrap()
        })
        .collect_vec();
        let poseidon_commitment = g1_array_poseidon_native::<bn256::Fr>(&pubkey_affines)?;
        Ok(poseidon_commitment.to_bytes_le().try_into().unwrap())
    }

    /// Return a fresh ethereum chain+client to test against
    fn make_client(anvil: &AnvilInstance) -> Arc<SignerMiddleware<Provider<Http>, LocalWallet>> {
        let provider =
            Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(std::time::Duration::from_millis(10u64));
        let wallet: LocalWallet = anvil.keys()[0].clone().into();

        let client: SignerMiddleware<Provider<Http>, _> = SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id()));
        Arc::new(client)
    }
}
