use crate::{
    gadget::crypto::{HashInstructions, Sha256ChipWide, ShaBitGateManager, ShaCircuitBuilder},
    poseidon::{fq_array_poseidon, fq_array_poseidon_native},
    ssz_merkle::{ssz_merkleize_chunks, verify_merkle_proof},
    sync_step_circuit::clear_3_bits,
    util::{AppCircuit, CommonGateManager, Eth2ConfigPinning, IntoWitness},
    witness::{self, HashInput, HashInputChunk},
    Eth2CircuitBuilder,
};
use eth_types::{Field, Spec, LIMB_BITS, NUM_LIMBS};
use halo2_base::{
    gates::{
        circuit::CircuitBuilderStage, flex_gate::threads::CommonCircuitBuilder, RangeInstructions,
    },
    halo2_proofs::{halo2curves::bn256, plonk::Error},
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{utils::decode_into_bn, ProperCrtUint},
    bls12_381::FpChip,
    fields::FieldChip,
};
use halo2curves::bls12_381;
use itertools::Itertools;
use ssz_rs::{Merkleized, Vector};
use std::{env::var, iter, marker::PhantomData, vec};

#[allow(type_alias_bounds)]
#[derive(Clone, Debug, Default)]
pub struct CommitteeUpdateCircuit<S: Spec, F: Field> {
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> CommitteeUpdateCircuit<S, F> {
    fn synthesize(
        builder: &mut ShaCircuitBuilder<F, ShaBitGateManager<F>>,
        fp_chip: &FpChip<F>,
        args: &witness::CommitteeRotationArgs<S>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let range = fp_chip.range();

        let sha256_chip = Sha256ChipWide::new(range);

        let compressed_encodings = args
            .pubkeys_compressed
            .iter()
            .map(|bytes| {
                assert_eq!(bytes.len(), 48);
                builder
                    .main()
                    .assign_witnesses(bytes.iter().map(|&b| F::from(b as u64)))
            })
            .collect_vec();

        // Note: This is the root of the public keys in the SyncCommittee struct
        // not the root of the SyncCommittee struct itself.
        let committee_root_ssz =
            Self::sync_committee_root_ssz(builder, &sha256_chip, compressed_encodings.clone())?;

        let poseidon_commit = {
            let pubkeys_x = Self::decode_pubkeys_x(builder.main(), fp_chip, compressed_encodings);
            fq_array_poseidon(builder.main(), range.gate(), &pubkeys_x)?
        };

        // Finalized header
        let finalized_slot_bytes: HashInputChunk<_> = args.finalized_header.slot.into_witness();
        let finalized_state_root = args
            .finalized_header
            .state_root
            .as_ref()
            .iter()
            .map(|v| builder.main().load_witness(F::from(*v as u64)))
            .collect_vec();
        let finalized_header_root = ssz_merkleize_chunks(
            builder,
            &sha256_chip,
            [
                finalized_slot_bytes,
                args.finalized_header.proposer_index.into_witness(),
                args.finalized_header.parent_root.as_ref().into_witness(),
                finalized_state_root.clone().into(),
                args.finalized_header.body_root.as_ref().into_witness(),
            ],
        )?;

        // Verify that the sync committee root is in the finalized state root
        verify_merkle_proof(
            builder,
            &sha256_chip,
            args.sync_committee_branch
                .iter()
                .map(|w| w.clone().into_witness()),
            committee_root_ssz.clone().into(),
            &finalized_state_root,
            S::SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX,
        )?;

        let public_inputs = iter::once(poseidon_commit)
            .chain(committee_root_ssz)
            .chain(finalized_header_root)
            .collect();

        Ok(public_inputs)
    }

    fn decode_pubkeys_x(
        ctx: &mut Context<F>,
        fp_chip: &FpChip<'_, F>,
        compressed_encodings: impl IntoIterator<Item = Vec<AssignedValue<F>>>,
    ) -> Vec<ProperCrtUint<F>> {
        let range = fp_chip.range();
        let gate = fp_chip.gate();

        compressed_encodings
            .into_iter()
            .map(|assigned_bytes| {
                // assertion check for assigned_uncompressed vector to be equal to S::PubKeyCurve::BYTES_COMPRESSED from specification
                assert_eq!(assigned_bytes.len(), 48);
                // masked byte from compressed representation
                let masked_byte = &assigned_bytes[48 - 1];
                // clear the flag bits from a last byte of compressed pubkey.
                // we are using [`clear_3_bits`] function which appears to be just as useful here as for public input commitment.
                let cleared_byte = clear_3_bits(ctx, range, masked_byte);
                // Use the cleared byte to construct the x coordinate
                let assigned_x_bytes_cleared =
                    [&assigned_bytes.as_slice()[..48 - 1], &[cleared_byte]].concat();

                decode_into_bn::<F>(
                    ctx,
                    gate,
                    assigned_x_bytes_cleared,
                    &fp_chip.limb_bases,
                    fp_chip.limb_bits(),
                )
            })
            .collect()
    }

    fn sync_committee_root_ssz<GateManager: CommonGateManager<F>>(
        builder: &mut ShaCircuitBuilder<F, GateManager>,
        hasher: &impl HashInstructions<F, CircuitBuilder = ShaCircuitBuilder<F, GateManager>>,
        compressed_encodings: impl IntoIterator<Item = Vec<AssignedValue<F>>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let pubkeys_hashes: Vec<HashInputChunk<QuantumCell<F>>> = compressed_encodings
            .into_iter()
            .map(|bytes| {
                let input: HashInputChunk<_> = bytes
                    .into_iter()
                    .pad_using(64, |_| builder.main().load_zero())
                    .into();
                hasher
                    .digest(builder, HashInput::Single(input))
                    .map(|r| r.into_iter().collect_vec().into())
            })
            .collect::<Result<Vec<_>, _>>()?;
        ssz_merkleize_chunks(builder, hasher, pubkeys_hashes)
    }

    pub fn instance(
        args: &witness::CommitteeRotationArgs<S>,
        limb_bits: usize,
    ) -> Vec<Vec<bn256::Fr>>
    where
        [(); S::SYNC_COMMITTEE_SIZE]:,
    {
        let pubkeys_x = args.pubkeys_compressed.iter().cloned().map(|mut bytes| {
            bytes.reverse();
            bytes[47] &= 0b00011111;
            bls12_381::Fq::from_bytes_le(&bytes)
        });

        let poseidon_commitment =
            fq_array_poseidon_native::<bn256::Fr>(pubkeys_x, limb_bits).unwrap();

        let mut pk_vector: Vector<Vector<u8, 48>, { S::SYNC_COMMITTEE_SIZE }> = args
            .pubkeys_compressed
            .iter()
            .cloned()
            .map(|v| v.try_into().unwrap())
            .collect_vec()
            .try_into()
            .unwrap();

        let ssz_root = pk_vector.hash_tree_root().unwrap();

        let finalized_header_root = args.finalized_header.clone().hash_tree_root().unwrap();

        let instance_vec = iter::once(poseidon_commitment)
            .chain(ssz_root.as_ref().iter().map(|b| bn256::Fr::from(*b as u64)))
            .chain(
                finalized_header_root
                    .as_ref()
                    .iter()
                    .map(|b| bn256::Fr::from(*b as u64)),
            )
            .collect();

        vec![instance_vec]
    }
}

impl<S: Spec> AppCircuit for CommitteeUpdateCircuit<S, bn256::Fr> {
    type Pinning = Eth2ConfigPinning;
    type Witness = witness::CommitteeRotationArgs<S>;

    fn create_circuit(
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        witness: &witness::CommitteeRotationArgs<S>,
        k: u32,
    ) -> Result<impl crate::util::PinnableCircuit<bn256::Fr>, Error> {
        let mut builder = Eth2CircuitBuilder::<ShaBitGateManager<bn256::Fr>>::from_stage(stage)
            .use_k(k as usize)
            .use_instance_columns(1);
        let range = builder.range_chip(8);
        let fp_chip = FpChip::new(&range, LIMB_BITS, NUM_LIMBS);

        let assigned_instances = Self::synthesize(&mut builder, &fp_chip, witness)?;

        match stage {
            CircuitBuilderStage::Prover => {
                builder.set_instances(0, assigned_instances);
                if let Some(pinning) = pinning {
                    builder.set_params(pinning.params);
                    builder.set_break_points(pinning.break_points);
                }
            }
            _ => {
                builder.calculate_params(Some(
                    var("MINIMUM_ROWS")
                        .unwrap_or_else(|_| "0".to_string())
                        .parse()
                        .unwrap(),
                ));
            }
        }

        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        aggregation::AggregationConfigPinning, util::Halo2ConfigPinning,
        witness::CommitteeRotationArgs,
    };

    use super::*;
    use ark_std::{end_timer, start_timer};
    use eth_types::Testnet;
    use ethereum_consensus_types::BeaconBlockHeader;
    use halo2_base::{
        halo2_proofs::{
            dev::MockProver,
            halo2curves::bn256::Fr,
            plonk::ProvingKey,
            poly::{commitment::Params, kzg::commitment::ParamsKZG},
        },
        utils::fs::gen_srs,
    };
    use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk};
    use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, CircuitExt, Snark};

    fn load_circuit_args() -> CommitteeRotationArgs<Testnet> {
        #[derive(serde::Deserialize)]
        struct ArgsJson {
            finalized_header: BeaconBlockHeader,
            committee_root_branch: Vec<Vec<u8>>,
            pubkeys_compressed: Vec<Vec<u8>>,
        }

        let ArgsJson {
            pubkeys_compressed,
            committee_root_branch,
            finalized_header,
        } = serde_json::from_slice(&fs::read("../test_data/rotation_512.json").unwrap()).unwrap();

        CommitteeRotationArgs {
            pubkeys_compressed,
            _spec: PhantomData,
            finalized_header,
            sync_committee_branch: committee_root_branch,
        }
    }

    fn gen_application_snark(
        params: &ParamsKZG<bn256::Bn256>,
        pk: &ProvingKey<bn256::G1Affine>,
        witness: &CommitteeRotationArgs<Testnet>,
        pinning_path: &str,
    ) -> Snark {
        CommitteeUpdateCircuit::<Testnet, Fr>::gen_snark_shplonk(
            params,
            pk,
            pinning_path,
            None::<String>,
            witness,
        )
        .unwrap()
    }

    #[test]
    fn test_committee_update_circuit() {
        const K: u32 = 18;
        let witness = load_circuit_args();

        let circuit = CommitteeUpdateCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            None,
            &witness,
            K,
        )
        .unwrap();

        let timer = start_timer!(|| "committee_update mock prover");
        let prover = MockProver::<Fr>::run(K, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied_par();
        end_timer!(timer);
    }

    #[test]
    fn test_committee_update_proofgen() {
        const K: u32 = 18;
        let params = gen_srs(K);

        const PINNING_PATH: &str = "./config/committee_update_18.json";
        const PKEY_PATH: &str = "../build/committee_update_18.pkey";

        let pk = CommitteeUpdateCircuit::<Testnet, Fr>::read_or_create_pk(
            &params,
            PKEY_PATH,
            PINNING_PATH,
            false,
            &CommitteeRotationArgs::<Testnet>::default(),
        );

        let witness = load_circuit_args();

        let _ = CommitteeUpdateCircuit::<Testnet, Fr>::gen_proof_shplonk(
            &params,
            &pk,
            PINNING_PATH,
            &witness,
        )
        .expect("proof generation & verification should not fail");
    }

    #[test]
    fn test_committee_update_aggregation_evm() {
        const APP_K: u32 = 18;
        const APP_PK_PATH: &str = "../build/committee_update_18.pkey";
        const APP_PINNING_PATH: &str = "./config/committee_update_18.json";
        const AGG_CONFIG_PATH: &str = "./config/committee_update_verifier_25.json";
        let params_app = gen_srs(APP_K);

        const AGG_K: u32 = 25;
        let pk_app = CommitteeUpdateCircuit::<Testnet, Fr>::read_or_create_pk(
            &params_app,
            APP_PK_PATH,
            APP_PINNING_PATH,
            false,
            &CommitteeRotationArgs::<Testnet>::default(),
        );

        let witness = load_circuit_args();
        let snark = gen_application_snark(&params_app, &pk_app, &witness, APP_PINNING_PATH);

        let params = gen_srs(AGG_K);
        println!("agg_params k: {:?}", params.k());

        let pk = AggregationCircuit::read_or_create_pk(
            &params,
            "../build/committee_update_verifier_25.pkey",
            AGG_CONFIG_PATH,
            false,
            &vec![snark.clone()],
        );

        let agg_config = AggregationConfigPinning::from_path(AGG_CONFIG_PATH);

        let agg_circuit = AggregationCircuit::create_circuit(
            CircuitBuilderStage::Prover,
            Some(agg_config),
            &vec![snark.clone()],
            AGG_K,
        )
        .unwrap();

        let instances = agg_circuit.instances();
        let num_instances = agg_circuit.num_instance();

        println!("num_instances: {:?}", num_instances);
        println!("instances: {:?}", instances);

        let proof = gen_evm_proof_shplonk(&params, &pk, agg_circuit, instances.clone());
        println!("proof size: {}", proof.len());
        let deployment_code = AggregationCircuit::gen_evm_verifier_shplonk(
            &params,
            &pk,
            None::<String>,
            &vec![snark],
        )
        .unwrap();
        println!("deployment_code size: {}", deployment_code.len());
        evm_verify(deployment_code, instances, proof);
    }
}
