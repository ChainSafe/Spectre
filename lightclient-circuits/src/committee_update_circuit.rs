use std::{env::var, iter, marker::PhantomData, vec};

use crate::{
    builder::Eth2CircuitBuilder,
    gadget::crypto::{
        calculate_ysquared, Fp2Point, FpPoint, G1Chip, G1Point, G2Chip, G2Point, HashInstructions,
        HashToCurveCache, HashToCurveChip, Sha256ChipWide, ShaBitThreadBuilder, ShaCircuitBuilder,
    },
    poseidon::{fq_array_poseidon, fq_array_poseidon_native, poseidon_sponge},
    ssz_merkle::{ssz_merkleize_chunks, verify_merkle_proof},
    sync_step_circuit::{clear_3_bits, to_bytes_le, truncate_sha256_into_single_elem},
    util::{
        decode_into_field, gen_pkey, AppCircuit, AssignedValueCell, Challenges, Eth2ConfigPinning,
        IntoWitness, ThreadBuilderBase,
    },
    witness::{self, HashInput, HashInputChunk},
};
use eth_types::{AppCurveExt, Field, Spec};
use group::UncompressedEncoding;
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, FlexGateConfigParams, GateThreadBuilder,
            MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
        },
        flex_gate::GateStrategy,
        range::{RangeConfig, RangeStrategy},
    },
    safe_types::{GateInstructions, RangeChip, RangeInstructions},
    utils::{fs::gen_srs, CurveAffineExt, ScalarField},
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bls12_381::{bls_signature, pairing::PairingChip, Fp12Chip, Fp2Chip, FpChip},
    ecc::{bls_signature::BlsSignatureChip, EcPoint, EccChip},
    fields::{fp12, vector::FieldVector, FieldChip, FieldExtConstructor},
};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error, ProvingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use halo2curves::{
    bls12_381::{self, Fq, Fq12, G1Affine, G2Affine, G2Prepared, G1, G2},
    bn256,
};
use itertools::Itertools;
use lazy_static::__Deref;
use num_bigint::BigUint;
use pasta_curves::group::{ff, GroupEncoding};
use poseidon::PoseidonChip;
use snark_verifier_sdk::CircuitExt;
use ssz_rs::{Merkleized, Vector};
use sync_committee_primitives::consensus_types::BeaconBlockHeader;

#[allow(type_alias_bounds)]
#[derive(Clone, Debug, Default)]
pub struct CommitteeUpdateCircuit<S: Spec, F: Field> {
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> CommitteeUpdateCircuit<S, F> {
    fn synthesize(
        thread_pool: &mut ShaBitThreadBuilder<F>,
        range: &RangeChip<F>,
        args: &witness::CommitteeRotationArgs<S, F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let fp_chip = FpChip::<F>::new(range, G2::LIMB_BITS, G2::NUM_LIMBS);
        let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
        let g1_chip = EccChip::new(fp2_chip.fp_chip());

        let sha256_chip = Sha256ChipWide::new(range, args.randomness);

        let compressed_encodings = args
            .pubkeys_compressed
            .iter()
            .map(|bytes| {
                assert_eq!(bytes.len(), 48);
                thread_pool
                    .main()
                    .assign_witnesses(bytes.iter().map(|&b| F::from(b as u64)))
            })
            .collect_vec();

        // Note: This is the root of the public keys in the SyncCommittee struct
        // not the root of the SyncCommittee struct itself.
        let committee_root_ssz =
            Self::sync_committee_root_ssz(thread_pool, &sha256_chip, compressed_encodings.clone())?;

        let poseidon_commit = {
            let pubkeys_x =
                Self::decode_pubkeys_x(thread_pool.main(), &fp_chip, compressed_encodings);
            fq_array_poseidon(thread_pool.main(), range.gate(), &pubkeys_x)?
        };

        // Finalized header
        let finalized_slot_bytes: HashInputChunk<_> = args.finalized_header.slot.into_witness();
        let finalized_state_root = args
            .finalized_header
            .state_root
            .as_ref()
            .iter()
            .map(|v| thread_pool.main().load_witness(F::from(*v as u64)))
            .collect_vec();
        let finalized_header_root = ssz_merkleize_chunks(
            thread_pool,
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
            thread_pool,
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

    pub fn instance(args: &witness::CommitteeRotationArgs<S, F>) -> Vec<Vec<bn256::Fr>> {
        let pubkeys_x = args.pubkeys_compressed.iter().cloned().map(|mut bytes| {
            bytes[47] &= 0b11111000;
            bls12_381::Fq::from_bytes_le(&bytes)
        });

        let poseidon_commitment = fq_array_poseidon_native::<bn256::Fr>(pubkeys_x).unwrap();

        let mut pk_vector: Vector<Vector<u8, 48>, 512> = args
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
            .chain(ssz_root.0.map(|b| bn256::Fr::from(b as u64)))
            .collect();

        vec![instance_vec]
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
                assert_eq!(assigned_bytes.len(), G1::BYTES_COMPRESSED);
                // masked byte from compressed representation
                let masked_byte = &assigned_bytes[G1::BYTES_COMPRESSED - 1];
                // clear the flag bits from a last byte of compressed pubkey.
                // we are using [`clear_3_bits`] function which appears to be just as useful here as for public input commitment.
                let cleared_byte = clear_3_bits(ctx, range, masked_byte);
                // Use the cleared byte to construct the x coordinate
                let assigned_x_bytes_cleared = [
                    &assigned_bytes.as_slice()[..G1::BYTES_COMPRESSED - 1],
                    &[cleared_byte],
                ]
                .concat();

                decode_into_field::<F, G1>(assigned_x_bytes_cleared, &fp_chip.limb_bases, gate, ctx)
            })
            .collect()
    }

    fn sync_committee_root_ssz<ThreadBuilder: ThreadBuilderBase<F>>(
        thread_pool: &mut ThreadBuilder,
        hasher: &impl HashInstructions<F, ThreadBuilder>,
        compressed_encodings: impl IntoIterator<Item = Vec<AssignedValue<F>>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let pubkeys_hashes: Vec<HashInputChunk<QuantumCell<F>>> = compressed_encodings
            .into_iter()
            .map(|bytes| {
                let input: HashInputChunk<_> = bytes
                    .into_iter()
                    .pad_using(64, |_| thread_pool.main().load_zero())
                    .into();
                hasher
                    .digest::<64>(thread_pool, HashInput::Single(input), false)
                    .map(|r| r.output_bytes.into())
            })
            .collect::<Result<Vec<_>, _>>()?;
        ssz_merkleize_chunks(thread_pool, hasher, pubkeys_hashes)
    }
}

impl<S: Spec> AppCircuit for CommitteeUpdateCircuit<S, bn256::Fr> {
    type Pinning = Eth2ConfigPinning;
    type Witness = witness::CommitteeRotationArgs<S, bn256::Fr>;

    fn create_circuit(
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        witness: &witness::CommitteeRotationArgs<S, bn256::Fr>,
        k: u32,
    ) -> Result<impl crate::util::PinnableCircuit<bn256::Fr>, Error> {
        let mut thread_pool = ShaBitThreadBuilder::from_stage(stage);
        let range = RangeChip::<bn256::Fr>::new(RangeStrategy::Vertical, 8);

        let assigned_instances = Self::synthesize(&mut thread_pool, &range, witness)?;

        match stage {
            CircuitBuilderStage::Prover => {}
            _ => {
                thread_pool.config(
                    k as usize,
                    Some(
                        var("MINIMUM_ROWS")
                            .unwrap_or_else(|_| "0".to_string())
                            .parse()
                            .unwrap(),
                    ),
                );
            }
        }

        Ok(Eth2CircuitBuilder::from_stage(
            assigned_instances,
            thread_pool,
            pinning.map(|p| p.break_points),
            stage,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env::{set_var, var},
        fs,
        path::PathBuf,
    };

    use crate::{
        aggregation::AggregationConfigPinning,
        gadget::crypto::constant_randomness,
        util::{full_prover, full_verifier, gen_pkey, Halo2ConfigPinning, PinnableCircuit},
        witness::{CommitteeRotationArgs, SyncStepArgs},
    };

    use super::*;
    use ark_std::{end_timer, start_timer};
    use eth_types::Testnet;
    use halo2_base::{
        gates::{
            builder::{CircuitBuilderStage, FlexGateConfigParams},
            flex_gate::GateStrategy,
            range::RangeStrategy,
        },
        utils::fs::gen_srs,
    };
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{keygen_pk, keygen_vk, Circuit, FloorPlanner},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    };
    use halo2curves::{bls12_381::G1Affine, bn256::Bn256};
    use pasta_curves::group::UncompressedEncoding;
    use rand::rngs::OsRng;
    use rayon::iter::ParallelIterator;
    use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator};
    use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
    use snark_verifier_sdk::{
        gen_pk,
        halo2::{
            aggregation::{AggregationCircuit, AggregationConfigParams},
            gen_proof_shplonk, gen_snark_shplonk,
        },
        CircuitExt, Snark, SHPLONK,
    };

    fn load_circuit_args() -> CommitteeRotationArgs<Testnet, Fr> {
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
            randomness: constant_randomness(),
            _spec: PhantomData,
            finalized_header: finalized_header,
            sync_committee_branch: committee_root_branch,
        }
    }

    fn gen_application_snark(
        params: &ParamsKZG<bn256::Bn256>,
        pk: &ProvingKey<bn256::G1Affine>,
        witness: &CommitteeRotationArgs<Testnet, Fr>,
    ) -> Snark {
        CommitteeUpdateCircuit::<Testnet, Fr>::gen_snark_shplonk(
            params,
            pk,
            "./config/committee_update.json",
            None::<String>,
            witness,
        )
        .unwrap()
    }

    #[test]
    fn test_committee_update_circuit() {
        const K: u32 = 18;
        let params = gen_srs(K);

        let witness = load_circuit_args();

        let pinning = Eth2ConfigPinning::from_path("./config/committee_update.json");
        let circuit = CommitteeUpdateCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Mock,
            Some(pinning),
            &witness,
            params.k(),
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

        let pk = CommitteeUpdateCircuit::<Testnet, Fr>::read_or_create_pk(
            &params,
            "../build/committee_update.pkey",
            "./config/committee_update.json",
            false,
            &CommitteeRotationArgs::<Testnet, Fr>::default(),
        );

        let witness = load_circuit_args();

        let pinning = Eth2ConfigPinning::from_path("./config/committee_update.json");

        let circuit = CommitteeUpdateCircuit::<Testnet, Fr>::create_circuit(
            CircuitBuilderStage::Prover,
            Some(pinning),
            &witness,
            K,
        )
        .unwrap();

        let instances = circuit.instances();
        let proof = full_prover(&params, &pk, circuit, instances.clone());

        assert!(full_verifier(&params, pk.get_vk(), proof, instances))
    }

    #[test]
    fn test_circuit_aggregation_proofgen() {
        const AGG_CONFIG_PATH: &str = "./config/committee_update_aggregation.json";
        const APP_K: u32 = 20;
        let params_app = gen_srs(APP_K);

        const AGG_K: u32 = 22;
        let pk_app = CommitteeUpdateCircuit::<Testnet, Fr>::read_or_create_pk(
            &params_app,
            "../build/committee_update.pkey",
            "./config/committee_update.json",
            false,
            &CommitteeRotationArgs::<Testnet, Fr>::default(),
        );
        let witness = load_circuit_args();
        let snark = gen_application_snark(&params_app, &pk_app, &witness);

        let params = gen_srs(AGG_K);
        println!("agg_params k: {:?}", params.k());
        let lookup_bits = params.k() as usize - 1;

        let pk = AggregationCircuit::read_or_create_pk(
            &params,
            "../build/aggregation.pkey",
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

        let proof = full_prover(&params, &pk, agg_circuit, instances.clone());

        assert!(full_verifier(&params, pk.get_vk(), proof, instances));
    }

    #[test]
    fn test_circuit_aggregation_evm() {
        const AGG_CONFIG_PATH: &str = "./config/committee_update_aggregation.json";
        const APP_K: u32 = 20;
        let params_app = gen_srs(APP_K);

        const AGG_K: u32 = 23;
        let pk_app = CommitteeUpdateCircuit::<Testnet, Fr>::read_or_create_pk(
            &params_app,
            "../build/committee_update.pkey",
            "./config/committee_update.json",
            false,
            &CommitteeRotationArgs::<Testnet, Fr>::default(),
        );
        let witness = load_circuit_args();
        let snark = gen_application_snark(&params_app, &pk_app, &witness);

        let params = gen_srs(AGG_K);
        println!("agg_params k: {:?}", params.k());
        let lookup_bits = params.k() as usize - 1;

        let pk = AggregationCircuit::read_or_create_pk(
            &params,
            "../build/aggregation.pkey",
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
            Some("contractyul"),
            &vec![snark],
        )
        .unwrap();
        println!("deployment_code size: {}", deployment_code.len());
        evm_verify(deployment_code, instances, proof);
    }

    #[test]
    fn test_circuit_aggregation_evm_2() {
        const K0: u32 = 18;
        const K1: u32 = 23;
        const K2: u32 = 23;

        const APP_CONFIG_PATH: &str = "./config/committee_update.json";
        const AGG_CONFIG_PATH: &str = "./config/committee_update_aggregation_1.json";
        const AGG_FINAL_CONFIG_PATH: &str = "./config/committee_update_aggregation_2.json";

        // Layer 0 snark gen
        let l0_snark = {
            let p0 = gen_srs(K0);
            let pk_l0 = CommitteeUpdateCircuit::<Testnet, Fr>::read_or_create_pk(
                &p0,
                "../build/committee_update.pkey",
                APP_CONFIG_PATH,
                false,
                &CommitteeRotationArgs::<Testnet, Fr>::default(),
            );
            let witness = load_circuit_args();
            let snark = gen_application_snark(&p0, &pk_l0, &witness);
            println!(
                "L0 num instances: {:?}",
                snark.instances.iter().map(|i| i.len()).collect_vec()
            );
            println!("L0 snark size: {}", snark.proof.len());
            snark
        };

        // Layer 1 snark gen
        let l1_snark = {
            let p1 = gen_srs(K1);
            let mut circuit = AggregationCircuit::keygen::<SHPLONK>(&p1, vec![l0_snark.clone()]);
            circuit.expose_previous_instances(false);

            println!("L1 Keygen num_instances: {:?}", circuit.num_instance());

            let pk_l1 = gen_pk(&p1, &circuit, None);
            circuit.write_pinning(AGG_CONFIG_PATH);
            let pinning = AggregationConfigPinning::from_path(AGG_CONFIG_PATH);
            let lookup_bits = K1 as usize - 1;
            let mut circuit = AggregationCircuit::new::<SHPLONK>(
                CircuitBuilderStage::Prover,
                Some(pinning.break_points),
                lookup_bits,
                &p1,

                iter::once(l0_snark.clone()),
            );
            circuit.expose_previous_instances(false);

            println!("L1 Prover num_instances: {:?}", circuit.num_instance());
            let snark = gen_snark_shplonk(&p1, &pk_l1, circuit, None::<String>);
            println!("L1 snark size: {}", snark.proof.len());
 
            snark
        };

        let p2 = gen_srs(K2);
        // Layer 2 snark gen
        let (proof, deployment_code, instances) = {
            let mut circuit =
                AggregationCircuit::keygen::<SHPLONK>(&p2, iter::once(l1_snark.clone()));
            circuit.expose_previous_instances(true);

            let num_instances = circuit.num_instance();
            println!("L2 Keygen num_instances: {:?}", num_instances);

            let pk_l2 = gen_pk(&p2, &circuit, None);
            circuit.write_pinning(AGG_FINAL_CONFIG_PATH);
            let pinning = AggregationConfigPinning::from_path(AGG_FINAL_CONFIG_PATH);

            let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
                &p2,
                pk_l2.get_vk(),
                num_instances,
                Some(&PathBuf::from("contractyul")),
            );
            let mut circuit = AggregationCircuit::prover::<SHPLONK>(
                &p2,
                iter::once(l1_snark.clone()),
                pinning.break_points,
            );
            circuit.expose_previous_instances(true);

            let num_instances = circuit.num_instance();
            let instances = circuit.instances();
            println!("L2 Prover num_instances: {:?}", num_instances);

            let proof = gen_evm_proof_shplonk(&p2, &pk_l2, circuit, instances.clone());
            println!("L2 proof size: {}", proof.len());
            println!("L2 Deployment Code Size: {}", deployment_code.len());
            (proof, deployment_code, instances)
        };

        evm_verify(deployment_code, instances, proof);
    }
}
