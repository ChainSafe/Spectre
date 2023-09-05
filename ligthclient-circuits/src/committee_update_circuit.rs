use std::{
    cell::{Ref, RefCell},
    collections::HashMap,
    env::{set_var, var},
    fs, iter,
    marker::PhantomData,
    ops::Neg,
    path::Path,
    rc::Rc,
    vec,
};

use crate::{
    gadget::crypto::{
        Fp2Point, FpPoint, G1Chip, G1Point, G2Chip, G2Point, HashChip, HashToCurveCache,
        HashToCurveChip, Sha256ChipWide, SpreadConfig,
    },
    poseidon::{g1_array_poseidon, poseidon_sponge},
    sha256_circuit::{util::NUM_ROUNDS, Sha256CircuitConfig},
    ssz_merkle::ssz_merkleize_chunks,
    table::Sha256Table,
    util::{
        decode_into_field, gen_pkey, AppCircuitExt, AssignedValueCell, Challenges, IntoWitness,
    },
    witness::{self, HashInput, HashInputChunk, SyncStateInput},
};
use eth_types::{AppCurveExt, Field, Spec};
use ethereum_consensus::phase0::BeaconBlockHeader;
use group::UncompressedEncoding;
use halo2_base::{
    gates::{
        builder::{FlexGateConfigParams, GateThreadBuilder, RangeCircuitBuilder},
        flex_gate::GateStrategy,
        range::RangeConfig,
    },
    safe_types::{GateInstructions, RangeChip, RangeInstructions},
    utils::{fs::gen_srs, CurveAffineExt},
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
    poly::kzg::commitment::ParamsKZG,
};
use halo2curves::{
    bls12_381::{Fq, Fq12, G1Affine, G2Affine, G2Prepared, G1, G2},
    bn256,
};
use itertools::Itertools;
use lazy_static::__Deref;
use num_bigint::BigUint;
use pasta_curves::group::{ff, GroupEncoding};
use poseidon::PoseidonChip;
use snark_verifier_sdk::CircuitExt;
use ssz_rs::Merkleized;

#[derive(Clone, Debug)]
pub struct CommitteeUpdateCircuitConfig<F: Field> {
    range: RangeConfig<F>,
    sha256_config: Sha256CircuitConfig<F>,
    challenges: Challenges<Value<F>>,
}

#[allow(type_alias_bounds)]
#[derive(Clone, Debug)]
pub struct CommitteeUpdateCircuit<S: Spec, F: Field> {
    builder: RefCell<GateThreadBuilder<F>>,
    pubkeys_compressed: Vec<Vec<u8>>,
    pubkeys_y: Vec<Fq>,
    dry_run: bool,
    sha256_offset: usize,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> CommitteeUpdateCircuit<S, F> {
    fn new_from_state(
        builder: RefCell<GateThreadBuilder<F>>,
        state: &witness::SyncState<F>,
    ) -> Self {
        let pubkeys_y = state
            .sync_committee
            .iter()
            .map(|v| {
                let g1_affine = G1Affine::from_uncompressed(
                    &v.pubkey_uncompressed.as_slice().try_into().unwrap(),
                )
                .unwrap();

                g1_affine.y
            })
            .collect_vec();
        let sha256_offset = 0;
        Self {
            builder,
            pubkeys_compressed: state
                .sync_committee
                .iter()
                .cloned()
                .map(|v| v.pubkey)
                .collect_vec(),
            pubkeys_y,
            dry_run: false,
            sha256_offset,
            _spec: PhantomData,
        }
    }

    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    fn decode_pubkeys<'a, I: IntoIterator<Item = Vec<AssignedValue<F>>>>(
        &self,
        ctx: &mut Context<F>,
        fp_chip: &FpChip<'a, F>,
        compressed_encodings: I,
    ) -> Vec<G1Point<F>> {
        let range = fp_chip.range();
        let gate = fp_chip.gate();

        let g1_chip = G1Chip::<F>::new(fp_chip);

        let mut pubkeys = vec![];

        assert_eq!(self.pubkeys_compressed.len(), S::SYNC_COMMITTEE_SIZE);

        for (assigned_bytes, y_coord) in
            itertools::multizip((compressed_encodings, self.pubkeys_y.iter()))
        {
            // assertion check for assigned_uncompressed vector to be equal to S::PubKeyCurve::BYTES_COMPRESSED from specification
            assert_eq!(assigned_bytes.len(), G1::BYTES_COMPRESSED);

            // masked byte from compressed representation
            let masked_byte = &assigned_bytes[G1::BYTES_COMPRESSED - 1];
            // clear the sign bit from masked byte
            let cleared_byte = Self::clear_flag_bits(range, masked_byte, ctx);
            // Use the cleared byte to construct the x coordinate
            let assigned_x_bytes_cleared = [
                &assigned_bytes.as_slice()[..G1::BYTES_COMPRESSED - 1],
                &[cleared_byte],
            ]
            .concat();
            let x_crt = decode_into_field::<F, G1>(
                assigned_x_bytes_cleared,
                &fp_chip.limb_bases,
                gate,
                ctx,
            );

            // Load private witness y coordinate
            let y_crt = fp_chip.load_private(ctx, *y_coord);
            // // Square y coordinate
            // let ysq = fp_chip.mul(ctx, y_crt.clone(), y_crt.clone());
            // // Calculate y^2 using the elliptic curve equation
            // let ysq_calc = Self::calculate_ysquared::<G1>(ctx, fp_chip, x_crt.clone());
            // // Constrain witness y^2 to be equal to calculated y^2
            // fp_chip.assert_equal(ctx, ysq, ysq_calc);

            pubkeys.push(EcPoint::new(x_crt, y_crt));
        }

        pubkeys
    }

    /// Clears the 3 first least significat bits used for flags from a last byte of compressed pubkey.
    /// This function emulates bitwise and on 00011111 (0x1F): `b & 0b00011111` = c
    fn clear_flag_bits(
        range: &RangeChip<F>,
        b: &AssignedValue<F>,
        ctx: &mut Context<F>,
    ) -> AssignedValue<F> {
        let gate = range.gate();
        // Shift `a` three bits to the left (equivalent to a << 3 mod 256)
        let b_shifted = gate.mul(ctx, *b, QuantumCell::Constant(F::from(8)));
        // since b_shifted can at max be 255*8=2^4 we use 16 bits for modulo division.
        let b_shifted = range.div_mod(ctx, b_shifted, BigUint::from(256u64), 16).1;

        // Shift `s` three bits to the right (equivalent to s >> 3) to zeroing the first three bits (MSB) of `a`.
        range.div_mod(ctx, b_shifted, BigUint::from(8u64), 8).0
    }

    fn sync_committee_root_ssz<'a, I: IntoIterator<Item = Vec<AssignedValue<F>>>>(
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
        hasher: &'a impl HashChip<F>,
        compressed_encodings: I,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mut pubkeys_hashes = compressed_encodings
            .into_iter()
            .map(|bytes| {
                hasher
                    .digest::<64>(
                        HashInput::Single(
                            bytes.into_iter().pad_using(64, |_| ctx.load_zero()).into(),
                        ),
                        ctx,
                        region,
                    )
                    .map(|r| r.output_bytes.into())
            })
            .collect::<Result<Vec<_>, _>>()?;
        println!("pubkeys_hashes: {:?}", pubkeys_hashes.len());
        ssz_merkleize_chunks(ctx, region, hasher, pubkeys_hashes)
    }
}

impl<S: Spec, F: Field> Circuit<F> for CommitteeUpdateCircuit<S, F> {
    type Config = CommitteeUpdateCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let range = RangeCircuitBuilder::configure(meta);
        let hash_table = Sha256Table::construct(meta);
        let sha256_config = Sha256CircuitConfig::new::<S>(meta, hash_table);
        CommitteeUpdateCircuitConfig {
            range,
            sha256_config,
            challenges: Challenges::mock(Value::known(Sha256CircuitConfig::fixed_challenge())),
        }
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config
            .range
            .load_lookup_table(&mut layouter)
            .expect("load range lookup table");

        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        let range = RangeChip::default(config.range.lookup_bits());
        let fp_chip = FpChip::<F>::new(&range, G2::LIMB_BITS, G2::NUM_LIMBS);
        let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
        let g1_chip = EccChip::new(fp2_chip.fp_chip());

        let sha256_chip = Sha256ChipWide::new(
            &config.sha256_config,
            &range,
            config.challenges.sha256_input(),
            None,
            self.sha256_offset,
        );

        let builder_clone = RefCell::from(self.builder.borrow().deref().clone());
        let mut builder = if self.dry_run {
            self.builder.borrow_mut()
        } else {
            builder_clone.borrow_mut()
        };

        layouter.assign_region(
            || "AggregationCircuitBuilder generated circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let ctx = builder.main(0);

                let compressed_encodings = self
                    .pubkeys_compressed
                    .iter()
                    .map(|bytes| ctx.assign_witnesses(bytes.iter().map(|&b| F::from(b as u64))))
                    .collect_vec();

                let root = Self::sync_committee_root_ssz(
                    ctx,
                    &mut region,
                    &sha256_chip,
                    compressed_encodings.clone(),
                )?;

                let pubkey_points = self.decode_pubkeys(ctx, &fp_chip, compressed_encodings);
                let poseidon_commit = g1_array_poseidon(ctx, range.gate(), pubkey_points)?;

                let extra_assignments = sha256_chip.take_extra_assignments();

                if self.dry_run {
                    return Ok(());
                }

                let _ = builder.assign_all(
                    &config.range.gate,
                    &config.range.lookup_advice,
                    &config.range.q_lookup,
                    &mut region,
                    extra_assignments,
                );

                Ok(())
            },
        )
    }
}

impl<S: Spec, F: Field> CircuitExt<F> for CommitteeUpdateCircuit<S, F> {
    fn num_instance(&self) -> Vec<usize> {
        self.instances().iter().map(|v| v.len()).collect()
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![]
    }
}

impl<S: Spec> AppCircuitExt<bn256::Fr> for CommitteeUpdateCircuit<S, bn256::Fr> {
    fn new_from_state(
        builder: RefCell<GateThreadBuilder<bn256::Fr>>,
        state: &witness::SyncState<bn256::Fr>,
    ) -> Self {
        let pubkeys_y = state
            .sync_committee
            .iter()
            .map(|v| {
                let g1_affine = G1Affine::from_uncompressed(
                    &v.pubkey_uncompressed.as_slice().try_into().unwrap(),
                )
                .unwrap();

                g1_affine.y
            })
            .collect_vec();

        Self {
            builder,
            pubkeys_compressed: state
                .sync_committee
                .iter()
                .cloned()
                .map(|v| v.pubkey)
                .collect_vec(),
            pubkeys_y,
            sha256_offset: 0,
            dry_run: false,
            _spec: PhantomData,
        }
    }

    fn parametrize(k: usize) -> FlexGateConfigParams {
        let circuit = CommitteeUpdateCircuit::<S, bn256::Fr>::default().dry_run();

        let mock_k = 19;
        // Due to the composite nature of Sync circuit (vanila + halo2-lib)
        // we have to perfrom dry run to determine best circuit config.
        let mock_params = FlexGateConfigParams {
            strategy: GateStrategy::Vertical,
            k: mock_k,
            num_advice_per_phase: vec![300],
            num_lookup_advice_per_phase: vec![60],
            num_fixed: 1,
        };

        set_var(
            "FLEX_GATE_CONFIG_PARAMS",
            serde_json::to_string(&mock_params).unwrap(),
        );
        std::env::set_var("LOOKUP_BITS", (mock_k - 1).to_string());

        let _ = MockProver::<bn256::Fr>::run(mock_k as u32, &circuit, vec![]);
        circuit.builder.borrow().config(k, Some(0));
        std::env::set_var("LOOKUP_BITS", (k - 1).to_string());
        let params: FlexGateConfigParams =
            serde_json::from_str(&var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
        println!("params: {:?}", params);
        params
    }

    fn setup(
        config: &FlexGateConfigParams,
        out: Option<&Path>,
    ) -> (ParamsKZG<bn256::Bn256>, ProvingKey<bn256::G1Affine>) {
        let circuit = CommitteeUpdateCircuit::<S, bn256::Fr>::default();

        set_var("LOOKUP_BITS", (config.k - 1).to_string());
        set_var(
            "FLEX_GATE_CONFIG_PARAMS",
            serde_json::to_string(&config).unwrap(),
        );

        let params = gen_srs(config.k as u32);

        let pk = gen_pkey(|| "committee_update", &params, out, circuit).unwrap();

        (params, pk)
    }
}

impl<S: Spec, F: Field> Default for CommitteeUpdateCircuit<S, F> {
    fn default() -> Self {
        let builder: GateThreadBuilder<F> = GateThreadBuilder::keygen();

        let dummy_x_bytes = iter::once(192).pad_using(48, |_| 0).rev().collect();
        let dymmy_y = Fq::from((G1::B as f64).sqrt() as u64);

        let pubkeys_y = iter::repeat(dymmy_y)
            .take(S::SYNC_COMMITTEE_SIZE)
            .collect_vec();

        Self {
            builder: RefCell::from(builder),
            pubkeys_compressed: iter::repeat(dummy_x_bytes)
                .take(S::SYNC_COMMITTEE_SIZE)
                .collect_vec(),
            pubkeys_y,
            sha256_offset: 0,
            dry_run: false,
            _spec: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env::{set_var, var},
        fs,
    };

    use crate::{
        table::Sha256Table,
        util::{full_prover, full_verifier, gen_pkey},
        witness::{SyncState, SyncStateInput, Validator},
    };

    use super::*;
    use ark_std::{end_timer, start_timer};
    use eth_types::Test;
    use ethereum_consensus::builder;
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

    fn get_circuit_with_data(k: usize) -> CommitteeUpdateCircuit<Test, Fr> {
        let builder = GateThreadBuilder::new(false);
        let state_input: SyncStateInput =
            serde_json::from_slice(&fs::read("../test_data/sync_state.json").unwrap()).unwrap();
        let state = state_input.into();

        let _ = CommitteeUpdateCircuit::<Test, Fr>::parametrize(k);

        let builder = RefCell::from(builder);
        CommitteeUpdateCircuit::new_from_state(builder, &state)
    }

    fn gen_application_snark(k: usize, params: &ParamsKZG<bn256::Bn256>) -> Snark {
        let circuit = get_circuit_with_data(k);

        let pk = gen_pk(params, &circuit, Some(Path::new(&format!("app_{}.pk", k))));
        gen_snark_shplonk(params, &pk, circuit, None::<String>)
    }

    #[test]
    fn test_committee_update_circuit() {
        let k = 18;
        let circuit = get_circuit_with_data(k);

        let timer = start_timer!(|| "committee_update circuit mock prover");
        let prover = MockProver::<Fr>::run(k as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied_par();
        end_timer!(timer);
    }

    #[test]
    fn test_committee_update_proofgen() {
        let k = 18;
        let circuit = get_circuit_with_data(k);

        let params = gen_srs(k as u32);

        let pkey = gen_pkey(|| "committee_update", &params, None, circuit.clone()).unwrap();

        let public_inputs = circuit.instances();
        let proof = full_prover(&params, &pkey, circuit, public_inputs.clone());
        let timer = start_timer!(|| "committee_update circuit full verifier");
        assert!(full_verifier(&params, pkey.get_vk(), proof, public_inputs));
        end_timer!(timer);
    }

    #[test]
    fn circuit_agg() {
        let path = "./config/committee_update_aggregation.json";
        let k = 17;
        let circuit = get_circuit_with_data(k);
        let params_app = gen_srs(k as u32);
        let snark = gen_application_snark(k, &params_app);

        let agg_config = AggregationConfigParams::from_path(path);

        let params = gen_srs(agg_config.degree);
        println!("agg_params k: {:?}", params.k());
        let lookup_bits = params.k() as usize - 1;

        let agg_circuit = AggregationCircuit::keygen::<SHPLONK>(&params, iter::once(snark.clone()));

        let start0 = start_timer!(|| "Aggregation Circuit gen vk & pk");
        let pk = gen_pk(&params, &agg_circuit, None);
        end_timer!(start0);
        let break_points = agg_circuit.break_points();
        let agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            Some(break_points.clone()),
            lookup_bits,
            &params,
            iter::once(snark),
        );

        let num_instances = agg_circuit.num_instance();
        let instances = agg_circuit.instances();
        let proof = gen_evm_proof_shplonk(&params, &pk, agg_circuit, instances.clone());
        println!("proof size: {}", proof.len());
        let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
            &params,
            pk.get_vk(),
            num_instances,
            None,
        );
        println!("deployment_code size: {}", deployment_code.len());
        evm_verify(deployment_code, instances, proof);
    }
}
