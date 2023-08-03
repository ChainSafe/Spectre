use std::{cell::RefCell, collections::HashMap, marker::PhantomData, ops::Neg, rc::Rc, vec};

use crate::{
    gadget::crypto::{
        CachedHashChip, Fp2Chip, Fp2Point, FpPoint, G1Point, G2Chip, G2Point, HashChip,
        HashToCurveCache, HashToCurveChip, Sha256Chip,
    },
    sha256_circuit::{util::NUM_ROUNDS, Sha256CircuitConfig},
    util::{Challenges, IntoWitness, SubCircuit, SubCircuitBuilder, SubCircuitConfig},
    witness::{self, Attestation, HashInput, HashInputChunk},
};
use eth_types::{AppCurveExt, Field, Spec};
use halo2_base::{
    gates::{
        builder::{GateThreadBuilder, RangeCircuitBuilder},
        range::RangeConfig,
    },
    safe_types::RangeChip,
    utils::CurveAffineExt,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bls12_381::bls_signature,
    ecc::{bls_signature::BlsSignatureChip, EcPoint, EccChip},
    fields::{fp, fp12, vector::FieldVector, FieldChip, FieldExtConstructor},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{ConstraintSystem, Error},
};
use itertools::Itertools;
use lazy_static::__Deref;
use pasta_curves::group::{ff, GroupEncoding};
use ssz_rs::Merkleized;
use witness::AttestationData;

pub const ZERO_HASHES: [[u8; 32]; 2] = [
    [0; 32],
    [
        245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35,
        32, 217, 240, 232, 234, 152, 49, 169, 39, 89, 251, 75,
    ],
];

#[allow(type_alias_bounds)]
type FpChip<'chip, F, C: AppCurveExt> = fp::FpChip<'chip, F, C::Fp>;

#[allow(type_alias_bounds)]
type Fp12Chip<'chip, F, C: BlsCurveExt> = fp12::Fp12Chip<'chip, F, FpChip<'chip, F, C>, C::Fq12, 1>; // 9 for BN254

pub trait BlsCurveExt: AppCurveExt {
    type Fq12: ff::Field + FieldExtConstructor<Self::Fp, 12>;

    fn new_signature_chip<'chip, F: Field>(
        fp_chip: &'chip fp::FpChip<'chip, F, Self::Fp>,
    ) -> impl BlsSignatureChip<'chip, F> + 'chip;
}

#[derive(Clone, Debug)]
pub struct AttestationsCircuitConfig<F: Field> {
    range: RangeConfig<F>,
    sha256_config: Sha256CircuitConfig<F>,
}

pub struct AttestationsCircuitArgs<F: Field> {
    pub range: RangeConfig<F>,
    pub sha256_config: Sha256CircuitConfig<F>,
}

impl<F: Field> SubCircuitConfig<F> for AttestationsCircuitConfig<F> {
    type ConfigArgs = AttestationsCircuitArgs<F>;

    fn new<S: Spec>(_meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let range = args.range;
        let sha256_config = args.sha256_config;
        Self {
            range,
            sha256_config,
        }
    }

    fn annotate_columns_in_region(&self, _region: &mut Region<'_, F>) {}
}

#[allow(type_alias_bounds)]
#[derive(Clone, Debug)]
pub struct AttestationsCircuitBuilder<'a, S: Spec, F: Field>
where
    [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
{
    builder: RefCell<GateThreadBuilder<F>>,
    attestations: &'a [Attestation<S>],
    sha256_offset: usize,
    agg_pubkeys: Option<Vec<<S::PubKeysCurve as AppCurveExt>::Affine>>,
    dry_run: bool,
    _spec: PhantomData<S>,
}

impl<'a, S: Spec, F: Field> SubCircuitBuilder<'a, S, F> for AttestationsCircuitBuilder<'a, S, F>
where
    S::SiganturesCurve: BlsCurveExt,
    <S::SiganturesCurve as AppCurveExt>::Fq:
        FieldExtConstructor<<S::SiganturesCurve as AppCurveExt>::Fp, 2>,
    [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
{
    type Config = AttestationsCircuitConfig<F>;
    type SynthesisArgs = Vec<G1Point<F>>;
    type Output = ();

    fn new_from_state(
        builder: Rc<RefCell<GateThreadBuilder<F>>>,
        state: &'a witness::State<S, F>,
    ) -> Self {
        // Self::new(
        //     builder,
        //     &state.attestations,
        //     state.sha256_inputs.len() * 144,
        // )
        todo!()
    }

    /// Assumptions:
    /// - partial attestations are aggregated into full attestations
    /// - number of attestations is less than MAX_COMMITTEES_PER_SLOT * SLOTS_PER_EPOCH
    /// - all attestation have same source and target epoch
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
        mut aggregated_pubkeys: Self::SynthesisArgs,
    ) -> Result<(), Error> {
        assert!(!self.attestations.is_empty(), "no attestations supplied");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        let range = RangeChip::default(config.range.lookup_bits());
        let fp_chip = FpChip::<F, S::SiganturesCurve>::new(
            &range,
            S::SiganturesCurve::LIMB_BITS,
            S::SiganturesCurve::NUM_LIMBS,
        );
        let fp2_chip = Fp2Chip::<F, S::SiganturesCurve>::new(&fp_chip);
        let g1_chip = EccChip::new(fp2_chip.fp_chip());
        let g2_chip = EccChip::new(&fp2_chip);
        let fp12_chip = Fp12Chip::<F, S::SiganturesCurve>::new(fp2_chip.fp_chip());
        let bls_chip = S::SiganturesCurve::new_signature_chip(fp2_chip.fp_chip());
        let sha256_chip = Sha256Chip::new(
            &config.sha256_config,
            &range,
            challenges.sha256_input(),
            None,
            self.sha256_offset,
        );
        let hasher = CachedHashChip::new(&sha256_chip);
        let h2c_chip = HashToCurveChip::<S, F, _>::new(&sha256_chip);

        let builder_clone = RefCell::from(self.builder.borrow().deref().clone());
        let mut builder = if self.dry_run {
            self.builder.borrow_mut()
        } else {
            builder_clone.borrow_mut()
        };

        layouter.assign_region(
            || "AggregationCircuitBuilder generated circuit",
            |mut region| {
                config.annotate_columns_in_region(&mut region);
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let ctx = builder.main(0);

                // assign pubkeys if in test
                aggregated_pubkeys =
                    self.agg_pubkeys
                        .clone()
                        .map_or(aggregated_pubkeys.clone(), |apks| {
                            apks.iter()
                                .map(|apk| {
                                    g1_chip.load_private_unchecked(ctx, apk.into_coordinates())
                                })
                                .collect_vec()
                        });

                let [source_root, target_root] = [
                    self.attestations[0].data.source.clone(),
                    self.attestations[0].data.target.clone(),
                ]
                .map(|cp| {
                    hasher
                        .digest::<64>(
                            (cp.epoch, cp.root.as_ref()).into_witness(),
                            ctx,
                            &mut region,
                        )
                        .unwrap()
                });

                let fp12_one = {
                    use ff::Field;
                    fp12_chip.load_constant(ctx, <S::SiganturesCurve as BlsCurveExt>::Fq12::one())
                };
                let mut h2c_cache = HashToCurveCache::<F>::default();
                let g1_neg = g1_chip.load_private_unchecked(
                    ctx,
                    S::PubKeysCurve::generator_affine().neg().into_coordinates(),
                );

                for Attestation::<S> {
                    data, signature, ..
                } in self
                    .attestations
                    .iter()
                    .take(S::MAX_COMMITTEES_PER_SLOT * S::SLOTS_PER_EPOCH)
                {
                    assert!(!signature.is_infinity());

                    let pubkey = aggregated_pubkeys
                        .get(data.index)
                        .expect("pubkey not found")
                        .clone();

                    let signature = Self::assign_signature(signature, &g2_chip, ctx);

                    let chunks = [
                        data.slot.into_witness(),
                        data.index.into_witness(),
                        data.beacon_block_root.as_ref().into_witness(),
                        source_root.output_bytes.into(),
                        target_root.output_bytes.into(),
                    ];

                    let signing_root = self.merkleize_chunks(chunks, &hasher, ctx, &mut region)?;

                    let msghash = h2c_chip.hash_to_curve::<S::SiganturesCurve>(
                        signing_root.into(),
                        &fp_chip,
                        ctx,
                        &mut region,
                        &mut h2c_cache,
                    )?;

                    let res =
                        bls_chip.verify_pairing(signature, msghash, pubkey, g1_neg.clone(), ctx);
                    // fp12_chip.assert_equal(ctx, res, fp12_one.clone());
                }

                let extra_assignments = hasher.take_extra_assignments();

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

                // TODO: constaint source_root, target_root with instances: `layouter.constrain_instance`
                Ok(())
            },
        )
    }

    fn unusable_rows() -> usize {
        todo!()
    }

    fn min_num_rows_state(_block: &witness::State<S, F>) -> (usize, usize) {
        todo!()
    }
}

impl<'a, S: Spec, F: Field> AttestationsCircuitBuilder<'a, S, F>
where
    S::SiganturesCurve: BlsCurveExt,
    <S::SiganturesCurve as AppCurveExt>::Fq:
        FieldExtConstructor<<S::SiganturesCurve as AppCurveExt>::Fp, 2>,
    [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
{
    pub fn new(
        builder: RefCell<GateThreadBuilder<F>>,
        attestations: &'a [Attestation<S>],
        sha256_offset: usize,
        agg_pubkeys: Option<Vec<<S::PubKeysCurve as AppCurveExt>::Affine>>,
    ) -> Self {
        assert_eq!(sha256_offset % (NUM_ROUNDS + 8), 0, "invalid sha256 offset");
        Self {
            builder,
            attestations,
            sha256_offset,
            agg_pubkeys,
            dry_run: false,
            _spec: PhantomData,
        }
    }

    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    fn assign_signature(
        bytes_compressed: &[u8],
        g2_chip: &G2Chip<F, S::SiganturesCurve>,
        ctx: &mut Context<F>,
    ) -> EcPoint<F, Fp2Point<F>> {
        let sig_affine = <S::SiganturesCurve as AppCurveExt>::Affine::from_bytes(
            &bytes_compressed.to_vec().try_into().unwrap(),
        )
        .unwrap();

        g2_chip.load_private_unchecked(ctx, sig_affine.into_coordinates())
    }

    fn merkleize_chunks<I: IntoIterator<Item = HashInputChunk<QuantumCell<F>>>>(
        &self,
        chunks: I,
        hasher: &'a CachedHashChip<F, Sha256Chip<'a, F>>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
    ) -> Result<Vec<AssignedValue<F>>, Error>
    where
        I::IntoIter: ExactSizeIterator,
    {
        let mut chunks = chunks.into_iter().collect_vec();
        let len_even = chunks.len() + chunks.len() % 2;
        let height = (len_even as f64).log2().ceil() as usize;

        for depth in 0..height {
            // Pad to even length using 32 zero bytes assigned as constants.
            let len_even = chunks.len() + chunks.len() % 2;
            let padded_chunks = chunks
                .into_iter()
                .pad_using(len_even, |_| {
                    HashInputChunk::from(
                        ZERO_HASHES[depth].map(|b| ctx.load_constant(F::from(b as u64))),
                    )
                })
                .collect_vec();

            chunks = padded_chunks
                .into_iter()
                .tuples()
                .map(|(left, right)| {
                    hasher
                        .digest::<64>(HashInput::TwoToOne(left, right), ctx, region)
                        .map(|res| res.output_bytes.into())
                })
                .collect::<Result<Vec<_>, _>>()?;
        }

        assert_eq!(chunks.len(), 1, "merkleize_chunks: expected one chunk");

        let root = chunks.pop().unwrap().map(|cell| match cell {
            QuantumCell::Existing(av) => av,
            _ => unreachable!(),
        });

        Ok(root.bytes)
    }
}

mod bls12_381 {
    use std::ops::Neg;

    use super::*;
    use halo2_ecc::bls12_381::{
        bls_signature::BlsSignatureChip as Bls12SignatureChip, pairing::PairingChip, FpChip,
    };
    use halo2curves::{
        bls12_381::{pairing, Fq12, G1Affine, G2Affine, G2Prepared, G2},
        pairing::MillerLoopResult,
    };
    use num_bigint::BigUint;
    use pasta_curves::group::cofactor::CofactorCurveAffine;

    impl BlsCurveExt for G2 {
        type Fq12 = Fq12;

        fn new_signature_chip<'chip, F: Field>(
            fp_chip: &'chip FpChip<'chip, F>,
        ) -> impl BlsSignatureChip<'chip, F> {
            let pairing_chip = PairingChip::new(fp_chip);
            Bls12SignatureChip::new(fp_chip, pairing_chip)
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
        root_circuit::SnarkAggregationCircuit,
        table::Sha256Table,
        util::{full_prover, full_verifier, generate_setup_artifacts},
        witness::Validator,
    };

    use super::*;
    use ark_std::{end_timer, start_timer};
    use eth_types::Test;
    use ethereum_consensus::builder;
    use halo2_base::gates::{
        builder::{CircuitBuilderStage, FlexGateConfigParams},
        flex_gate::GateStrategy,
        range::RangeStrategy,
    };
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{keygen_pk, keygen_vk, Circuit, FloorPlanner},
        poly::kzg::commitment::ParamsKZG,
    };
    use halo2curves::{bls12_381::G1Affine, bn256::Bn256};
    use pasta_curves::group::UncompressedEncoding;
    use rand::rngs::OsRng;
    use snark_verifier_sdk::{halo2::gen_snark_shplonk, CircuitExt};

    #[derive(Clone, Debug)]
    struct TestCircuit<'a, S: Spec, F: Field>
    where
        [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
    {
        inner: AttestationsCircuitBuilder<'a, S, F>,
    }

    impl<'a, S: Spec, F: Field> Circuit<F> for TestCircuit<'a, S, F>
    where
        S::SiganturesCurve: BlsCurveExt,
        <S::SiganturesCurve as AppCurveExt>::Fq:
            FieldExtConstructor<<S::SiganturesCurve as AppCurveExt>::Fp, 2>,
        [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
    {
        type Config = (AttestationsCircuitConfig<F>, Challenges<Value<F>>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let range = RangeCircuitBuilder::configure(meta);
            let hash_table = Sha256Table::construct(meta);
            let sha256_config = Sha256CircuitConfig::new::<Test>(meta, hash_table);
            let config = AttestationsCircuitConfig::new::<Test>(
                meta,
                AttestationsCircuitArgs {
                    range,
                    sha256_config,
                },
            );

            (
                config,
                Challenges::mock(Value::known(Sha256CircuitConfig::fixed_challenge())),
            )
        }

        fn synthesize(
            &self,
            mut config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config
                .0
                .range
                .load_lookup_table(&mut layouter)
                .expect("load range lookup table");
            self.inner
                .synthesize_sub(&config.0, &config.1, &mut layouter, vec![])?;
            Ok(())
        }
    }

    impl<'a, S: Spec, F: Field> CircuitExt<F> for TestCircuit<'a, S, F>
    where
        S::SiganturesCurve: BlsCurveExt,
        <S::SiganturesCurve as AppCurveExt>::Fq:
            FieldExtConstructor<<S::SiganturesCurve as AppCurveExt>::Fp, 2>,
        [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
    {
        fn num_instance(&self) -> Vec<usize> {
            self.inner.instance().iter().map(|v| v.len()).collect()
        }

        fn instances(&self) -> Vec<Vec<F>> {
            self.inner.instance()
        }
    }

    impl<'a, S: Spec, F: Field> TestCircuit<'a, S, F>
    where
        [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
    {
        const NUM_ADVICE: &[usize] = &[80];
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 15;
        const LOOKUP_BITS: usize = 16;
    }

    #[test]
    fn test_attestations_circuit() {
        let builder = GateThreadBuilder::new(false);
        let attestations: Vec<Attestation<Test>> =
            serde_json::from_slice(&fs::read("../test_data/attestations.json").unwrap()).unwrap();

        let bytes_pubkeys: Vec<Vec<u8>> =
            serde_json::from_slice(&fs::read("../test_data/aggregated_pubkeys.json").unwrap())
                .unwrap();

        let agg_pubkeys = bytes_pubkeys
            .iter()
            .map(|b| G1Affine::from_uncompressed(&b.as_slice().try_into().unwrap()).unwrap())
            .collect_vec();

        let mock_k = 17;
        let k = 17;
        {
            let mock_params = FlexGateConfigParams {
                strategy: GateStrategy::Vertical,
                k: mock_k,
                num_advice_per_phase: vec![80],
                num_lookup_advice_per_phase: vec![15],
                num_fixed: 1,
            };

            set_var(
                "FLEX_GATE_CONFIG_PARAMS",
                serde_json::to_string(&mock_params).unwrap(),
            );
            std::env::set_var("LOOKUP_BITS", 16.to_string());
            let circuit = TestCircuit::<'_, Test, Fr> {
                inner: AttestationsCircuitBuilder::new(
                    RefCell::from(builder.clone()),
                    &attestations,
                    0,
                    Some(agg_pubkeys.clone()),
                )
                .dry_run(),
            };

            let _ = MockProver::<Fr>::run(mock_k as u32, &circuit, vec![]);
            circuit.inner.builder.borrow().config(k, Some(2520));
            std::env::set_var("LOOKUP_BITS", 16.to_string());
            let pp: FlexGateConfigParams =
                serde_json::from_str(&var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
            println!("params: {:?}", pp);
        }
        let builder = RefCell::from(builder);
        let circuit = TestCircuit::<'_, Test, Fr> {
            inner: AttestationsCircuitBuilder::new(
                builder,
                &attestations,
                0,
                Some(agg_pubkeys.clone()),
            ),
        };

        let timer = start_timer!(|| "test_attestations_circuit");
        let prover = MockProver::<Fr>::run(k as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        end_timer!(timer);
    }

    #[test]
    fn test_snark_aggregation() {
        let k = 17;

        let builder = GateThreadBuilder::new(false);
        let attestations: Vec<Attestation<Test>> =
            serde_json::from_slice(&fs::read("../test_data/attestations.json").unwrap()).unwrap();
        let attestations: [Attestation<Test>; 2] = attestations
            .into_iter()
            .take(2)
            .collect_vec()
            .try_into()
            .unwrap();

        let bytes_pubkeys: Vec<Vec<u8>> =
            serde_json::from_slice(&fs::read("../test_data/aggregated_pubkeys.json").unwrap())
                .unwrap();

        let agg_pubkeys = bytes_pubkeys
            .iter()
            .map(|b| G1Affine::from_uncompressed(&b.as_slice().try_into().unwrap()).unwrap())
            .collect_vec();

        let first_pubkey = agg_pubkeys.iter().take(1).cloned().collect_vec();

        let mock_k = 17;
        let k = 17;
        {
            let mock_params = FlexGateConfigParams {
                strategy: GateStrategy::Vertical,
                k: mock_k,
                num_advice_per_phase: vec![59],
                num_lookup_advice_per_phase: vec![8],
                num_fixed: 1,
            };

            set_var(
                "FLEX_GATE_CONFIG_PARAMS",
                serde_json::to_string(&mock_params).unwrap(),
            );
            std::env::set_var("LOOKUP_BITS", 16.to_string());
            let circuit = TestCircuit::<'_, Test, Fr> {
                inner: AttestationsCircuitBuilder::new(
                    RefCell::from(builder.clone()),
                    &attestations[..1],
                    0,
                    Some(first_pubkey.clone()),
                )
                .dry_run(),
            };

            let _ = MockProver::<Fr>::run(mock_k as u32, &circuit, vec![]);
            circuit.inner.builder.borrow().config(k, Some(2520));
            let pp: FlexGateConfigParams =
                serde_json::from_str(&var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
            println!("params: {:?}", pp);
        }

        let keygen_circuit = {
            let builder = RefCell::from(builder.clone());
            TestCircuit::<'_, Test, Fr> {
                inner: AttestationsCircuitBuilder::new(
                    builder,
                    &attestations[..1],
                    0,
                    Some(first_pubkey.clone()),
                ),
            }
        };

        let (params, pkey, vkey) =
            generate_setup_artifacts(k as u32, None, keygen_circuit).unwrap();

        let builder = RefCell::from(builder.clone());
        let circuit = TestCircuit::<'_, Test, Fr> {
            inner: AttestationsCircuitBuilder::new(
                builder,
                &attestations[..1],
                0,
                Some(first_pubkey.clone()),
            ),
        };
        // gen_snark_shplonk(&params, &pkey, circuit.clone(), None::<&str>);
        let proof = full_prover(&params, &pkey, circuit.clone(), vec![]);

        let is_valid = full_verifier(&params, &vkey, proof, vec![]);
        assert!(is_valid);
        // let snarks = attestations
        //     .chunks(1)
        //     .zip(agg_pubkeys.chunks(1))
        //     .map(|(atts, pk)| {
        //         let builder = RefCell::from(builder.clone());
        //         let circuit = TestCircuit::<'_, Test, Fr> {
        //             inner: AttestationsCircuitBuilder::new(
        //                 builder,
        //                 atts,
        //                 0,
        //                 Some(vec![agg_pubkeys[i].clone()]),
        //             ),
        //         };
        //         gen_snark_shplonk(&params, &pkey, circuit, None::<&str>)
        //     })
        //     .collect_vec();

        // // create aggregation circuit
        // let agg_circuit = SnarkAggregationCircuit::<3>::new(
        //     CircuitBuilderStage::Mock,
        //     &params,
        //     TestCircuit::<Test, Fr>::LOOKUP_BITS,
        //     snarks,
        // );
    }
}
