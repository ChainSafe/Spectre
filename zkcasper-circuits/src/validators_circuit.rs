pub(crate) mod cell_manager;
pub(crate) mod constraint_builder;

use crate::{
    gadget::math::LtGadget,
    table::{
        state_table::{StateTables, StateTreeLevel},
        LookupTable, ValidatorsTable,
    },
    util::{Challenges, ConstrainBuilderCommon, SubCircuit, SubCircuitConfig},
    witness::{self, pad_to_max_per_committee, Validator},
    N_BYTES_U64,
};
use cell_manager::CellManager;
use constraint_builder::*;
use eth_types::*;

use gadgets::util::{and, not, select, Expr};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, FirstPhase, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use std::{iter, marker::PhantomData};

pub(crate) const N_BYTE_LOOKUPS: usize = 16; // 8 per lt gadget (target_gte_activation, target_lt_exit)
pub(crate) const MAX_DEGREE: usize = 5;

#[derive(Clone, Debug)]
pub struct ValidatorsCircuitConfig<F: Field> {
    max_rows: usize,
    q_enabled: Column<Fixed>,
    q_first: Column<Fixed>,
    q_last: Column<Fixed>,
    q_committee_first: Column<Fixed>,
    q_attest_digits: Vec<Column<Fixed>>,
    state_tables: StateTables,
    pub validators_table: ValidatorsTable,
    storage_phase1: [Column<Advice>; 2], // one per `LtGadget`
    byte_lookup: [Column<Advice>; N_BYTE_LOOKUPS],
    target_epoch: Column<Advice>, // TODO: should be an instance or assigned from instance
    cell_manager: CellManager<F>,
    // Lazy initialized
    target_gte_activation: Option<LtGadget<F, N_BYTES_U64>>,
    target_lt_exit: Option<LtGadget<F, N_BYTES_U64>>,
}

pub struct ValidatorsCircuitArgs {
    pub state_tables: StateTables,
}

impl<F: Field> SubCircuitConfig<F> for ValidatorsCircuitConfig<F> {
    type ConfigArgs = ValidatorsCircuitArgs;

    fn new<S: Spec>(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let q_enabled = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_last = meta.fixed_column();
        let q_committee_first = meta.fixed_column();
        let q_attest_digits = iter::repeat_with(|| meta.fixed_column())
            .take(S::attest_digits_len::<F>())
            .collect_vec();

        let target_epoch = meta.advice_column();
        let state_tables = args.state_tables;
        let validators_table: ValidatorsTable = ValidatorsTable::construct::<S, F>(meta);

        let storage_phase1 = array_init::array_init(|_| meta.advice_column());
        let byte_lookup = array_init::array_init(|_| meta.advice_column());

        let cm_advices = storage_phase1
            .iter()
            .copied()
            .chain(byte_lookup.iter().copied())
            .collect_vec();

        let cell_manager = CellManager::new(meta, S::VALIDATOR_REGISTRY_LIMIT, &cm_advices);

        let mut config = Self {
            max_rows: S::MAX_VALIDATORS_PER_COMMITTEE
                * S::MAX_COMMITTEES_PER_SLOT
                * S::SLOTS_PER_EPOCH,
            q_enabled,
            q_first,
            q_last,
            q_committee_first,
            q_attest_digits,
            target_epoch,
            state_tables,
            validators_table,
            storage_phase1,
            byte_lookup,
            target_gte_activation: None,
            target_lt_exit: None,
            cell_manager,
        };

        // Annotate circuit
        config.validators_table.annotate_columns(meta);
        config.annotations().iter().for_each(|(col, ann)| {
            meta.annotate_lookup_any_column(*col, || ann);
        });

        let mut lookups = Vec::new();

        meta.create_gate("validators constraints", |meta| {
            let q = queries::<S, F>(meta, &config);
            let mut cb = ConstraintBuilder::new(&mut config.cell_manager, MAX_DEGREE);

            cb.require_boolean("is_active is boolean", q.table.is_active());
            cb.require_boolean("is_attested is boolean", q.table.attest_bit());
            cb.require_boolean("slashed is boolean", q.table.slashed());

            cb.condition(q.table.attest_bit(), |cb| {
                cb.require_true(
                    "is_active is true when is_attested is true",
                    q.table.is_active(),
                );
            });

            let target_gte_activation = LtGadget::<_, N_BYTES_U64>::construct(
                &mut cb,
                q.table.activation_epoch(),
                q.next_epoch(),
            );
            let target_lt_exit = LtGadget::<_, N_BYTES_U64>::construct(
                &mut cb,
                q.target_epoch(),
                q.table.exit_epoch(),
            );

            cb.condition(q.table.is_active(), |cb| {
                cb.require_zero("slashed is false for active validators", q.table.slashed());

                cb.require_true(
                    "activation_epoch <= target_epoch > exit_epoch for active validators",
                    target_gte_activation.expr() * target_lt_exit.expr(),
                )
            });

            config.target_gte_activation = Some(target_gte_activation);
            config.target_lt_exit = Some(target_lt_exit);

            cb.add_lookup(
                "validator.balance in state table",
                config.state_tables.build_lookup(
                    meta,
                    StateTreeLevel::Validators,
                    true,
                    q.table.is_active(),
                    q.table.balance_gindex(),
                    q.table.balance(),
                ),
            );

            cb.add_lookup(
                "validator.slashed in state table",
                config.state_tables.build_lookup(
                    meta,
                    StateTreeLevel::Validators,
                    false,
                    q.table.is_active(),
                    q.table.slashed_gindex(),
                    q.table.slashed(),
                ),
            );

            cb.add_lookup(
                "validator.activation_epoch in state table",
                config.state_tables.build_lookup(
                    meta,
                    StateTreeLevel::Validators,
                    false,
                    q.table.is_active(),
                    q.table.activation_epoch_gindex(),
                    q.table.activation_epoch(),
                ),
            );

            cb.add_lookup(
                "validator.exit_epoch in state table",
                config.state_tables.build_lookup(
                    meta,
                    StateTreeLevel::Validators,
                    true,
                    q.table.is_active(),
                    q.table.exit_epoch_gindex(),
                    q.table.exit_epoch(),
                ),
            );

            cb.add_lookup(
                "validator.pubkey[0..32] in state table",
                config.state_tables.build_lookup(
                    meta,
                    StateTreeLevel::PubKeys,
                    true,
                    q.table.is_active(),
                    q.table.pubkey_lo_gindex(),
                    q.table.pubkey_lo_rlc(),
                ),
            );

            cb.add_lookup(
                "validator.pubkey[32..48] in state table",
                config.state_tables.build_lookup(
                    meta,
                    StateTreeLevel::PubKeys,
                    false,
                    q.table.is_active(),
                    q.table.pubkey_hi_gindex(),
                    q.table.pubkey_hi_rlc(),
                ),
            );

            lookups = cb.lookups();
            cb.gate(q.q_enabled())
        });

        for (name, lookup) in lookups {
            meta.lookup_any(name, |_| lookup);
        }

        meta.create_gate("balance accumulation: first row", |meta| {
            let q = queries::<S, F>(meta, &config);
            let mut cb = ConstraintBuilder::new(&mut config.cell_manager, MAX_DEGREE);
            cb.require_equal("init balance_acc", q.table.balance(), q.table.balance_acc());
            cb.gate(q.q_first())
        });

        meta.create_gate("balance accumulation", |meta| {
            let q = queries::<S, F>(meta, &config);
            let mut cb = ConstraintBuilder::new(&mut config.cell_manager, MAX_DEGREE);
            let new_balance_acc = select::expr(
                q.table.attest_bit(),
                q.table.balance_acc_prev() + q.table.balance(),
                q.table.balance_acc(),
            );
            cb.require_equal(
                "balance_acc = balance_acc_prev + balance",
                q.table.balance_acc(),
                new_balance_acc,
            );
            cb.gate(and::expr(vec![q.q_enabled(), not::expr(q.q_first())]))
        });

        meta.create_gate("attetsation digits: first committe rows", |meta| {
            let q = queries::<S, F>(meta, &config);
            let mut cb = ConstraintBuilder::new(&mut config.cell_manager, MAX_DEGREE);
            cb.require_equal(
                "attest_digit[0] = is_attested",
                q.table.attest_digit(0),
                q.table.attest_bit(),
            );
            for i in 1..S::attest_digits_len::<F>() {
                cb.require_zero("attest_digit[1..] are zero", q.table.attest_digit(i));
            }
            cb.gate(q.q_committee_first())
        });

        meta.create_gate("attetsation digits", |meta| {
            let q = queries::<S, F>(meta, &config);
            let mut cb = ConstraintBuilder::new(&mut config.cell_manager, MAX_DEGREE);

            for i in 0..S::attest_digits_len::<F>() {
                // bit = q_attest_digits[0] ? attest_bit : 0
                let bit = and::expr(vec![q.q_attest_digits(i), q.table.attest_bit()]);
                cb.require_equal(
                    "attest_digits += attest_bit",
                    q.table.attest_digit(i),
                    q.table.attest_digit_prev(i) * 2.expr() + bit,
                );
            }

            cb.gate(and::expr(vec![
                q.q_enabled(),
                not::expr(q.q_committee_first()),
            ]))
        });

        println!("validators circuit degree={}", meta.degree());

        config
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.state_tables.annotate_columns_in_region(region);
        self.annotations()
            .into_iter()
            .for_each(|(col, ann)| region.name_column(|| &ann, col));
        self.validators_table.annotate_columns_in_region(region);
    }
}

impl<F: Field> ValidatorsCircuitConfig<F> {
    fn assign<S: Spec>(
        &mut self,
        layouter: &mut impl Layouter<F>,
        validators: &[Validator],
        target_epoch: u64,
        challange: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "validators circuit",
            |mut region| {
                self.assign_with_region::<S>(&mut region, validators, target_epoch, challange)
            },
        )
    }

    fn assign_with_region<S: Spec>(
        &mut self,
        region: &mut Region<'_, F>,
        validators: &[Validator],
        target_epoch: u64,
        randomness: Value<F>,
    ) -> Result<(), Error> {
        let padded_validators = pad_to_max_per_committee::<S>(validators.iter());
        let num_committees = padded_validators.len() / S::MAX_VALIDATORS_PER_COMMITTEE;

        let target_gte_activation = self
            .target_gte_activation
            .as_ref()
            .expect("target_gte_activation gadget is expected");
        let target_lt_exit = self
            .target_lt_exit
            .as_ref()
            .expect("target_lt_exited gadget is expected");

        let mut offset = 0;
        let mut committees_balances = vec![0; num_committees];
        let mut attest_digits = vec![vec![0; S::attest_digits_len::<F>()]; num_committees];
        let vs_per_committee = S::MAX_VALIDATORS_PER_COMMITTEE;
        let f_bits = F::NUM_BITS as usize;
        let attest_digits_len = S::attest_digits_len::<F>();

        region.assign_fixed(
            || "assign q_first",
            self.q_first,
            0,
            || Value::known(F::one()),
        )?;

        for i in 0..self.max_rows {
            region.assign_fixed(
                || "assign q_enabled",
                self.q_enabled,
                offset,
                || Value::known(F::one()),
            )?;

            region.assign_fixed(
                || "assign q_committee_first",
                self.q_committee_first,
                offset,
                || Value::known(F::from((i % vs_per_committee == 0) as u64)),
            )?;

            region.assign_fixed(
                || "assign q_attest_digits",
                self.q_attest_digits[((i % vs_per_committee) / f_bits) % attest_digits_len],
                offset,
                || Value::known(F::one()),
            )?;

            if let Some(&validator) = padded_validators.get(i) {
                region.assign_advice(
                    || "assign target epoch",
                    self.target_epoch,
                    offset,
                    || Value::known(F::from(target_epoch)),
                )?; // TODO: assign from instance instead

                target_gte_activation.assign(
                    region,
                    offset,
                    F::from(validator.activation_epoch),
                    F::from(target_epoch + 1),
                )?;
                target_lt_exit.assign(
                    region,
                    offset,
                    F::from(target_epoch),
                    F::from(validator.exit_epoch),
                )?;

                let validator_rows = validator.table_assignment::<S, F>(
                    randomness,
                    &mut attest_digits,
                    &mut committees_balances,
                );
                for (i, row) in validator_rows.into_iter().enumerate() {
                    self.validators_table
                        .assign_with_region::<S, F>(region, offset + i, &row)?;
                }

                offset += 1;
            }
        }

        region.assign_fixed(
            || "assign q_last",
            self.q_last,
            self.max_rows,
            || Value::known(F::one()),
        )?;

        // annotate circuit
        self.annotate_columns_in_region(region);

        Ok(())
    }

    pub fn annotations(&self) -> Vec<(Column<Any>, String)> {
        itertools::chain!(
            vec![
                (self.q_enabled.into(), "q_enabled".to_string()),
                (self.q_first.into(), "q_first".to_string()),
                (self.q_last.into(), "q_last".to_string()),
                (
                    self.q_committee_first.into(),
                    "q_committee_first".to_string(),
                ),
                (
                    self.storage_phase1[0].into(),
                    "activation_lte_target".to_string(),
                ),
                (self.storage_phase1[1].into(), "exit_gt_target".to_string()),
                (self.target_epoch.into(), "target_epoch".to_string()),
            ],
            self.q_attest_digits
                .iter()
                .enumerate()
                .map(|(i, &col)| { (col.into(), format!("q_attest_digits_{}", i)) }),
            self.byte_lookup
                .iter()
                .enumerate()
                .map(|(i, &col)| { (col.into(), format!("byte_lookup_{}", i)) }),
        )
        .collect()
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorsCircuit<S: Spec, F> {
    pub(crate) validators: Vec<Validator>,
    target_epoch: u64,
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> ValidatorsCircuit<S, F> {
    pub fn new(validators: Vec<Validator>, target_epoch: u64) -> Self {
        Self {
            validators,
            target_epoch,
            _f: PhantomData,
            _spec: PhantomData,
        }
    }
}

impl<S: Spec, F: Field> SubCircuit<F> for ValidatorsCircuit<S, F> {
    type Config = ValidatorsCircuitConfig<F>;
    type SynthesisArgs = ();

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(block.validators.clone(), block.target_epoch)
    }

    fn unusable_rows() -> usize {
        todo!()
    }

    fn min_num_rows_block(_block: &witness::Block<F>) -> (usize, usize) {
        todo!()
    }

    /// Make the assignments to the ValidatorsCircuit
    fn synthesize_sub(
        &self,
        config: &mut Self::Config,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
        _: Self::SynthesisArgs,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "validators circuit",
            |mut region| {
                config.assign_with_region::<S>(
                    &mut region,
                    &self.validators,
                    self.target_epoch,
                    challenges.sha256_input(),
                )?;
                Ok(())
            },
        )
    }

    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
}

fn queries<S: Spec, F: Field>(
    meta: &mut VirtualCells<'_, F>,
    config: &ValidatorsCircuitConfig<F>,
) -> Queries<S, F> {
    Queries {
        q_enabled: meta.query_fixed(config.q_enabled, Rotation::cur()),
        q_first: meta.query_fixed(config.q_first, Rotation::cur()),
        q_last: meta.query_fixed(config.q_last, Rotation::cur()),
        q_committee_first: meta.query_fixed(config.q_committee_first, Rotation::cur()),
        q_attest_digits: config
            .q_attest_digits
            .iter()
            .map(|col| meta.query_fixed(*col, Rotation::cur()))
            .collect_vec(),
        target_epoch: meta.query_advice(config.target_epoch, Rotation::cur()),
        table: config.validators_table.queries(meta),
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use crate::{table::state_table::StateTables, witness::MerkleTrace};
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    use std::{fs, marker::PhantomData};

    use eth_types::Test as S;

    #[derive(Debug, Clone)]
    struct TestValidators<S: Spec, F: Field> {
        inner: ValidatorsCircuit<S, F>,
        state_tree_trace: MerkleTrace,
        _f: PhantomData<F>,
    }

    impl<S: Spec, F: Field> Circuit<F> for TestValidators<S, F> {
        type Config = (ValidatorsCircuitConfig<F>, Challenges<F>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let args = ValidatorsCircuitArgs {
                state_tables: StateTables::dev_construct(meta),
            };

            (
                ValidatorsCircuitConfig::new::<S>(meta, args),
                Challenges::construct(meta),
            )
        }

        fn synthesize(
            &self,
            mut config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = config.1.sha256_input();
            config.0.state_tables.dev_load::<S, _>(
                &mut layouter,
                &self.state_tree_trace,
                challenge,
            )?;
            self.inner.synthesize_sub(
                &mut config.0,
                &config.1.values(&mut layouter),
                &mut layouter,
                (),
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_validators_circuit() {
        let k = 10;
        let validators: Vec<Validator> =
            serde_json::from_slice(&fs::read("../test_data/validators.json").unwrap()).unwrap();
        let state_tree_trace: MerkleTrace =
            serde_json::from_slice(&fs::read("../test_data/merkle_trace.json").unwrap()).unwrap();

        let circuit = TestValidators::<Test, Fr> {
            inner: ValidatorsCircuit::new(validators, 25),
            state_tree_trace,
            _f: PhantomData,
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
