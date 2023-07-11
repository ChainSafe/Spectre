pub(crate) mod cell_manager;
pub(crate) mod constraint_builder;

use crate::{
    gadget::math::LtGadget,
    table::{
        state_table::{StateTables, StateTreeLevel},
        LookupTable, ValidatorsTable,
    },
    util::{Challenges, ConstrainBuilderCommon, SubCircuit, SubCircuitConfig},
    witness::{self, into_casper_entities, CasperEntity, Committee, Validator},
    N_BYTES_U64,
};
use cell_manager::CellManager;
use constraint_builder::*;
use eth_types::*;
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
    q_enabled: Column<Fixed>,
    state_tables: StateTables,
    pub validators_table: ValidatorsTable,
    storage_phase1: Column<Advice>,
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
        let target_epoch = meta.advice_column();
        let state_tables = args.state_tables;
        let validators_table: ValidatorsTable = ValidatorsTable::construct(meta);

        let storage_phase1 = meta.advice_column_in(FirstPhase);
        let byte_lookup: [_; N_BYTE_LOOKUPS] = (0..N_BYTE_LOOKUPS)
            .map(|_| meta.advice_column_in(FirstPhase))
            .collect_vec()
            .try_into()
            .unwrap();

        let cm_advices = iter::once(storage_phase1)
            .chain(byte_lookup.iter().copied())
            .collect_vec();

        let cell_manager = CellManager::new(meta, S::VALIDATOR_REGISTRY_LIMIT, &cm_advices);

        let mut config = Self {
            q_enabled,
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
            let mut cb = ConstraintBuilder::new(&mut config.cell_manager, MAX_DEGREE, q.selector());

            cb.require_boolean("tag in [validator/committee]", q.table.tag());
            cb.require_boolean("is_active is boolean", q.table.is_active());
            cb.require_boolean("is_attested is boolean", q.table.is_attested());
            cb.require_boolean("slashed is boolean", q.table.slashed());

            cb.condition(q.table.is_attested(), |cb| {
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
                    q.table.is_validator(),
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
                    q.table.is_validator(),
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
                    q.table.is_validator(),
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
                    q.table.is_validator(),
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
                    q.table.is_validator(),
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
                    q.table.is_validator(),
                    q.table.pubkey_hi_gindex(),
                    q.table.pubkey_hi_rlc(),
                ),
            );

            lookups = cb.lookups();
            cb.gate(q.table.is_validator())
        });

        for (name, lookup) in lookups {
            meta.lookup_any(name, |_| lookup);
        }

        meta.create_gate("committee constraints", |meta| {
            let q = queries::<S, F>(meta, &config);
            let mut cb = ConstraintBuilder::new(&mut config.cell_manager, MAX_DEGREE, q.selector());

            cb.require_boolean("tag in [validator/committee]", q.table.tag());
            cb.require_zero("is_active is 0 for committees", q.table.is_active());
            cb.require_zero("is_attested is 0 for committees", q.table.is_attested());
            cb.require_zero("slashed is 0 for committees", q.table.slashed());
            cb.require_zero("activation epoch is 0 for committees", q.table.exit_epoch());
            cb.require_zero("exit epoch is 0 for committees", q.table.exit_epoch());

            cb.gate(q.selector() * q.table.is_committee())
        });

        println!("validators circuit degree={}", meta.degree());

        config
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.state_tables.annotate_columns_in_region(region);
        self.annotations()
            .into_iter()
            .for_each(|(col, ann)| region.name_column(|| &ann, col));
    }
}

impl<F: Field> ValidatorsCircuitConfig<F> {
    fn assign(
        &mut self,
        layouter: &mut impl Layouter<F>,
        validators: &[Validator],
        committees: &[Committee],
        target_epoch: u64,
        challange: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "validators circuit",
            |mut region| {
                self.assign_with_region(
                    &mut region,
                    validators,
                    committees,
                    target_epoch,
                    challange,
                )
            },
        )
    }

    fn assign_with_region(
        &mut self,
        region: &mut Region<'_, F>,
        validators: &[Validator],
        committees: &[Committee],
        target_epoch: u64,
        randomness: Value<F>,
    ) -> Result<(), Error> {
        let casper_entities = into_casper_entities(validators.iter(), committees.iter());

        let target_gte_activation = self
            .target_gte_activation
            .as_ref()
            .expect("target_gte_activation gadget is expected");
        let target_lt_exit = self
            .target_lt_exit
            .as_ref()
            .expect("target_lt_exited gadget is expected");

        let mut offset = 0;
        for entity in casper_entities.iter() {
            region.assign_advice(
                || "assign target epoch",
                self.target_epoch,
                offset,
                || Value::known(F::from(target_epoch)),
            )?; // TODO: assign from instance instead

            // TODO: enable selector to max_rows
            region.assign_fixed(
                || "assign q_enabled",
                self.q_enabled,
                offset,
                || Value::known(F::one()),
            )?;

            match entity {
                CasperEntity::Validator(validator) => {
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

                    let validator_rows = validator.table_assignment(randomness);

                    for (i, row) in validator_rows.into_iter().enumerate() {
                        self.validators_table
                            .assign_with_region(region, offset + i, &row)?;
                    }

                    offset += 1;
                }
                CasperEntity::Committee(committee) => {
                    let committee_rows = committee.table_assignment(randomness);

                    for (i, row) in committee_rows.into_iter().enumerate() {
                        self.validators_table
                            .assign_with_region(region, offset + i, &row)?;
                    }

                    offset += 1;
                }
            }
        }

        // annotate circuit
        self.annotate_columns_in_region(region);

        Ok(())
    }

    pub fn annotations(&self) -> Vec<(Column<Any>, String)> {
        let mut annotations = vec![
            (self.q_enabled.into(), "q_enabled".to_string()),
            (self.storage_phase1.into(), "storage_phase1".to_string()),
            (self.target_epoch.into(), "epoch".to_string()),
        ];

        for (i, col) in self.byte_lookup.iter().copied().enumerate() {
            annotations.push((col.into(), format!("byte_lookup_{}", i)));
        }

        annotations
    }
}

#[derive(Default, Clone, Debug)]
pub struct ValidatorsCircuit<F> {
    pub(crate) validators: Vec<Validator>,
    pub(crate) committees: Vec<Committee>,
    target_epoch: u64,
    _f: PhantomData<F>,
}

impl<F: Field> ValidatorsCircuit<F> {
    pub fn new(validators: Vec<Validator>, committees: Vec<Committee>, target_epoch: u64) -> Self {
        Self {
            validators,
            committees,
            target_epoch,
            _f: PhantomData,
        }
    }
}

impl<F: Field> SubCircuit<F> for ValidatorsCircuit<F> {
    type Config = ValidatorsCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(
            block.validators.clone(),
            block.committees.clone(),
            block.target_epoch,
        )
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
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "validators circuit",
            |mut region| {
                config.assign_with_region(
                    &mut region,
                    &self.validators,
                    &self.committees,
                    self.target_epoch,
                    challenges.sha256_input(),
                )
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
    struct TestValidators<F: Field> {
        inner: ValidatorsCircuit<F>,
        state_tree_trace: MerkleTrace,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestValidators<F> {
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
            config
                .0
                .state_tables
                .dev_load::<S, _>(&mut layouter, &self.state_tree_trace, challenge)?;
            self.inner.synthesize_sub(
                &mut config.0,
                &config.1.values(&mut layouter),
                &mut layouter,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_validators_circuit() {
        let k = 10;
        let validators: Vec<Validator> =
            serde_json::from_slice(&fs::read("../test_data/validators.json").unwrap()).unwrap();
        let committees: Vec<Committee> =
            serde_json::from_slice(&fs::read("../test_data/committees.json").unwrap()).unwrap();
        let state_tree_trace: MerkleTrace =
            serde_json::from_slice(&fs::read("../test_data/merkle_trace.json").unwrap()).unwrap();

        let circuit = TestValidators::<Fr> {
            inner: ValidatorsCircuit::new(validators, committees, 25),
            state_tree_trace,
            _f: PhantomData,
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
