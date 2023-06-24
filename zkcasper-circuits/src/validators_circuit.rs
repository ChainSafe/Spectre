pub(crate) mod cell_manager;
pub(crate) mod constraint_builder;

use crate::{
    table::{LookupTable, StateTable},
    util::{Cell, Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, StateEntry, StateTag, StateRow},
    MAX_VALIDATORS, STATE_ROWS_PER_VALIDATOR, STATE_ROWS_PER_COMMITEE,
};
use cell_manager::CellManager;
use constraint_builder::*;
use eth_types::*;
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed, Instance,
        SecondPhase, Selector, VirtualCells, Any,
    },
    poly::Rotation,
};
use itertools::Itertools;
use std::{iter, marker::PhantomData};

pub(crate) const N_BYTE_LOOKUPS: usize = 8;

#[derive(Clone, Debug)]
pub struct ValidatorsCircuitConfig<F: Field> {
    q_enabled: Column<Fixed>, // TODO: use selector instead
    state_table: StateTable,
    tag: BinaryNumberConfig<StateTag, 3>,
    storage_phase1: Column<Advice>,
    byte_lookup: [Column<Advice>; N_BYTE_LOOKUPS],
    target_epoch: Column<Advice>, // TODO: should be an instance or assigned from instance
    constraint_builder: ConstraintBuilder<F>,
}

impl<F: Field> SubCircuitConfig<F> for ValidatorsCircuitConfig<F> {
    type ConfigArgs = StateTable;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let q_enabled = meta.fixed_column();
        let target_epoch = meta.advice_column();
        let state_table = args;

        let storage_phase1 = meta.advice_column_in(FirstPhase);
        let byte_lookup: [_; N_BYTE_LOOKUPS] = (0..N_BYTE_LOOKUPS)
            .map(|_| meta.advice_column_in(FirstPhase))
            .collect_vec()
            .try_into()
            .unwrap();

        let cm_advices = iter::once(storage_phase1)
            .chain(byte_lookup.iter().copied())
            .collect_vec();

        let tag: BinaryNumberConfig<StateTag, 3> =
            BinaryNumberChip::configure(meta, q_enabled, Some(state_table.tag));

        let cell_manager = CellManager::new(meta, MAX_VALIDATORS, &cm_advices);
        let mut constraint_builder = ConstraintBuilder::new(cell_manager);

        let mut config = Self {
            q_enabled,
            target_epoch,
            state_table,
            tag,
            storage_phase1,
            byte_lookup,
            constraint_builder
        };

        // Annotate circuit
        config.state_table.annotate_columns(meta);
        tag.annotate_columns(meta, "tag");
        config.annotations().iter().for_each(|(col, ann)| {
            meta.annotate_lookup_any_column(*col, || ann);
        });

        meta.create_gate("validators constraints", |meta| {
            let queries = queries(meta, &config);
            config.constraint_builder.build(&queries);
            config.constraint_builder.gate(queries.selector)
        });

        config
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        // self.state_table.annotate_columns_in_region(region);
        // self.tag.annotate_columns_in_region(region, "tag");
        self.annotations()
            .into_iter()
            .for_each(|(col, ann)| region.name_column(|| &ann, col));
    }
}

impl<F: Field> ValidatorsCircuitConfig<F> {
    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        beacon_state: &[StateEntry],
        target_epoch: u64,
        challange: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "validators circuit",
            |mut region| {
                self.assign_with_region(&mut region, beacon_state, target_epoch, challange)
            },
        );

        Ok(())
    }

    fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        beacon_state: &[StateEntry],
        target_epoch: u64,
        randomness: Value<F>,
    ) -> Result<(), Error> {
        self.annotate_columns_in_region(region);

        let tag_chip = BinaryNumberChip::construct(self.tag);

        let mut offset = 0;
        for entry in beacon_state.iter() {
            region.assign_advice(
                || "assign target epoch",
                self.target_epoch,
                offset,
                || Value::known(F::from(target_epoch)),
            )?; // TODO: assign from instance instead

            match entry {
                StateEntry::Validator { activation_epoch, exit_epoch, ..} => {
                    // enable selector for the first row of each validator
                    region.assign_fixed(
                        || "assign q_enabled",
                        self.q_enabled,
                        offset,
                        || Value::known(F::one()),
                    )?;
                    
                    self.constraint_builder.assign_with_region(region, offset, &entry, target_epoch);

                    for i in 0..STATE_ROWS_PER_VALIDATOR {
                        tag_chip.assign(region, offset + i, &StateTag::Validator)?;
                    }
                   
                    offset += STATE_ROWS_PER_VALIDATOR;
                }
                StateEntry::Committee { .. } => {
                    tag_chip.assign(region, offset, &StateTag::Committee)?;
                    self.constraint_builder.assign_with_region(region, offset, &entry, target_epoch);
                    offset += STATE_ROWS_PER_COMMITEE;
                }
            } 
            // todo cell manager assignments
        }

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

/// State Circuit for proving RwTable is valid
#[derive(Default, Clone, Debug)]
pub struct ValidatorsCircuit<F> {
    pub(crate) beacon_state: Vec<StateEntry>,
    target_epoch: u64,
    _f: PhantomData<F>,
}

impl<F: Field> ValidatorsCircuit<F> {
    /// make a new state circuit from an RwMap
    pub fn new(beacon_state: Vec<StateEntry>, target_epoch: u64) -> Self {
        Self {
            beacon_state,
            target_epoch,
            _f: PhantomData,
        }
    }
}

impl<F: Field> SubCircuit<F> for ValidatorsCircuit<F> {
    type Config = ValidatorsCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(block.beacon_state.clone(), block.target_epoch)
    }

    fn unusable_rows() -> usize {
       todo!()
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        todo!()
    }

    /// Make the assignments to the ValidatorsCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "validators circuit",
            |mut region| {
                config.assign_with_region(&mut region, &self.beacon_state, self.target_epoch, challenges.sha256_input())
            }
        );

        Ok(())
    }

    /// powers of randomness for instance columns
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
}


fn queries<F: Field>(meta: &mut VirtualCells<'_, F>, c: &ValidatorsCircuitConfig<F>) -> Queries<F> {
    Queries {
        selector: meta.query_fixed(c.q_enabled, Rotation::cur()),
        target_epoch: meta.query_advice(c.target_epoch, Rotation::cur()),
        state_table: StateQueries {
            id: meta.query_advice(c.state_table.id, Rotation::cur()),
            order: meta.query_advice(c.state_table.id, Rotation::cur()),
            tag: meta.query_advice(c.state_table.tag, Rotation::cur()),
            is_active: meta.query_advice(c.state_table.is_active, Rotation::cur()),
            is_attested: meta.query_advice(c.state_table.is_attested, Rotation::cur()),
            field_tag: meta.query_advice(c.state_table.field_tag, Rotation::cur()),
            index: meta.query_advice(c.state_table.index, Rotation::cur()),
            g_index: meta.query_advice(c.state_table.gindex, Rotation::cur()),
            value: meta.query_advice(c.state_table.value, Rotation::cur()),
            // vitual queries for tag == 'validator'
            balance: meta.query_advice(c.state_table.value, Rotation::cur()),
            slashed: meta.query_advice(c.state_table.value, Rotation::next()),
            activation_epoch: meta.query_advice(c.state_table.value, Rotation(2)),
            exit_epoch: meta.query_advice(c.state_table.value, Rotation(3)),
            pubkey_lo: meta.query_advice(c.state_table.value, Rotation(4)),
            pubkey_hi: meta.query_advice(c.state_table.value, Rotation(5)),
        },
        tag_bits: c
            .tag
            .bits
            .map(|bit| meta.query_advice(bit, Rotation::cur())),
    }
}



mod tests {
    use super::*;
    use crate::{
        witness::{MerkleTrace, StateEntry},
    };
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::Circuit,
    };
    use itertools::Itertools;
    use std::{fs, marker::PhantomData, vec};

    #[derive(Debug, Clone)]
    struct TestValidators<F: Field> {
        validators_circuit: ValidatorsCircuit<F>,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestValidators<F> {
        type Config = (ValidatorsCircuitConfig<F>, Challenges<F>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let state_table = StateTable::construct(meta);
            (
                ValidatorsCircuitConfig::new(meta, state_table),
                Challenges::construct(meta)
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = config.1.sha256_input();
            config
                .0
                .state_table
                .load(&mut layouter, &self.validators_circuit.beacon_state, challenge)?;
            self.validators_circuit.synthesize_sub(
                &config.0,
                &config.1.values(&mut layouter),
                &mut layouter,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_validators_circuit() {
        let k = 10;
        let state: Vec<StateEntry> =
            serde_json::from_slice(&fs::read("../test_data/validators.json").unwrap()).unwrap();
    
        let circuit = TestValidators::<Fr> {
            validators_circuit: ValidatorsCircuit::new(state, 25),
            _f: PhantomData,
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
