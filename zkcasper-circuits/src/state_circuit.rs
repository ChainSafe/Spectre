use crate::{
    sha256_circuit::Sha256CircuitConfig,
    table::{
        state_table::{StateTable, StateTables, StateTreeLevel},
        Sha256Table,
    },
    util::ConstrainBuilderCommon,
};

pub mod cell_manager;

pub mod constraint_builder;
use constraint_builder::ConstraintBuilder;

pub mod merkle_tree;
use ethereum_consensus::configs::goerli::config;
use log::{debug, info};
use merkle_tree::TreeLevel;

use crate::{
    table::LookupTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, MerkleTrace},
};
use eth_types::*;
use gadgets::util::{not, rlc};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance},
    poly::Rotation,
};
use itertools::Itertools;
use std::{
    marker::PhantomData,
    ops::{Add, Mul},
    vec,
};

pub const TREE_LEVEL_AUX_COLUMNS: usize = 1;

#[derive(Clone, Debug)]
pub struct StateCircuitConfig<F: Field> {
    tree: Vec<TreeLevel<F>>,
    sha256_table: Sha256Table,
    pub state_tables: StateTables,
    pub state_root: [Column<Instance>; 32],
}

pub struct StateCircuitArgs<F> {
    pub sha256_table: Sha256Table,
    pub randomness: F,
}

impl<F: Field> SubCircuitConfig<F> for StateCircuitConfig<F> {
    type ConfigArgs = StateCircuitArgs<F>;

    fn new<S: Spec>(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let state_root = array_init::array_init(|_| meta.instance_column());
        let sha256_table = args.sha256_table;

        let pubkeys_level = TreeLevel::configure(meta, S::STATE_TREE_LEVEL_PUBKEYS, 0, 3, true);
        let validators_level =
            TreeLevel::configure(meta, S::STATE_TREE_LEVEL_VALIDATORS, 0, 0, true);

        let state_tables = [
            (StateTreeLevel::PubKeys, pubkeys_level.clone().into()),
            (StateTreeLevel::Validators, validators_level.clone().into()),
        ]
        .into();

        let mut tree = vec![pubkeys_level, validators_level];

        let mut padding = 0;
        for i in (2..=S::STATE_TREE_DEPTH - 2).rev() {
            if i > (S::STATE_TREE_DEPTH
                - ((S::VALIDATOR_REGISTRY_LIMIT as f64).log2().ceil() as usize + 2))
            {
                padding = padding * 2 + 1;
            } else if i < S::STATE_TREE_LEVEL_BEACON_STATE {
                padding = 0;
            }
            let level = TreeLevel::configure(meta, i, 0, padding, false);
            tree.push(level);
        }

        let tree = tree.into_iter().rev().collect_vec();

        // Annotate circuit
        sha256_table.annotate_columns(meta);

        for depth in (2..S::STATE_TREE_DEPTH).rev() {
            let depth = depth - 1;
            let level = &tree[depth];
            let next_level = &tree[depth - 1];

            meta.create_gate("tree_level boolean checks", |meta| {
                let selector = level.selector(meta);
                let mut cb = ConstraintBuilder::default();
                cb.require_boolean("into_left is boolean", level.into_left(meta));
                cb.gate(selector)
            });

            meta.lookup_any("hash(node, sibling) == next_level.node", |meta| {
                let selector = level.selector(meta);
                let into_node = level.into_left(meta);
                let node = level.node(meta);
                let sibling = level.sibling(meta);
                let parent = next_level.node(meta);
                sha256_table.build_lookup(meta, selector * into_node, node, sibling, parent)
            });

            meta.lookup_any("hash(node, sibling) = next_level.sibling", |meta| {
                let selector = level.selector(meta);
                let into_sibling: Expression<F> = not::expr(level.into_left(meta));
                let node = level.node(meta);
                let sibling = level.sibling(meta);
                let parent = if depth < S::STATE_TREE_LEVEL_BEACON_STATE {
                    next_level.sibling(meta) // FIXME: this likely won't work when leaves from beacon state fields are present
                } else {
                    next_level.sibling_at(level.padding().add(1).mul(-1), meta)
                };
                sha256_table.build_lookup(meta, selector * into_sibling, node, sibling, parent)
            });
        }

        let last_level = &tree[0];
        meta.lookup_any("state root", |meta| {
            let selector = last_level.selector(meta);
            let node = last_level.node(meta);
            let sibling = last_level.sibling(meta);
            let bytes = state_root.map(|col| meta.query_instance(col, Rotation::cur()));
            let state_root_rlc = rlc::expr(&bytes, Expression::Constant(args.randomness));
            sha256_table.build_lookup(meta, selector, node, sibling, state_root_rlc)
        });

        debug!("state circuit degree={}", meta.degree());

        StateCircuitConfig {
            tree,
            sha256_table,
            state_tables,
            state_root,
        }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.state_tables.annotate_columns_in_region(region);
        self.sha256_table.annotate_columns_in_region(region);
        for level in self.tree.iter() {
            level.annotate_columns_in_region(region);
        }
    }
}

impl<F: Field> StateCircuitConfig<F> {
    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness: &MerkleTrace,
        challenge: Value<F>,
    ) -> Result<usize, Error> {
        let trace_by_depth = witness.trace_by_levels();

        let max_rows = trace_by_depth
            .iter()
            .map(|steps| steps.len())
            .max()
            .unwrap();

        layouter.assign_region(
            || "state circuit",
            |mut region| {
                self.annotate_columns_in_region(&mut region);

                // filter out the first (root) level, state root is assigned seperately into instance column.
                let trace_by_depth = trace_by_depth
                    .clone()
                    .into_iter()
                    .filter(|e| e[0].depth != 1)
                    .collect_vec();
                for (level, steps) in self.tree.iter().zip(trace_by_depth) {
                    level.assign_with_region(&mut region, steps, challenge)?;
                }

                Ok(())
            },
        )?;

        Ok(max_rows)
    }
}

/// Circuit for verify Merkle-multi proof of the SSZ Merkelized `BeaconState`
#[derive(Clone, Debug)]
pub struct StateCircuit<'a, S: Spec, F: Field> {
    trace: &'a MerkleTrace,
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<'a, S: Spec, F: Field> StateCircuit<'a, S, F> {
    pub fn new(trace: &'a MerkleTrace) -> Self {
        Self {
            trace,
            _f: PhantomData,
            _spec: PhantomData::<S>,
        }
    }
}

impl<'a, S: Spec, F: Field> SubCircuit<'a, S, F> for StateCircuit<'a, S, F>
where
    [(); { S::MAX_VALIDATORS_PER_COMMITTEE }]:,
{
    type Config = StateCircuitConfig<F>;
    type SynthesisArgs = ();
    type Output = ();

    fn new_from_state(state: &'a witness::State<S, F>) -> Self {
        Self::new(&state.merkle_trace)
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
        _: Self::SynthesisArgs,
    ) -> Result<(), Error> {
        let num_rows = config.assign(layouter, self.trace, challenges.sha256_input())?;

        info!("state ssz circuit rows: {}", num_rows);

        Ok(())
    }

    fn instance(&self) -> Vec<Vec<F>> {
        self.trace.root().map(|b| vec![F::from(b as u64)]).to_vec()
    }

    fn unusable_rows() -> usize {
        todo!()
    }

    fn min_num_rows_state(_block: &witness::State<S, F>) -> (usize, usize) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256_circuit::Sha256CircuitConfig, witness::MerkleTrace};
    use eth_types::Test as S;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };
    use std::{fs, marker::PhantomData};

    #[derive(Debug, Clone)]
    struct TestState<'a, S: Spec, F: Field> {
        inner: StateCircuit<'a, S, F>,
        _f: PhantomData<F>,
    }

    impl<'a, S: Spec, F: Field> Circuit<F> for TestState<'a, S, F>
    where
        [(); { S::MAX_VALIDATORS_PER_COMMITTEE }]:,
    {
        type Config = (StateCircuitConfig<F>, Challenges<Value<F>>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha256_table = Sha256Table::construct(meta);

            let config = {
                StateCircuitConfig::new::<S>(
                    meta,
                    StateCircuitArgs {
                        sha256_table,
                        randomness: Sha256CircuitConfig::fixed_challenge(),
                    },
                )
            };

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
            let challenge = config.1.sha256_input();
            let hash_inputs = self.inner.trace.sha256_inputs();
            config
                .0
                .sha256_table
                .dev_load(&mut layouter, &hash_inputs, challenge)?;
            self.inner
                .synthesize_sub(&config.0, &config.1, &mut layouter, ())?;
            Ok(())
        }
    }

    #[test]
    fn test_state_circuit() {
        let k = 10;
        let merkle_trace: MerkleTrace =
            serde_json::from_slice(&fs::read("../test_data/merkle_trace.json").unwrap()).unwrap();

        let circuit = TestState::<Test, Fr> {
            inner: StateCircuit::new(&merkle_trace),
            _f: PhantomData,
        };

        let instance = circuit.inner.instance();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        prover.assert_satisfied();
    }
}
