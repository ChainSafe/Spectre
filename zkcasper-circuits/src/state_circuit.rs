use crate::{table::state_table::StateTable, util::ConstrainBuilderCommon};

pub mod cell_manager;

pub mod constraint_builder;
use constraint_builder::ConstraintBuilder;

pub mod merkle_tree;
use log::info;

use crate::{
    table::{LookupTable, SHA256Table},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, MerkleTrace},
};
use eth_types::*;
use gadgets::util::not;
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{ConstraintSystem, Error, Expression},
};
use itertools::Itertools;
use std::{marker::PhantomData, vec};

use self::merkle_tree::LongMerkleTree;

pub const CHUNKS_PER_VALIDATOR: usize = 8;
pub const USED_CHUNKS_PER_VALIDATOR: usize = 5;
pub const TREE_DEPTH: usize = 10; // ceil(log2(TREE_MAX_LEAVES))
pub const TREE_LEVEL_AUX_COLUMNS: usize = 1;

pub const PUBKEYS_LEVEL: usize = 10;
pub const VALIDATORS_LEVEL: usize = PUBKEYS_LEVEL - 1;

#[derive(Clone, Debug)]
pub struct StateSSZCircuitConfig<F: Field> {
    tree: LongMerkleTree<F>,
    sha256_table: SHA256Table,
    pub state_table: StateTable,
}

pub struct StateSSZCircuitArgs {
    pub sha256_table: SHA256Table,
}

impl<F: Field> SubCircuitConfig<F> for StateSSZCircuitConfig<F> {
    type ConfigArgs = StateSSZCircuitArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let sha256_table = args.sha256_table;

        let tree = LongMerkleTree::configure(meta);

        // Annotate circuit
        sha256_table.annotate_columns(meta);

        // Also enforces that the node and sibling are the left and right node
        meta.lookup_any("hash(node, sibling) == parent is in sha256 table", |meta| {
            let selector = tree.enable(meta);
            let node = tree.node(meta);
            // TODO: Check if this is the left or right node using the gindex
            let sibling = tree.sibling(meta);
            let parent = tree.parent(meta);
            let root = tree.root(meta);
            sha256_table.build_lookup(
                meta,
                selector * (Expression::Negated(Box::new(root))),
                node,
                sibling,
                parent,
            )
        });

        println!("state circuit degree={}", meta.degree());

        StateSSZCircuitConfig {
            tree: tree.clone(),
            sha256_table,
            state_table: tree.clone().into(),
        }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.state_table.annotate_columns_in_region(region);
        self.sha256_table.annotate_columns_in_region(region);
        self.tree.annotate_columns_in_region(region);
    }
}

impl<F: Field> StateSSZCircuitConfig<F> {
    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness: &MerkleTrace,
        challenge: Value<F>,
    ) -> Result<(), Error> {
        let trace_by_depth = witness.trace_by_gindex();

        layouter.assign_region(
            || "state ssz circuit",
            |mut region| {
                self.annotate_columns_in_region(&mut region);
                self.tree
                    .assign_with_region(&mut region, &trace_by_depth, challenge)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

/// Circuit for verify Merkle-multi proof of the SSZ Merkelized `BeaconState`
#[derive(Clone, Default, Debug)]
pub struct StateSSZCircuit<F: Field> {
    trace: MerkleTrace,
    _f: PhantomData<F>,
}

impl<F: Field> StateSSZCircuit<F> {
    pub fn new(trace: MerkleTrace) -> Self {
        Self {
            trace,
            _f: PhantomData,
        }
    }
}

impl<F: Field> SubCircuit<F> for StateSSZCircuit<F> {
    type Config = StateSSZCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(block.merkle_trace.clone())
    }

    fn unusable_rows() -> usize {
        todo!()
    }

    fn min_num_rows_block(_block: &witness::Block<F>) -> (usize, usize) {
        todo!()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign(layouter, &self.trace, challenges.sha256_input())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::MerkleTrace;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };
    use std::{fs, marker::PhantomData};

    #[derive(Debug, Clone)]
    struct TestStateSSZ<F: Field> {
        state_circuit: StateSSZCircuit<F>,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestStateSSZ<F> {
        type Config = (StateSSZCircuitConfig<F>, Challenges<F>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha256_table = SHA256Table::construct(meta);

            let config = { StateSSZCircuitConfig::new(meta, StateSSZCircuitArgs { sha256_table }) };

            (config, Challenges::construct(meta))
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = config.1.sha256_input();
            let hash_inputs = self.state_circuit.trace.sha256_inputs();
            config
                .0
                .sha256_table
                .dev_load(&mut layouter, &hash_inputs, challenge.clone())?;
            self.state_circuit.synthesize_sub(
                &config.0,
                &config.1.values(&mut layouter),
                &mut layouter,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_state_ssz_circuit() {
        let k = 20;
        let merkle_trace: MerkleTrace =
            serde_json::from_slice(&fs::read("../test_data/merkle_trace.json").unwrap()).unwrap();
        println!("merkle trace len={}", merkle_trace.0.len());
        let circuit = TestStateSSZ::<Fr> {
            state_circuit: StateSSZCircuit::new(merkle_trace),
            _f: PhantomData,
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
