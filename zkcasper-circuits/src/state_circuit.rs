use crate::{util::ConstrainBuilderCommon, MAX_VALIDATORS, table::state_table};

pub mod cell_manager;
use cell_manager::CellManager;

pub mod constraint_builder;
use constraint_builder::ConstraintBuilder;

pub mod merkle_tree;
use merkle_tree::TreeLevel;

use crate::{
    gadget::IsEqualGadget,
    table::{sha256_table, LookupTable, SHA256Table, StateTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, MerkleTrace},
};
use eth_types::*;
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    util::{not, Expr},
};
use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed, Instance,
        SecondPhase, Selector, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use std::{
    fmt::format,
    iter,
    ops::{Add, Mul},
    vec, marker::PhantomData,
};

pub const CHUNKS_PER_VALIDATOR: usize = 8;
pub const USED_CHUNKS_PER_VALIDATOR: usize = 5;
// pub const TREE_MAX_LEAVES: usize = MAX_VALIDATORS * CHUNKS_PER_VALIDATOR;
pub const TREE_DEPTH: usize = 10; // ceil(log2(TREE_MAX_LEAVES))
pub const TREE_LEVEL_AUX_COLUMNS: usize = 1;

pub const PUBKEYS_LEVEL: usize = 10;
pub const VALIDATORS_LEVEL: usize = PUBKEYS_LEVEL - 1;

#[derive(Clone, Debug)]
pub struct StateSSZCircuitConfig<F: Field> {
    selector: Selector,
    tree: [TreeLevel<F>; TREE_DEPTH],
    sha256_table: SHA256Table,
    state_table: StateTable,
}

pub struct StateSSZCircuitArgs {
    pub sha256_table: SHA256Table,
    pub state_table: StateTable,
}

impl<F: Field> SubCircuitConfig<F> for StateSSZCircuitConfig<F> {
    type ConfigArgs = StateSSZCircuitArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let sha256_table = args.sha256_table;
        let state_table = args.state_table;

        let selector = meta.selector();
        let mut tree = vec![TreeLevel::configure(
            meta,
            PUBKEYS_LEVEL,
            0,
            3,
            true,
        )];

        let mut padding = 0;
        for i in (1..TREE_DEPTH).rev() {
            if i != VALIDATORS_LEVEL {
                padding = padding * 2 + 1;
            }
            let level =
                TreeLevel::configure(meta, i, 0, padding, i == VALIDATORS_LEVEL);
            tree.push(level);
        }

        let mut tree: [_; TREE_DEPTH] = tree.into_iter().rev().collect_vec().try_into().unwrap();

        for i in (0..TREE_DEPTH).rev() {
            let level = &tree[i];
            let next_level = &tree[i - 1];

            meta.create_gate("tree_level boolean checks", |meta| {
                let selector = meta.query_selector(selector);
                let mut cb = ConstraintBuilder::new();
                cb.require_boolean("into_left is boolean", level.into_left(meta));
                if let Some(is_left_col) = level.is_left {
                    cb.require_boolean(
                        "is_left is boolean",
                        meta.query_advice(is_left_col, Rotation::cur()),
                    );
                }
                if let Some(is_right_col) = level.is_right {
                    cb.require_boolean(
                        "is_right is boolean",
                        meta.query_advice(is_right_col, Rotation::cur()),
                    );
                }
                cb.gate(selector)
            });

            if let Some(is_left_col) = level.is_left {
                meta.lookup_any(
                    "state_table.lookup(tree_level,node, tree_level.index)",
                    |meta| {
                        let selector = meta.query_selector(selector);
                        let is_left = meta.query_advice(is_left_col, Rotation::cur());

                        // TODO: constraint (node, index) with StateTable
                        // https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/main/zkevm-circuits/src/evm_circuit/execution.rs#L815-L816
                        // state_table.build_lookup(
                        //     meta,
                        //     selector * is_left,
                        //     level.node(meta),
                        //     level.node_index(meta),
                        // )
                        vec![]
                    },
                );
            }

            if let Some(is_right_col) = level.is_right {
                meta.lookup_any(
                    "state_table.lookup(tree_level.sibling, tree_level.sibling_index",
                    |meta| {
                        let selector = meta.query_selector(selector);
                        let is_right = meta.query_advice(is_right_col, Rotation::cur());

                        // TODO: constraint (sibling, sibling_index) with StateTable
                        // state_table.build_lookup(
                        //     meta,
                        //     selector * is_right,
                        //     level.sibling(meta),
                        //     level.sibling_index(meta),
                        // )
                        vec![]
                    },
                );
            }

            meta.lookup_any(
                "hash(tree_level.node | tree_level.sibling) == next_level.node",
                |meta| {
                    let selector = meta.query_selector(selector);
                    let into_node = level.into_left(meta);
                    let node = level.node(meta);
                    let sibling = level.sibling(meta);
                    let parent = next_level.node(meta);
                    sha256_table.build_lookup(meta, selector * into_node, node, sibling, parent)
                },
            );

            meta.lookup_any("hash(tree_level.node | tree_level.sibling) == next_level.sibling@rotation(-(padding + 1))", |meta| {
                let selector = meta.query_selector(selector);
                let into_sibling: Expression<F> = not::expr(level.into_left(meta));
                let node = level.node(meta);
                let sibling = level.sibling(meta);
                let parent = next_level.sibling_at(level.padding().add(1).mul(-1), meta);
                sha256_table.build_lookup(
                    meta,
                    selector * into_sibling,
                    node,
                    sibling,
                    parent,
                )
            });
        }

        StateSSZCircuitConfig {
            selector,
            tree,
            sha256_table,
            state_table,
        }
    }

}

impl<F: Field> StateSSZCircuitConfig<F> {
    fn assign(&self,
        layouter: &mut impl Layouter<F>,
        witness: &MerkleTrace,
        challange: Value<F>
    ) -> Result<usize, Error> {
        let trace_by_depth = witness
            .into_iter()
            .group_by(|step| step.depth)
            .into_iter()
            .sorted_by_key(|(depth, steps)| depth.clone())
            .rev()
            .map(|(depth, steps)| steps.collect_vec())
            .collect_vec();

        let max_rows = trace_by_depth
            .iter()
            .map(|steps| steps.len())
            .max()
            .unwrap();

        layouter.assign_region(
            || "assign merkle trace",
            |mut region| {
            for offset in 0..max_rows {
                self.selector.enable(&mut region, offset)?;
            }

            for (level, steps) in self.tree.iter().zip(trace_by_depth.clone()) {
                level.assign_with_region(&mut region, steps, challange)?;
            }

            Ok(())
        });

        Ok(max_rows)
    }
}

/// Circuit for verify Merkle-multi proof of the SSZ Merkelized `BeaconState`
#[derive(Clone, Default, Debug)]
pub struct StateSSZCircuit<F: Field> {
    offset: usize,
    trace: MerkleTrace,
    _f: PhantomData<F>,
}

impl<F: Field> StateSSZCircuit<F> {
    pub fn new(
        offset: usize,
        trace: MerkleTrace,
    ) -> Self {
        Self {
            offset,
            trace,
            _f: PhantomData,
        }
    }

   
}

impl<F: Field> SubCircuit<F> for StateSSZCircuit<F> {
    type Config = StateSSZCircuitConfig<F>;

    fn unusable_rows() -> usize {
        todo!()
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        todo!()
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        todo!()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let num_rows = config.assign(layouter, &self.trace, challenges.sha256_input())?;

        println!("state ssz circuit rows: {}", num_rows);

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, circuit::{Value, SimpleFloorPlanner}, plonk::Circuit};
    use itertools::Itertools;
    use crate::{witness::{StateEntry, MerkleTrace}, sha256_circuit::{Sha256Circuit, Sha256CircuitConfig}};
    use std::{marker::PhantomData, fs};


    #[derive(Debug, Clone)]
    struct TestStateSSZ<F: Field> {
        state: Vec<StateEntry>,
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
            let state_table = StateTable::construct(meta);
            let sha256_table = SHA256Table::construct(meta);
    
            let config = {
                StateSSZCircuitConfig::new(
                    meta,
                    StateSSZCircuitArgs {
                        state_table,
                        sha256_table,
                    },
                )
            };
    
            (config, Challenges::construct(meta))
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = Value::known(Sha256CircuitConfig::fixed_challenge());
            let hash_inputs = self.state.iter().flat_map(|e| e.sha256_inputs()).collect_vec();
            config.0.sha256_table.dev_load(
                &mut layouter,
                &hash_inputs,
                challenge.clone(),
            )?;
            config.0.state_table.load(&mut layouter, &self.state, challenge)?;
            self.state_circuit.synthesize_sub(&config.0, &config.1.values(&mut layouter), &mut layouter)?;
            Ok(())
        }
    }

    #[test]
    fn test_state_ssz_circuit() {
        let k = 10;
        let state: Vec<StateEntry> = serde_json::from_slice(&fs::read("../test_data/validators.json").unwrap()).unwrap();
        let merkle_trace: MerkleTrace = serde_json::from_slice(&fs::read("../test_data/merkle_trace.json").unwrap()).unwrap();
        let circuit = TestStateSSZ::<Fr> {
            state,
            state_circuit: StateSSZCircuit::new(0, merkle_trace),
            _f: PhantomData,
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        let verify_result = prover.verify();
        if !verify_result.is_ok() {
            if let Some(errors) = verify_result.err() {
                for error in errors.iter() {
                    println!("{}", error);
                }
            }
            panic!();
        }
    }
}
