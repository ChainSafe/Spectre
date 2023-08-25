use crate::sha256_circuit::Sha256Circuit;
use crate::table::sha256_table::Sha256TableAssignedRow;
use crate::witness::MerkleTraceStep;
use crate::{
    sha256_circuit::Sha256CircuitConfig, table::Sha256Table, util::ConstrainBuilderCommon,
};

use log::{debug, info};

use crate::gadget::{not, rlc};
use crate::{
    table::LookupTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, MerkleTrace},
};
use eth_types::*;
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance},
    poly::Rotation,
};
use itertools::Itertools;
use poseidon_circuit::{hash, poseidon};
use std::collections::HashMap;
use std::{
    marker::PhantomData,
    ops::{Add, Mul},
    vec,
};

pub const TREE_LEVEL_AUX_COLUMNS: usize = 1;

#[derive(Clone, Debug)]
pub struct StateCircuitConfig<F: Field> {
    sha256_circuit: Sha256CircuitConfig<F>,
    pub state_root: [Column<Instance>; 32],
}

pub struct StateCircuitArgs<F> {
    pub sha256_circuit: Sha256CircuitConfig<F>,
    pub randomness: F,
}

impl<F: Field> SubCircuitConfig<F> for StateCircuitConfig<F> {
    type ConfigArgs = StateCircuitArgs<F>;

    fn new<S: Spec>(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let state_root = array_init::array_init(|_| meta.instance_column());
        let sha256_circuit = args.sha256_circuit;

        debug!("state circuit degree={}", meta.degree());

        StateCircuitConfig {
            sha256_circuit,
            state_root,
        }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.sha256_circuit.annotate_columns_in_region(region);
    }
}

impl<F: Field> StateCircuitConfig<F> {
    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness: &MerkleTrace,
        challenge: Value<F>,
    ) -> Result<(), Error> {
        let trace_steps = witness.sorted();

        let mut sha256_witness =
            Sha256Circuit::<F>::generate_witness(&witness.sha256_inputs(), Default::default());
        let sha256_cells = self.sha256_circuit.assign(layouter, &sha256_witness)?;

        layouter.assign_region(
            || "state circuit",
            |mut region| {
                self.annotate_columns_in_region(&mut region);

                let cells_map: HashMap<_, _> = sha256_cells
                    .iter()
                    .zip(trace_steps.iter())
                    .map(|(r, s)| (s.index, r))
                    .collect();

                // Apply equality constraints
                for ((
                    index,
                    Sha256TableAssignedRow {
                        is_enabled,
                        input_chunks,
                        input_rlc,
                        input_len,
                        hash_rlc,
                        hash_bytes,
                    },
                )) in cells_map.iter()
                {
                    if *index == 1 {
                        continue;
                    }

                    let parent_index = index / 2;
                    let right = parent_index % 2;

                    if parent_index == 1 {
                        // parent is root node
                        // region.constrain_equal(parent_cell.cell(), cells[&1].2.cell())?;
                        continue;
                    }

                    // if parent index is odd, that means its a sibling node
                    // TODO: Rename node to "left" and sibling to "right"
                    let parent_node_cell = if right == 0 {
                        // node cell (left)
                        &cells_map[&parent_index].input_chunks[0]
                    } else if right == 1 {
                        // sibling cell (right)
                        &cells_map[&(parent_index - 1)].input_chunks[1]
                    } else {
                        unreachable!()
                    };

                    region.constrain_equal(hash_rlc.cell(), parent_node_cell.cell())?;
                }

                Ok(())
            },
        )
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

impl<'a, S: Spec, F: Field> SubCircuit<'a, F> for StateCircuit<'a, S, F> {
    type Config = StateCircuitConfig<F>;
    type SynthesisArgs = ();
    type Output = ();

    fn new_from_state(state: &'a witness::SyncState<F>) -> Self {
        Self::new(&state.merkle_trace)
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
        _: Self::SynthesisArgs,
    ) -> Result<(), Error> {
        config.assign(layouter, self.trace, challenges.sha256_input())
    }

    fn instances(&self) -> Vec<Vec<F>> {
        self.trace.root().map(|b| vec![F::from(b as u64)]).to_vec()
    }

    fn unusable_rows() -> usize {
        todo!()
    }

    fn min_num_rows_state(_block: &witness::SyncState<F>) -> (usize, usize) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sha256_circuit::Sha256CircuitConfig,
        util::{full_prover, full_verifier, gen_pkey},
        witness::{MerkleTrace, SyncState, SyncStateInput},
    };
    use ark_std::{end_timer, start_timer};
    use eth_types::Test as S;
    use halo2_base::utils::fs::gen_srs;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };
    use std::{fs, marker::PhantomData};

    #[derive(Debug, Clone)]
    struct TestCircuit<'a, S: Spec, F: Field> {
        inner: StateCircuit<'a, S, F>,
    }

    impl<'a, S: Spec, F: Field> Circuit<F> for TestCircuit<'a, S, F> {
        type Config = (StateCircuitConfig<F>, Challenges<Value<F>>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha256_table = Sha256Table::construct(meta);
            let sha256_circuit = Sha256CircuitConfig::new::<S>(meta, sha256_table);

            let config = {
                StateCircuitConfig::new::<S>(
                    meta,
                    StateCircuitArgs {
                        sha256_circuit,
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
            self.inner
                .synthesize_sub(&config.0, &config.1, &mut layouter, ())?;
            Ok(())
        }
    }

    #[test]
    fn test_state_circuit() {
        let k = 18;
        let state_input: SyncStateInput =
            serde_json::from_slice(&fs::read("../test_data/sync_state.json").unwrap()).unwrap();
        let state: SyncState<Fr> = state_input.into();
        let circuit = TestCircuit::<Test, Fr> {
            inner: StateCircuit::new(&state.merkle_trace),
        };

        let instance = circuit.inner.instances();
        let timer = start_timer!(|| "state circuit mock prover");
        let prover = MockProver::<Fr>::run(k as u32, &circuit, instance).unwrap();
        prover.assert_satisfied();
        end_timer!(timer);
    }

    #[test]
    fn test_state_proofgen() {
        let k = 18;
        let state_input: SyncStateInput =
            serde_json::from_slice(&fs::read("../test_data/sync_state.json").unwrap()).unwrap();
        let state: SyncState<Fr> = state_input.into();
        let circuit = TestCircuit::<Test, Fr> {
            inner: StateCircuit::new(&state.merkle_trace),
        };

        let params = gen_srs(k as u32);

        let pkey = gen_pkey(|| "state", &params, None, circuit.clone()).unwrap();

        let public_inputs = circuit.inner.instances();
        let proof = full_prover(&params, &pkey, circuit, public_inputs.clone());

        assert!(full_verifier(&params, pkey.get_vk(), proof, public_inputs))
    }
}
