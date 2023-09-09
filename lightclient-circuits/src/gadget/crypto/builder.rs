use std::{cell::RefCell, collections::HashMap, env::set_var, mem};

use eth_types::Field;
use halo2_base::{
    gates::{
        builder::{
            assign_threads_in, FlexGateConfigParams, KeygenAssignments,
            MultiPhaseThreadBreakPoints, ThreadBreakPoints,
        },
        range::{RangeConfig, RangeStrategy},
    },
    safe_types::RangeChip,
    SKIP_FIRST_PASS,
};
use halo2_proofs::{
    circuit::{self, Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use snark_verifier_sdk::CircuitExt;

use crate::{
    gadget::crypto::{Sha256Chip, ShaThreadBuilder},
    sha256_circuit::Sha256CircuitConfig,
};

use super::sha256::{assign_threads_sha, SpreadConfig, FIRST_PHASE};

#[derive(Debug, Clone)]
pub struct SHAConfig<F: Field> {
    pub spread: SpreadConfig<F>,
    pub range: RangeConfig<F>,
}

impl<F: Field> SHAConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: FlexGateConfigParams) -> Self {
        let degree = params.k;
        let mut range = RangeConfig::configure(
            meta,
            RangeStrategy::Vertical,
            &params.num_advice_per_phase,
            &params.num_lookup_advice_per_phase,
            params.num_fixed,
            params.k - 1,
            degree,
        );
        let spread = SpreadConfig::configure(meta, 8, 2); // TODO configure num_advice_columns

        range.gate.max_rows = (1 << degree) - meta.minimum_rows();
        Self { range, spread }
    }
}

pub struct ShaCircuitBuilder<F: Field> {
    pub builder: RefCell<ShaThreadBuilder<F>>,
    pub break_points: RefCell<MultiPhaseThreadBreakPoints>, // `RefCell` allows the circuit to record break points in a keygen call of `synthesize` for use in later witness gen
}

impl<F: Field> ShaCircuitBuilder<F> {
    /// Creates a new [ShaCircuitBuilder] with `use_unknown` of [ShaThreadBuilder] set to true.
    pub fn keygen(builder: ShaThreadBuilder<F>) -> Self {
        Self {
            builder: RefCell::new(builder.unknown(true)),
            break_points: RefCell::new(vec![]),
        }
    }

    /// Creates a new [ShaCircuitBuilder] with `use_unknown` of [GateThreadBuilder] set to false.
    pub fn mock(builder: ShaThreadBuilder<F>) -> Self {
        Self {
            builder: RefCell::new(builder.unknown(false)),
            break_points: RefCell::new(vec![]),
        }
    }

    /// Creates a new [ShaCircuitBuilder].
    pub fn prover(builder: ShaThreadBuilder<F>, break_points: MultiPhaseThreadBreakPoints) -> Self {
        Self {
            builder: RefCell::new(builder.unknown(false)),
            break_points: RefCell::new(break_points),
        }
    }

    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> FlexGateConfigParams {
        // clone everything so we don't alter the circuit in any way for later calls
        let mut builder = self.builder.borrow().clone();
        builder.config(k, minimum_rows)
    }

    // re-usable function for synthesize
    #[allow(clippy::type_complexity)]
    pub fn sub_synthesize(
        &self,
        config: &SHAConfig<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<HashMap<(usize, usize), (circuit::Cell, usize)>, Error> {
        config
            .range
            .load_lookup_table(layouter)
            .expect("load range lookup table");

        let mut first_pass = SKIP_FIRST_PASS;
        let witness_gen_only = self.builder.borrow().witness_gen_only();

        let mut assigned_advices = HashMap::new();

        config.spread.load(layouter)?;

        layouter.assign_region(
            || "ShaCircuitBuilder generated circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                if !witness_gen_only {
                    let mut builder = self.builder.borrow().clone();

                    let assignments = builder.assign_all(
                        &config.range.gate,
                        &config.range.lookup_advice,
                        &config.range.q_lookup,
                        &config.spread,
                        &mut region,
                        Default::default(),
                    );
                    *self.break_points.borrow_mut() = assignments.break_points.clone();
                    assigned_advices = assignments.assigned_advices;
                } else {
                    let builder = &mut self.builder.borrow_mut();
                    let break_points = &mut self.break_points.borrow_mut();

                    let break_points_gate = mem::take(&mut break_points[FIRST_PHASE]);
                    // warning: we currently take all contexts from phase 0, which means you can't read the values
                    // from these contexts later in phase 1. If we want to read, should clone here
                    let threads = mem::take(&mut builder.gate_builder.threads[FIRST_PHASE]);

                    assign_threads_in(
                        FIRST_PHASE,
                        threads,
                        &config.range.gate,
                        &config.range.lookup_advice[FIRST_PHASE],
                        &mut region,
                        break_points_gate,
                    );

                    let threads_dense = mem::take(&mut builder.threads_dense);
                    let threads_spread = mem::take(&mut builder.threads_spread);

                    assign_threads_sha(
                        &threads_dense,
                        &threads_spread,
                        &config.spread,
                        &mut region,
                        false,
                        None,
                    );
                }
                Ok(())
            },
        )?;
        Ok(assigned_advices)
    }
}

impl<F: Field> Circuit<F> for ShaCircuitBuilder<F> {
    type Config = SHAConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> SHAConfig<F> {
        let params: FlexGateConfigParams =
            serde_json::from_str(&std::env::var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
        SHAConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.sub_synthesize(&config, &mut layouter);
        Ok(())
    }
}
