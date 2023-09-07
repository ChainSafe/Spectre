use std::{cell::RefCell, collections::HashMap, env::set_var};

use eth_types::Field;
use halo2_base::{
    gates::{
        builder::{FlexGateConfigParams, KeygenAssignments, ThreadBreakPoints},
        range::{RangeConfig, RangeStrategy},
    },
    safe_types::RangeChip,
    SKIP_FIRST_PASS,
};
use halo2_proofs::{
    circuit::{self, Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::{
    gadget::crypto::{Sha256Chip, SpreadConfig, SpreadThreadBuilder},
    sha256_circuit::Sha256CircuitConfig,
};

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
        set_var("UNUSABLE_ROWS", meta.minimum_rows().to_string());

        range.gate.max_rows = (1 << degree) - meta.minimum_rows();
        Self { range, spread }
    }
}

pub struct ShaCircuitBuilder<F: Field> {
    pub builder: RefCell<SpreadThreadBuilder<F>>,
    pub break_points: RefCell<ThreadBreakPoints>,
    pub range: RangeChip<F>,
}

impl<F: Field> ShaCircuitBuilder<F> {
    pub fn new(
        builder: SpreadThreadBuilder<F>,
        range: RangeChip<F>,
        break_points: Option<ThreadBreakPoints>,
        // synthesize_phase1: FnPhase1,
    ) -> Self {
        Self {
            builder: RefCell::new(builder),
            break_points: RefCell::new(break_points.unwrap_or_default()),
            range,
            // synthesize_phase1: RefCell::new(Some(synthesize_phase1)),
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

        layouter
            .assign_region(
                || "ShaCircuitBuilder generated circuit",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    if !witness_gen_only {
                        let mut builder = self.builder.borrow().clone();
                  
                        let mut assignments = KeygenAssignments {
                            ..Default::default()
                        };
                    
                        assignments = builder.assign_all(
                            &config.range.gate,
                            &config.range.lookup_advice,
                            &config.range.q_lookup,
                            &config.spread,
                            &mut region,
                            assignments,
                        );
                        *self.break_points.borrow_mut() = assignments.break_points[0].clone();
                        assigned_advices = assignments.assigned_advices;
                    } else {
                        unimplemented!()
                    }
                    Ok(())
                },
            )?;
        Ok(assigned_advices)
    }
}

impl<F: Field /*, FnPhase1: FnSynthesize<F>*/> Circuit<F> for ShaCircuitBuilder<F> {
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
