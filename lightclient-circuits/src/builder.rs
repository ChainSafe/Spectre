use std::{cell::RefCell, collections::HashMap, env::set_var};

use eth_types::Field;
use halo2_base::{
    gates::{
        builder::{FlexGateConfigParams, KeygenAssignments, ThreadBreakPoints},
        range::RangeConfig,
    },
    safe_types::RangeChip,
    SKIP_FIRST_PASS,
};
use halo2_proofs::{
    circuit::{self, Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem},
};

use crate::{
    gadget::crypto::{Sha256Chip, SpreadConfig, SpreadThreadBuilder},
    sha256_circuit::Sha256CircuitConfig,
};

pub struct SHAConfig<F: Field> {
    pub spread: SpreadConfig<F>,
    pub range: RangeConfig<F>,
}

impl<F: Field> SHAConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: FlexGateConfigParams) -> Self {
        let degree = params.k;
        let mut range = RangeConfig::configure(
            meta,
            params.strategy,
            &params.num_advice_per_phase,
            &params.num_lookup_advice_per_phase,
            params.num_fixed,
            params.lookup_bits.unwrap_or(8),
            degree as usize,
        );
        set_var("KECCAK_DEGREE", degree.to_string());
        set_var("KECCAK_ROWS", params.keccak_rows_per_round.to_string());
        let spread = SpreadConfig::configure(meta, range.lookup_bits(), 2); // TODO configure num_advice_columns
        set_var("UNUSABLE_ROWS", meta.minimum_rows().to_string());

        range.range.gate.max_rows = (1 << degree) - meta.minimum_rows();
        Self { range, spread }
    }
}

pub struct ShaCircuitBuilder<'a, F: Field> {
    pub builder: RefCell<SpreadThreadBuilder<F>>,
    pub break_points: RefCell<ThreadBreakPoints>,
    pub sha256: Sha256Chip<'a, F>,
    pub range: RangeChip<F>,
}

impl<'a, F: Field> ShaCircuitBuilder<'a, F> {
    pub fn new(
        builder: SpreadThreadBuilder<F>,
        sha256: Sha256Chip<F>,
        range: RangeChip<F>,
        break_points: Option<ThreadBreakPoints>,
        // synthesize_phase1: FnPhase1,
    ) -> Self {
        Self {
            builder: RefCell::new(builder),
            break_points: RefCell::new(break_points.unwrap_or_default()),
            sha256,
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
    pub fn sub_synthesize(
        &self,
        config: &SHAConfig<F>,
        layouter: &mut impl Layouter<F>,
    ) -> HashMap<(usize, usize), (circuit::Cell, usize)> {
        config
            .rlp
            .range
            .load_lookup_table(layouter)
            .expect("load range lookup table");
        config
            .keccak
            .load_aux_tables(layouter)
            .expect("load keccak lookup tables");

        let mut first_pass = SKIP_FIRST_PASS;
        let witness_gen_only = self.builder.borrow().witness_gen_only();

        let mut assigned_advices = HashMap::new();

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
                        let mut sha256 = self.sha256.borrow().clone();

                        // Do any custom synthesize functions in SecondPhase
                        let mut assignments = KeygenAssignments {
                            ..Default::default()
                        };
                        // let rlp_chip = RlpChip::new(&self.range, Some(&rlc_chip));
                        // f(&mut builder, rlp_chip, keccak_rlcs);
                        assignments = builder.assign_all(
                            &config.rlp.range.gate,
                            &config.rlp.range.lookup_advice,
                            &config.rlp.range.q_lookup,
                            &config.rlp.rlc,
                            &mut region,
                            assignments,
                        );
                        *self.break_points.borrow_mut() = assignments.break_points;
                        assigned_advices = assignments.assigned_advices;
                    } else {
                        unimplemented!()
                    }
                    Ok(())
                },
            )
            .unwrap();
        assigned_advices
    }
}

impl<'a, F: Field /*, FnPhase1: FnSynthesize<F>*/> Circuit<F> for ShaCircuitBuilder<'a, F> {
    type Config = SHAConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Sha256CircuitConfig<F> {
        let params: EthConfigParams =
            serde_json::from_str(&std::env::var("ETH_CONFIG_PARAMS").unwrap()).unwrap();
        MPTConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.two_phase_synthesize(&config, &mut layouter);
        Ok(())
    }
}
