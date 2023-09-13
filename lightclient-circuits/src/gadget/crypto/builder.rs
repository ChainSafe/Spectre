use std::{cell::RefCell, collections::HashMap, env::set_var, marker::PhantomData, mem};

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
    util::{ThreadBuilderBase, ThreadBuilderConfigBase},
};

use super::sha256_wide::Sha256BitConfig;
use super::{
    sha256_flex::{SpreadConfig, FIRST_PHASE},
    ShaBitThreadBuilder,
};
pub trait ShaGenericThreadBuilderBase<F: Field>:
    ThreadBuilderBase<F, Config = <Self as ShaGenericThreadBuilderBase<F>>::Config>
{
    type Config: ShaGenericThreadBuilderConfigBase<F>;
}

pub trait ShaGenericThreadBuilderConfigBase<F: Field>: ThreadBuilderConfigBase<F> {}

impl<F: Field> ShaGenericThreadBuilderBase<F> for ShaThreadBuilder<F> {
    type Config = SpreadConfig<F>;
}
impl<F: Field> ShaGenericThreadBuilderBase<F> for ShaBitThreadBuilder<F> {
    type Config = Sha256BitConfig<F>;
}
impl<F: Field> ShaGenericThreadBuilderConfigBase<F> for SpreadConfig<F> {}
impl<F: Field> ShaGenericThreadBuilderConfigBase<F> for Sha256BitConfig<F> {}

#[derive(Debug, Clone)]
pub struct SHAConfig<F: Field, CustomConfig: ShaGenericThreadBuilderConfigBase<F>> {
    pub compression: CustomConfig,
    pub range: RangeConfig<F>,
}

impl<F: Field, CustomConfig: ShaGenericThreadBuilderConfigBase<F>> SHAConfig<F, CustomConfig> {
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
        let compression = CustomConfig::configure(meta, params);

        range.gate.max_rows = (1 << degree) - meta.minimum_rows();
        Self { range, compression }
    }
}

pub struct ShaCircuitBuilder<F: Field, ThreadBuilder: ShaGenericThreadBuilderBase<F>> {
    pub builder: RefCell<ThreadBuilder>,
    pub break_points: RefCell<MultiPhaseThreadBreakPoints>, // `RefCell` allows the circuit to record break points in a keygen call of `synthesize` for use in later witness gen
    _f: PhantomData<F>,
}

impl<F: Field, ThreadBuilder: ShaGenericThreadBuilderBase<F>> ShaCircuitBuilder<F, ThreadBuilder> {
    /// Creates a new [ShaCircuitBuilder] with `use_unknown` of [ShaThreadBuilder] set to true.
    pub fn keygen(builder: ThreadBuilder) -> Self {
        Self {
            builder: RefCell::new(builder.unknown(true)),
            break_points: RefCell::new(vec![]),
            _f: PhantomData,
        }
    }

    /// Creates a new [ShaCircuitBuilder] with `use_unknown` of [GateThreadBuilder] set to false.
    pub fn mock(builder: ThreadBuilder) -> Self {
        Self {
            builder: RefCell::new(builder.unknown(false)),
            break_points: RefCell::new(vec![]),
            _f: PhantomData,
        }
    }

    /// Creates a new [ShaCircuitBuilder].
    pub fn prover(builder: ThreadBuilder, break_points: MultiPhaseThreadBreakPoints) -> Self {
        Self {
            builder: RefCell::new(builder.unknown(false)),
            break_points: RefCell::new(break_points),
            _f: PhantomData,
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
        config: &SHAConfig<F, <ThreadBuilder as ShaGenericThreadBuilderBase<F>>::Config>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<HashMap<(usize, usize), (circuit::Cell, usize)>, Error> {
        config
            .range
            .load_lookup_table(layouter)
            .expect("load range lookup table");

        let mut first_pass = SKIP_FIRST_PASS;
        let witness_gen_only = self.builder.borrow().witness_gen_only();

        let mut assigned_advices = HashMap::new();

        config.compression.load(layouter)?;

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
                        &config.compression,
                        &mut region,
                        Default::default(),
                    )?;
                    *self.break_points.borrow_mut() = assignments.break_points.clone();
                    assigned_advices = assignments.assigned_advices;
                } else {
                    let builder = &mut self.builder.borrow_mut();
                    let break_points = &mut self.break_points.borrow_mut();

                    builder.assign_witnesses(
                        &config.range.gate,
                        &config.range.lookup_advice,
                        &config.compression,
                        &mut region,
                        break_points,
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(assigned_advices)
    }
}

impl<F: Field, ThreadBuilder: ShaGenericThreadBuilderBase<F>> Circuit<F>
    for ShaCircuitBuilder<F, ThreadBuilder>
{
    type Config = SHAConfig<F, <ThreadBuilder as ShaGenericThreadBuilderBase<F>>::Config>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> SHAConfig<F, <ThreadBuilder as ShaGenericThreadBuilderBase<F>>::Config> {
        let params: FlexGateConfigParams =
            serde_json::from_str(&std::env::var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
        SHAConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.sub_synthesize(&config, &mut layouter)?;
        Ok(())
    }
}
