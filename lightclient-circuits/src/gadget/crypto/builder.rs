use std::{cell::RefCell, collections::HashMap, env::set_var, marker::PhantomData, mem};

use eth_types::Field;
use getset::Getters;
use halo2_base::{
    gates::{
        circuit::{
            builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig, CircuitBuilderStage,
        },
        flex_gate::{
            threads::{CommonCircuitBuilder, SinglePhaseCoreManager},
            MultiPhaseThreadBreakPoints,
        },
        RangeChip,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    utils::BigPrimeField,
    virtual_region::manager::VirtualRegionManager,
    Context,
};
use itertools::Itertools;
use snark_verifier_sdk::CircuitExt;

use crate::{
    gadget::crypto::{Sha256Chip, ShaFlexGateManager},
    util::{CommonGateManager, Eth2ConfigPinning, GateBuilderConfig, PinnableCircuit},
};

use super::sha256_flex::{assign_threads_sha, SpreadConfig, FIRST_PHASE};

#[derive(Debug, Clone)]
pub struct SHAConfig<F: Field, CustomConfig: GateBuilderConfig<F>> {
    pub compression: CustomConfig,
    pub base: BaseConfig<F>,
}

impl<F: BigPrimeField, GateConfig: GateBuilderConfig<F>> SHAConfig<F, GateConfig> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: BaseCircuitParams) -> Self {
        let base = BaseConfig::configure(meta, params);
        let compression = GateConfig::configure(meta);

        Self { base, compression }
    }
}

#[derive(Getters)]
pub struct ShaCircuitBuilder<F: Field, ThreadBuilder: CommonGateManager<F>> {
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) sha: ThreadBuilder,
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) base: BaseCircuitBuilder<F>,
}

impl<F: Field, GateManager: CommonGateManager<F>> ShaCircuitBuilder<F, GateManager> {
    pub fn new(witness_gen_only: bool) -> Self {
        let base = BaseCircuitBuilder::new(witness_gen_only);
        Self {
            sha: GateManager::new(witness_gen_only)
                .use_copy_manager(base.core().phase_manager[FIRST_PHASE].copy_manager.clone()),
            base,
        }
    }

    pub fn from_stage(stage: CircuitBuilderStage) -> Self {
        Self::new(stage == CircuitBuilderStage::Prover)
            .unknown(stage == CircuitBuilderStage::Keygen)
    }

    pub fn unknown(mut self, use_unknown: bool) -> Self {
        self.sha = self.sha.unknown(use_unknown);
        self.base = self.base.unknown(use_unknown);
        self
    }

    /// Creates a new [ShaCircuitBuilder] with `use_unknown` of [ShaThreadBuilder] set to true.
    pub fn keygen() -> Self {
        Self::from_stage(CircuitBuilderStage::Keygen)
    }

    /// Creates a new [ShaCircuitBuilder] with `use_unknown` of [GateThreadBuilder] set to false.
    pub fn mock() -> Self {
        Self::from_stage(CircuitBuilderStage::Mock)
    }

    /// Creates a new [ShaCircuitBuilder].
    pub fn prover() -> Self {
        Self::from_stage(CircuitBuilderStage::Prover)
    }

    /// The log_2 size of the lookup table, if using.
    pub fn lookup_bits(&self) -> Option<usize> {
        self.base.lookup_bits()
    }

    /// Set lookup bits
    pub fn set_lookup_bits(&mut self, lookup_bits: usize) {
        self.base.set_lookup_bits(lookup_bits);
    }

    /// Returns new with lookup bits
    pub fn use_lookup_bits(mut self, lookup_bits: usize) -> Self {
        self.set_lookup_bits(lookup_bits);
        self
    }

    /// Sets new `k` = log2 of domain
    pub fn set_k(&mut self, k: usize) {
        self.base.set_k(k);
    }

    /// Returns new with `k` set
    pub fn use_k(mut self, k: usize) -> Self {
        self.set_k(k);
        self
    }

    /// Set config params
    pub fn set_params(&mut self, params: BaseCircuitParams) {
        self.base.set_params(params)
    }

    /// Returns new with config params
    pub fn use_params(mut self, params: BaseCircuitParams) -> Self {
        self.set_params(params);
        self
    }

    /// Sets the break points of the circuit.
    pub fn set_break_points(&mut self, break_points: MultiPhaseThreadBreakPoints) {
        self.base.set_break_points(break_points);
    }

    /// Returns new with break points
    pub fn use_break_points(mut self, break_points: MultiPhaseThreadBreakPoints) -> Self {
        self.set_break_points(break_points);
        self
    }

    /// Returns [SinglePhaseCoreManager] with the virtual region with all core threads in the given phase.
    pub fn pool(&mut self, phase: usize) -> &mut SinglePhaseCoreManager<F> {
        self.base.pool(phase)
    }

    pub fn calculate_params(&mut self, minimum_rows: Option<usize>) -> BaseCircuitParams {
        self.base.calculate_params(minimum_rows)
    }

    pub fn sha_contexts_pair(&mut self) -> (&mut Context<F>, GateManager::CustomContext<'_>) {
        (self.base.main(0), self.sha.custom_context())
    }

    pub fn range_chip(&mut self, lookup_bits: usize) -> RangeChip<F> {
        self.base.set_lookup_bits(lookup_bits);
        self.base.range_chip()
    }
}

impl<F: Field, GateManager: CommonGateManager<F>> CommonCircuitBuilder<F>
    for ShaCircuitBuilder<F, GateManager>
{
    fn main(&mut self) -> &mut Context<F> {
        self.base.main(0)
    }

    fn thread_count(&self) -> usize {
        self.thread_count()
    }

    fn new_context(&self, context_id: usize) -> Context<F> {
        self.new_context(context_id)
    }

    fn new_thread(&mut self) -> &mut Context<F> {
        self.new_thread()
    }
}

impl<F: Field, GateManager: CommonGateManager<F>> Circuit<F> for ShaCircuitBuilder<F, GateManager>
where
    GateManager::Config: GateBuilderConfig<F>,
{
    type Config = SHAConfig<F, GateManager::Config>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseCircuitParams;

    fn params(&self) -> Self::Params {
        self.base.config_params.clone()
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        SHAConfig::configure(meta, params)
    }

    fn configure(_meta: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!("You must use configure_with_params");
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.compression.load(&mut layouter)?;

        layouter.assign_region(
            || "ShaCircuitBuilder generated circuit",
            |mut region| {
                self.sha.assign_raw(&config.compression, &mut region);
                Ok(())
            },
        )?;

        self.base.synthesize(config.base.clone(), layouter)?;

        Ok(())
    }
}

impl<F: Field, GateManager: CommonGateManager<F>> CircuitExt<F>
    for ShaCircuitBuilder<F, GateManager>
where
    GateManager::Config: GateBuilderConfig<F>,
{
    fn num_instance(&self) -> Vec<usize> {
        self.base
            .assigned_instances
            .iter()
            .map(|e| e.len())
            .collect()
    }

    fn instances(&self) -> Vec<Vec<F>> {
        self.base
            .assigned_instances
            .iter()
            .map(|v| v.into_iter().map(|av| *av.value()).collect_vec())
            .collect()
    }
}

impl<F: Field, GateManager: CommonGateManager<F>> PinnableCircuit<F>
    for ShaCircuitBuilder<F, GateManager>
where
    GateManager::Config: GateBuilderConfig<F>,
{
    type Pinning = Eth2ConfigPinning;

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.base.break_points()
    }
}
