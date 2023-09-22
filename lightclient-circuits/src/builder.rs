use eth_types::Field;
use halo2_base::{
    gates::builder::{CircuitBuilderStage, FlexGateConfigParams, MultiPhaseThreadBreakPoints},
    AssignedValue,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use log::debug;

use crate::{
    gadget::crypto::{SHAConfig, ShaCircuitBuilder, ShaThreadBuilder},
    util::{Eth2ConfigPinning, PinnableCircuit, ThreadBuilderBase, ThreadBuilderConfigBase},
};

#[derive(Clone, Debug)]
/// Config shared for block header and storage proof circuits
pub struct Eth2Config<F: Field, CustomConfig: ThreadBuilderConfigBase<F>> {
    sha: SHAConfig<F, CustomConfig>,
    pub instance: Column<Instance>,
}

/// This is an extension of [`ShaCircuitBuilder`] that adds support for public instances (aka public inputs+outputs)
pub struct Eth2CircuitBuilder<F: Field, ThreadBuilder: ThreadBuilderBase<F>> {
    pub inner: ShaCircuitBuilder<F, ThreadBuilder>,
    pub assigned_instances: Vec<AssignedValue<F>>,
}

impl<F: Field, ThreadBuilder: ThreadBuilderBase<F>> Eth2CircuitBuilder<F, ThreadBuilder> {
    pub fn new(
        assigned_instances: Vec<AssignedValue<F>>,
        builder: ShaCircuitBuilder<F, ThreadBuilder>,
    ) -> Self {
        Self {
            assigned_instances,
            inner: builder,
        }
    }

    pub fn from_stage(
        assigned_instances: Vec<AssignedValue<F>>,
        builder: ThreadBuilder,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        stage: CircuitBuilderStage,
    ) -> Self {
        Self::new(
            assigned_instances,
            ShaCircuitBuilder::from_stage(builder, break_points, stage),
        )
    }

    /// Creates a new [Eth2CircuitBuilder] with `use_unknown` of [ThreadBuilder] set to true.
    pub fn keygen(assigned_instances: Vec<AssignedValue<F>>, builder: ThreadBuilder) -> Self {
        Self {
            assigned_instances,
            inner: ShaCircuitBuilder::keygen(builder),
        }
    }

    /// Creates a new [Eth2CircuitBuilder] with `use_unknown` of [ThreadBuilder] set to false.
    pub fn mock(assigned_instances: Vec<AssignedValue<F>>, builder: ThreadBuilder) -> Self {
        Self {
            assigned_instances,
            inner: ShaCircuitBuilder::mock(builder),
        }
    }

    /// Creates a new [Eth2CircuitBuilder].
    pub fn prover(
        assigned_instances: Vec<AssignedValue<F>>,
        builder: ThreadBuilder,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        Self {
            assigned_instances,
            inner: ShaCircuitBuilder::prover(builder, break_points),
        }
    }

    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> FlexGateConfigParams {
        self.inner.config(k, minimum_rows)
    }

    pub fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.inner.break_points.borrow().clone()
    }

    pub fn instance_count(&self) -> usize {
        self.assigned_instances.len()
    }

    pub fn instance(&self) -> Vec<F> {
        self.assigned_instances.iter().map(|v| *v.value()).collect()
    }
}

impl<F: Field, ThreadBuilder: ThreadBuilderBase<F>> Circuit<F>
    for Eth2CircuitBuilder<F, ThreadBuilder>
{
    type Config = Eth2Config<F, ThreadBuilder::Config>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let sha = ShaCircuitBuilder::<F, ThreadBuilder>::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Eth2Config { sha, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // we later `take` the builder, so we need to save this value
        let witness_gen_only = self.inner.builder.borrow().witness_gen_only();

        let assigned_advices = self.inner.sub_synthesize(&config.sha, &mut layouter)?;

        if !witness_gen_only {
            // expose public instances
            let mut layouter = layouter.namespace(|| "expose");
            for (i, instance) in self.assigned_instances.iter().enumerate() {
                let cell = instance.cell.unwrap();
                let (cell, _) = assigned_advices
                    .get(&(cell.context_id, cell.offset))
                    .expect("instance not assigned");
                layouter.constrain_instance(*cell, config.instance, i);
            }
        }
        Ok(())
    }
}

impl<F: Field, ThreadBuilder: ThreadBuilderBase<F>> snark_verifier_sdk::CircuitExt<F>
    for Eth2CircuitBuilder<F, ThreadBuilder>
{
    fn num_instance(&self) -> Vec<usize> {
        vec![self.instance_count()]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![self.instance()]
    }
}

impl<F: Field, ThreadBuilder: ThreadBuilderBase<F>> PinnableCircuit<F>
    for Eth2CircuitBuilder<F, ThreadBuilder>
{
    type Pinning = Eth2ConfigPinning;

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.inner.break_points.borrow().clone()
    }
}
