#![allow(dead_code)]
use eth_types::*;
use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    halo2_proofs::{
        circuit::{Layouter, Region},
        plonk::{ConstraintSystem, Error},
    },
    virtual_region::{
        copy_constraints::SharedCopyConstraintManager, manager::VirtualRegionManager,
    },
};

pub trait GateBuilderConfig<F: Field>: Clone + Sized {
    fn configure(meta: &mut ConstraintSystem<F>) -> Self;

    fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;

    fn annotate_columns_in_region(&self, region: &mut Region<F>);
}

pub trait CommonGateManager<F: Field>: VirtualRegionManager<F> + Clone {
    type CustomContext<'a>
    where
        Self: 'a;

    fn new(witness_gen_only: bool) -> Self;

    fn custom_context(&mut self) -> Self::CustomContext<'_>;

    /// Returns `self` with a given copy manager
    fn use_copy_manager(self, copy_manager: SharedCopyConstraintManager<F>) -> Self;

    fn from_stage(stage: CircuitBuilderStage) -> Self {
        Self::new(stage == CircuitBuilderStage::Prover)
            .unknown(stage == CircuitBuilderStage::Keygen)
    }

    fn mock() -> Self {
        Self::new(false)
    }

    fn keygen() -> Self {
        Self::new(false).unknown(true)
    }

    fn prover() -> Self {
        Self::new(true)
    }

    fn unknown(self, use_unknown: bool) -> Self;
}
