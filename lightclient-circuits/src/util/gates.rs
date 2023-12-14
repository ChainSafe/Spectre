// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use eth_types::*;
use halo2_base::{
    gates::circuit::BaseCircuitParams,
    halo2_proofs::{
        circuit::{Layouter, Region},
        plonk::{ConstraintSystem, Error},
    },
    virtual_region::{
        copy_constraints::SharedCopyConstraintManager, manager::VirtualRegionManager,
    },
};

/// Custom config for a custom gate builder.
pub trait GateBuilderConfig<F: Field>: Clone + Sized {
    fn configure(meta: &mut ConstraintSystem<F>, params: BaseCircuitParams) -> Self;

    fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;

    fn annotate_columns_in_region(&self, region: &mut Region<F>);
}

/// Thin abstraction over a gate a `VirtualRegionManager`.
pub trait CommonGateManager<F: Field>: VirtualRegionManager<F> + Clone {
    type CustomContext<'a>
    where
        Self: 'a;

    fn new(witness_gen_only: bool) -> Self;

    fn custom_context(&mut self) -> Self::CustomContext<'_>;

    /// Returns `self` with a given copy manager
    fn use_copy_manager(self, copy_manager: SharedCopyConstraintManager<F>) -> Self;

    fn unknown(self, use_unknown: bool) -> Self;
}
