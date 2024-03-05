// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(clippy::needless_range_loop)]

pub mod gadget;
pub mod util;
pub mod witness;

pub mod aggregation_circuit;
pub mod committee_update_circuit;
pub mod sync_step_circuit;

pub mod poseidon;
mod ssz_merkle;

pub use halo2_base;
pub use halo2_base::halo2_proofs;

use halo2_base::halo2_proofs::halo2curves::bn256;
#[allow(type_alias_bounds)]
pub type Eth2CircuitBuilder<GateManager: util::CommonGateManager<bn256::Fr>> =
    gadget::crypto::ShaCircuitBuilder<bn256::Fr, GateManager>;
