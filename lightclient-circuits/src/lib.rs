#![allow(incomplete_features)]
#![feature(int_roundings)]
#![feature(associated_type_bounds)]
#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(trait_alias)]
#![feature(generic_arg_infer)]
#![feature(return_position_impl_trait_in_trait)]
#![allow(unused, clippy::uninlined_format_args, clippy::needless_range_loop)]
pub mod gadget;
pub mod util;
pub mod witness;

pub mod aggregation;
pub mod committee_update_circuit;
pub mod sync_step_circuit;

// pub mod builder;
mod poseidon;
mod ssz_merkle;

pub use halo2_base;

use halo2_base::halo2_proofs::halo2curves::bn256;
#[allow(type_alias_bounds)]
pub type Eth2CircuitBuilder<GateManager: util::CommonGateManager<bn256::Fr>> =
    gadget::crypto::ShaCircuitBuilder<bn256::Fr, GateManager>;
