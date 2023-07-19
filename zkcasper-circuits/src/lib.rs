#![feature(int_roundings)]
#![feature(associated_type_bounds)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(const_cmp)]
#![feature(stmt_expr_attributes)]
#![feature(trait_alias)]
#![allow(unused, clippy::uninlined_format_args, clippy::needless_range_loop)]
pub(crate) mod gadget;
pub mod table;
pub(crate) mod util;
pub mod witness;

pub mod aggregation_circuit;
pub mod attestations_circuit;
pub mod sha256_circuit;
pub mod state_circuit;
pub mod super_circuit;
pub mod validators_circuit;

pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

pub(crate) const N_BYTES_U64: usize = 8;
