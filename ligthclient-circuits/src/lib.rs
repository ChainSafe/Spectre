#![allow(incomplete_features)]
#![feature(int_roundings)]
#![feature(associated_type_bounds)]
#![feature(generic_const_exprs)]
#![feature(const_cmp)]
#![feature(stmt_expr_attributes)]
#![feature(trait_alias)]
#![feature(generic_arg_infer)]
#![feature(return_position_impl_trait_in_trait)]
#![allow(unused, clippy::uninlined_format_args, clippy::needless_range_loop)]
pub(crate) mod gadget;
pub mod table;
pub(crate) mod util;
pub mod witness;

pub mod sha256_circuit;
pub mod sync_circuit;
pub mod state_circuit;