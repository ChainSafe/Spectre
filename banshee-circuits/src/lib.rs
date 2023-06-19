pub(crate) mod gadget;
pub mod table;
pub(crate) mod util;
pub mod witness;

pub mod sha256_circuit;
pub mod state_circuit;
pub mod vs_circuit;

pub const MAX_VALIDATORS: usize = 100;

pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

pub(crate) const N_BYTES_U64: usize = 8;
