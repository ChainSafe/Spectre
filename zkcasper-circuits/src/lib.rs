pub(crate) mod gadget;
pub mod table;
pub(crate) mod util;
pub mod witness;

pub mod sha256_circuit;
pub mod state_circuit;
pub mod validators_circuit;
pub mod super_circuit;

pub const MAX_VALIDATORS: usize = 100;

pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

pub(crate) const N_BYTES_U64: usize = 8;

pub(crate) const STATE_ROWS_PER_VALIDATOR: usize = 6;

pub(crate) const STATE_ROWS_PER_COMMITEE: usize = 3; // TODO: or 15 if pubkey chunks are written row-wise
