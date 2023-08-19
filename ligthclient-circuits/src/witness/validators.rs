use std::{iter, vec};

use crate::gadget::rlc;
use eth_types::{AppCurveExt, Field, Spec};
use ethereum_consensus::phase0::is_active_validator;

use group::{Group, GroupEncoding};
use halo2_proofs::circuit::Value;
use itertools::Itertools;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

/// Beacon validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    pub id: usize,
    pub is_attested: bool,
    pub pubkey: Vec<u8>,
    pub pubkey_uncompressed: Vec<u8>,
}

lazy_static! {
    pub static ref DUMMY_VALIDATOR: Validator = Validator::default();
    pub static ref DUMMY_PUBKEY: Vec<u8> = iter::once(192).pad_using(48, |_| 0).rev().collect();
}

impl Default for Validator {
    fn default() -> Self {
        Validator {
            id: 0,
            is_attested: true,
            pubkey: iter::once(192).pad_using(48, |_| 0).rev().collect(),
            pubkey_uncompressed: iter::once(64).pad_using(96, |_| 0).collect(),
        }
    }
}
