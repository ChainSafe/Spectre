// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use core::fmt::Debug;
use ethereum_types::{EthSpec, MainnetEthSpec, MinimalEthSpec};
/// Beacon chain specification.
pub trait Spec: 'static + Sized + Copy + Default + Debug {
    type EthSpec: EthSpec;

    const NAME: &'static str;
    const SYNC_COMMITTEE_SIZE: usize;
    const SYNC_COMMITTEE_ROOT_INDEX: usize;
    const SYNC_COMMITTEE_DEPTH: usize;
    const SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX: usize;
    const SYNC_COMMITTEE_PUBKEYS_DEPTH: usize;

    const DST: &'static [u8];
    const EXECUTION_STATE_ROOT_INDEX: usize;
    const EXECUTION_STATE_ROOT_DEPTH: usize;
    const FINALIZED_HEADER_INDEX: usize;
    const FINALIZED_HEADER_DEPTH: usize;

    const HEADER_SLOT_INDEX: usize = 8;
    const HEADER_STATE_ROOT_INDEX: usize = 11;
    const HEADER_BODY_ROOT_INDEX: usize = 12;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Minimal;

impl Spec for Minimal {
    type EthSpec = MinimalEthSpec;

    const NAME: &'static str = "minimal";
    const SYNC_COMMITTEE_SIZE: usize = 32;
    const SYNC_COMMITTEE_DEPTH: usize = 5;
    const SYNC_COMMITTEE_ROOT_INDEX: usize = 55;
    const SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX: usize = Self::SYNC_COMMITTEE_ROOT_INDEX * 2;
    const SYNC_COMMITTEE_PUBKEYS_DEPTH: usize = Self::SYNC_COMMITTEE_DEPTH + 1;

    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const EXECUTION_STATE_ROOT_INDEX: usize = 9;
    const EXECUTION_STATE_ROOT_DEPTH: usize = 4;
    const FINALIZED_HEADER_INDEX: usize = 105;
    const FINALIZED_HEADER_DEPTH: usize = 6;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Testnet;

impl Spec for Testnet {
    type EthSpec = MainnetEthSpec;

    const NAME: &'static str = "testnet";
    const SYNC_COMMITTEE_SIZE: usize = 512;
    const SYNC_COMMITTEE_DEPTH: usize = 5;
    const SYNC_COMMITTEE_ROOT_INDEX: usize = 55;
    const SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX: usize = Self::SYNC_COMMITTEE_ROOT_INDEX * 2;
    const SYNC_COMMITTEE_PUBKEYS_DEPTH: usize = Self::SYNC_COMMITTEE_DEPTH + 1;
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const EXECUTION_STATE_ROOT_INDEX: usize = 25;
    const EXECUTION_STATE_ROOT_DEPTH: usize = 4;
    const FINALIZED_HEADER_INDEX: usize = 105;
    const FINALIZED_HEADER_DEPTH: usize = 6;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Mainnet;

impl Spec for Mainnet {
    type EthSpec = MainnetEthSpec;

    const NAME: &'static str = "mainnet";
    const SYNC_COMMITTEE_SIZE: usize = 512;
    const SYNC_COMMITTEE_DEPTH: usize = 5;
    const SYNC_COMMITTEE_ROOT_INDEX: usize = 55;
    const SYNC_COMMITTEE_PUBKEYS_ROOT_INDEX: usize = Self::SYNC_COMMITTEE_ROOT_INDEX * 2;
    const SYNC_COMMITTEE_PUBKEYS_DEPTH: usize = Self::SYNC_COMMITTEE_DEPTH + 1;
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const EXECUTION_STATE_ROOT_INDEX: usize = 25;
    const EXECUTION_STATE_ROOT_DEPTH: usize = 4;
    const FINALIZED_HEADER_INDEX: usize = 105;
    const FINALIZED_HEADER_DEPTH: usize = 6;
}
