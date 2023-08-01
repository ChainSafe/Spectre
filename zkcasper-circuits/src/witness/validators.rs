use std::{iter, vec};

use banshee_preprocessor::util::pad_to_ssz_chunk;
use eth_types::{AppCurveExt, Field, Spec};
use ethereum_consensus::phase0::is_active_validator;
use gadgets::util::rlc;

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
    pub shuffle_pos: usize,
    pub committee: usize,
    pub is_active: bool,
    pub is_attested: bool,
    pub effective_balance: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
    pub slashed: bool,
    pub pubkey: Vec<u8>,
    pub pubkey_uncompressed: Vec<u8>,
}

lazy_static! {
    pub static ref DUMMY_VALIDATOR: Validator = Validator::default();
}

impl Default for Validator {
    fn default() -> Self {
        Validator {
            id: 0,
            shuffle_pos: 0,
            committee: 0,
            is_active: false,
            is_attested: false,
            effective_balance: 0,
            activation_epoch: 0,
            exit_epoch: 0,
            slashed: false,
            pubkey: iter::once(192).pad_using(48, |_| 0).rev().collect(),
            pubkey_uncompressed: iter::once(64).pad_using(96, |_| 0).collect(),
        }
    }
}

impl Validator {
    pub fn dummy(id: usize, committee: usize) -> Self {
        Validator {
            id,
            committee,
            ..Validator::default()
        }
    }

    /// Get validaotor table record.
    /// `attest_digits` - digits composed from attestation bits of validator's committee.
    pub(crate) fn table_assignment<S: Spec, F: Field>(
        &self,
        committee: usize,
        randomness: Value<F>,
        attest_digits: &mut [Vec<u64>],
        committees_balances: &mut [u64],
    ) -> Vec<ValidatorRow<F>> {
        let committee_pos = self.committee_pos::<S>();
        assert!(
            committee_pos <= S::VALIDATOR_REGISTRY_LIMIT,
            "validator position out of bounds"
        );

        let attest_digit_len = S::attest_digits_len::<F>();
        let current_digit = committee_pos / F::NUM_BITS as usize;
        // accumulate bits into current digit
        let committee_attest_digits = &mut attest_digits[committee];
        let digit = committee_attest_digits.get_mut(current_digit).unwrap();
        *digit = *digit * 2 + self.is_attested as u64;
        // accumulate balance of the current committee
        committees_balances[committee] += self.effective_balance * self.is_active as u64;

        vec![ValidatorRow {
            id: Value::known(F::from(self.id as u64)),
            is_active: Value::known(F::from(self.is_active as u64)),
            is_attested: Value::known(F::from(self.is_attested as u64)),
            balance: Value::known(F::from(self.effective_balance)),
            slashed: Value::known(F::from(self.slashed as u64)),
            activation_epoch: Value::known(F::from(self.activation_epoch)),
            exit_epoch: Value::known(F::from(self.exit_epoch)),
            pubkey: [
                randomness.map(|rnd| rlc::value(&self.pubkey[0..32], rnd)),
                randomness.map(|rnd| rlc::value(&pad_to_ssz_chunk(&self.pubkey[32..48]), rnd)),
            ],
            attest_digits: committee_attest_digits
                .iter()
                .take(attest_digit_len)
                .map(|b| Value::known(F::from(*b)))
                .collect(),
            total_balance_acc: Value::known(F::from(committees_balances.iter().sum::<u64>())),
        }]
    }

    /// method to build a vector of `banshee::Validator` from the
    /// `ethereum_consensus::phase0::Validator` struct.
    /// TODO: Perhaps there is more "rustacean" way to implement this,
    /// but we cannot implement `From<Vec<ethereum_consensus::phase0::Validator`>>` for
    /// `Vec<Validator>`, because that would be trying to implement an external trait on
    /// an external type.
    pub fn build_from_validators<'a>(
        validators: impl Iterator<Item = &'a ethereum_consensus::phase0::Validator>,
    ) -> Vec<Validator> {
        let mut banshee_validators = vec![];

        // the `id` is the *order* in which the validator appears in
        // the BeaconState. This should be preserved, and not mutated
        // anywhere. This method is not designed to provide any filtering
        // and users should rely on `filter` to perform any filtering
        // they require.
        for (id, eth_validator) in validators.enumerate() {
            let exit_epoch = eth_validator.exit_epoch;
            let is_active = is_active_validator(eth_validator, exit_epoch);
            // TODO: figure out how to set this. This needs to be determined from
            // https://eth2book.info/capella/annotated-spec/#beaconblockbody
            let is_attested = true;

            let banshee_validator = Validator {
                id,
                shuffle_pos: 0, // TODO
                committee: 0,   // TODO: shuffle_pos/S::MAX_VALIDATORS_PER_COMMITTEE
                is_active,
                is_attested,
                effective_balance: eth_validator.effective_balance,
                activation_epoch: eth_validator.activation_epoch,
                exit_epoch,
                slashed: eth_validator.slashed,
                pubkey: eth_validator.public_key.as_ref().to_vec(),
                pubkey_uncompressed: vec![], // FIXME
            };
            banshee_validators.push(banshee_validator);
        }
        banshee_validators
    }

    fn committee_pos<S: Spec>(&self) -> usize {
        self.committee * S::MAX_VALIDATORS_PER_COMMITTEE
            + self.shuffle_pos % S::MAX_VALIDATORS_PER_COMMITTEE
    }
}

/// Orders validators by committees and pads to S::MAX_VALIDATORS_PER_COMMITTEE.
/// Returns a vector of (committee, validator) pairs.
/// Note: use returned `committee` instead `validator.committee`
///  as `DUMMY_VALIDATOR` may contain wrong committee index.
pub fn pad_to_max_per_committee<'a, S: Spec>(
    validators: impl Iterator<Item = &'a Validator>,
) -> Vec<(usize, &'a Validator)> {
    validators
        .into_iter()
        .group_by(|v| v.committee)
        .into_iter()
        .sorted_by_key(|(committee, _)| *committee)
        .take(S::MAX_COMMITTEES_PER_SLOT * S::SLOTS_PER_EPOCH)
        .flat_map(|(committee, vs)| {
            vs.map(move |v| (committee, v))
                .pad_using(S::MAX_VALIDATORS_PER_COMMITTEE, move |_| {
                    (committee, &DUMMY_VALIDATOR)
                })
        })
        .collect()
}

/// Validators table row assignments
#[derive(Clone, Debug)]
pub struct ValidatorRow<F: Field> {
    pub(crate) id: Value<F>,
    pub(crate) is_active: Value<F>,
    pub(crate) is_attested: Value<F>,
    pub(crate) balance: Value<F>,
    pub(crate) slashed: Value<F>,
    pub(crate) activation_epoch: Value<F>,
    pub(crate) exit_epoch: Value<F>,
    pub(crate) pubkey: [Value<F>; 2],
    pub(crate) attest_digits: Vec<Value<F>>,
    pub(crate) total_balance_acc: Value<F>,
}
