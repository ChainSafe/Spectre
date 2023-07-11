use std::vec;

use banshee_preprocessor::util::pad_to_ssz_chunk;
use eth_types::Field;
use ethereum_consensus::phase0::is_active_validator;
use gadgets::util::rlc;

use halo2_proofs::circuit::Value;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

/// Beacon validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    pub id: usize,
    pub committee: usize,
    pub is_active: bool,
    pub is_attested: bool,
    pub effective_balance: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
    pub slashed: bool,
    pub pubkey: Vec<u8>,
}

/// Committee
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Committee {
    pub id: usize,
    pub accumulated_balance: u64,
    pub aggregated_pubkey: Vec<u8>,
}

impl Validator {
    pub(crate) fn table_assignment<F: Field>(
        &self,
        randomness: Value<F>,
    ) -> Vec<CasperEntityRow<F>> {
        vec![CasperEntityRow {
            id: Value::known(F::from(self.id as u64)),
            tag: Value::known(F::one()),
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
            row_type: CasperTag::Validator,
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
            // TODO: how do I set this?
            let committee = 0;
            let banshee_validator = Validator {
                id,
                committee,
                is_active,
                is_attested,
                effective_balance: eth_validator.effective_balance,
                activation_epoch: eth_validator.activation_epoch,
                exit_epoch,
                slashed: eth_validator.slashed,
                pubkey: eth_validator.public_key.as_ref().to_vec(),
            };
            banshee_validators.push(banshee_validator);
        }
        banshee_validators
    }
}

impl Committee {
    pub(crate) fn table_assignment<F: Field>(
        &self,
        _randomness: Value<F>,
    ) -> Vec<CasperEntityRow<F>> {
        vec![CasperEntityRow {
            id: Value::known(F::from(self.id as u64)),
            tag: Value::known(F::zero()),
            is_active: Value::known(F::zero()),
            is_attested: Value::known(F::zero()),
            balance: Value::known(F::from(self.accumulated_balance)),
            slashed: Value::known(F::zero()),
            activation_epoch: Value::known(F::zero()),
            exit_epoch: Value::known(F::zero()),
            pubkey: [Value::known(F::zero()), Value::known(F::zero())], // TODO:
            // .chain(decompose_bigint_option(Value::known(self.aggregated_pubkey.x), 7, 55).into_iter().map(|limb| new_state_row(FieldTag::PubKeyAffineX, 0, limb)))
            // .chain(decompose_bigint_option(Value::known(self.aggregated_pubkey.y), 7, 55).into_iter().map(|limb| new_state_row(FieldTag::PubKeyAffineX, 0, limb)))
            row_type: CasperTag::Committee,
        }]
    }
}

pub enum CasperEntity<'a> {
    Validator(&'a Validator),
    Committee(&'a Committee),
}

impl<'a> CasperEntity<'a> {
    pub fn table_assignment<F: Field>(&self, randomness: Value<F>) -> Vec<CasperEntityRow<F>> {
        match self {
            CasperEntity::Validator(v) => v.table_assignment(randomness),
            CasperEntity::Committee(c) => c.table_assignment(randomness),
        }
    }
}

pub fn into_casper_entities<'a>(
    validators: impl Iterator<Item = &'a Validator>,
    committees: impl Iterator<Item = &'a Committee>,
) -> Vec<CasperEntity<'a>> {
    let mut casper_entity = vec![];

    let mut committees: Vec<&Committee> = committees.collect();

    let binding = validators.into_iter().group_by(|v| v.committee);
    let validators_per_committees = binding
        .into_iter()
        .sorted_by_key(|(committee, _vs)| *committee)
        .map(|(committee, vs)| (committee, vs));

    assert_eq!(
        validators_per_committees.len(),
        committees.len(),
        "number of given committees not equal to number of committees of given validators",
    );

    committees.sort_by_key(|v| v.id);

    for (comm_idx, validators) in validators_per_committees {
        casper_entity.extend(validators.map(CasperEntity::Validator));
        casper_entity.push(CasperEntity::Committee(committees[comm_idx]));
    }

    casper_entity
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, EnumIter, Hash)]
pub enum CasperTag {
    Validator = 0,
    Committee,
}

/// State table row assignment
#[derive(Clone, Debug)]
pub struct CasperEntityRow<F: Field> {
    pub(crate) row_type: CasperTag,
    pub(crate) id: Value<F>,
    pub(crate) tag: Value<F>,
    pub(crate) is_active: Value<F>,
    pub(crate) is_attested: Value<F>,
    pub(crate) balance: Value<F>,
    pub(crate) slashed: Value<F>,
    pub(crate) activation_epoch: Value<F>,
    pub(crate) exit_epoch: Value<F>,
    pub(crate) pubkey: [Value<F>; 2],
}
