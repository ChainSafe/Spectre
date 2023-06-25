use std::vec;

use banshee_preprocessor::util::pad_to_ssz_chunk;
use eth_types::Field;
use gadgets::impl_expr;
use gadgets::util::rlc;
use halo2_base::utils::decompose_bigint_option;
use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::plonk::Expression;
use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use super::ValueRLC;

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
            balance: ValueRLC::new(
                Value::known(F::from(self.effective_balance as u64)),
                randomness.map(|rnd| {
                    rlc::value(
                        &pad_to_ssz_chunk(&self.effective_balance.to_le_bytes()),
                        rnd,
                    )
                }),
            ),
            slashed: ValueRLC::new(
                Value::known(F::from(self.slashed as u64)),
                randomness.map(|rnd| rlc::value(&pad_to_ssz_chunk(&[self.slashed as u8]), rnd)),
            ),
            activation_epoch: ValueRLC::new(
                Value::known(F::from(self.activation_epoch as u64)),
                randomness.map(|rnd| {
                    rlc::value(&pad_to_ssz_chunk(&self.activation_epoch.to_le_bytes()), rnd)
                }),
            ),
            exit_epoch: ValueRLC::new(
                Value::known(F::from(self.exit_epoch as u64)),
                randomness
                    .map(|rnd| rlc::value(&pad_to_ssz_chunk(&self.exit_epoch.to_le_bytes()), rnd)),
            ),
            pubkey: [
                randomness.map(|rnd| rlc::value(&self.pubkey[0..32], rnd)),
                randomness.map(|rnd| rlc::value(&pad_to_ssz_chunk(&self.pubkey[32..48]), rnd)),
            ],
        }]
    }
}

impl Committee {
    pub(crate) fn table_assignment<F: Field>(
        &self,
        randomness: Value<F>,
    ) -> Vec<CasperEntityRow<F>> {
        vec![CasperEntityRow {
            id: Value::known(F::from(self.id as u64)),
            tag: Value::known(F::zero()),
            is_active: Value::known(F::zero()),
            is_attested: Value::known(F::zero()),
            balance: ValueRLC::new(
                Value::known(F::from(self.accumulated_balance as u64)),
                randomness.map(|rnd| {
                    rlc::value(
                        &pad_to_ssz_chunk(&self.accumulated_balance.to_le_bytes()),
                        rnd,
                    )
                }),
            ),
            slashed: ValueRLC::empty(),
            activation_epoch: ValueRLC::empty(),
            exit_epoch: ValueRLC::empty(),
            pubkey: [Value::known(F::zero()), Value::known(F::zero())], // TODO:
                                                                        // .chain(decompose_bigint_option(Value::known(self.aggregated_pubkey.x), 7, 55).into_iter().map(|limb| new_state_row(FieldTag::PubKeyAffineX, 0, limb)))
                                                                        // .chain(decompose_bigint_option(Value::known(self.aggregated_pubkey.y), 7, 55).into_iter().map(|limb| new_state_row(FieldTag::PubKeyAffineX, 0, limb)))
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

    let groups = validators.group_by(|v| v.committee);
    let validators_per_committees = {
        groups
            .into_iter()
            .sorted_by_key(|(committee, vs)| *committee)
            .map(|(_, vs)| vs.collect_vec())
    };

    assert_eq!(
        validators_per_committees.len(),
        committees.len(),
        "number of given committees not equal to number of committees of given validators",
    );

    committees.sort_by_key(|v| v.id);

    for (comm_idx, validators) in validators_per_committees.enumerate() {
        casper_entity.extend(validators.into_iter().map(|v| CasperEntity::Validator(v)));
        casper_entity.push(CasperEntity::Committee(committees[comm_idx]));
    }

    casper_entity
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, EnumIter, Hash)]
pub enum StateTag {
    Validator = 0,
    Committee,
}
impl_expr!(StateTag);

impl From<StateTag> for usize {
    fn from(value: StateTag) -> usize {
        value as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldTag {
    EffectiveBalance = 0,
    ActivationEpoch,
    ExitEpoch,
    Slashed,
    PubKeyRLC,
    PubKeyAffineX,
    PubKeyAffineY,
}
impl_expr!(FieldTag);

/// State table row assignment
#[derive(Clone, Debug)]
pub struct CasperEntityRow<F: Field> {
    pub(crate) id: Value<F>,
    pub(crate) tag: Value<F>,
    pub(crate) is_active: Value<F>,
    pub(crate) is_attested: Value<F>,
    pub(crate) balance: ValueRLC<F>,
    pub(crate) slashed: ValueRLC<F>,
    pub(crate) activation_epoch: ValueRLC<F>,
    pub(crate) exit_epoch: ValueRLC<F>,
    pub(crate) pubkey: [Value<F>; 2],
}
