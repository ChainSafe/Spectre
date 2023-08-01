use std::marker::PhantomData;

use gadgets::util::{not, Expr};
use halo2_proofs::circuit::Cell;

use crate::{
    validators_circuit::ValidatorsCircuitOutput,
    witness::{pad_to_max_per_committee, Validator, ValidatorRow},
};

use super::*;
use eth_types::Spec;

/// The StateTable contains records of the state of the beacon chain.
#[derive(Clone, Debug)]
pub struct ValidatorsTable {
    /// ValidatorIndex when tag == 'Validator'.
    pub id: Column<Advice>,
    /// Signals whether validator is active during that epoch.
    pub is_active: Column<Advice>,
    /// Signals whether validator have attested during that epoch.
    pub attest_bit: Column<Advice>,
    /// Effective balance of validator.
    pub balance: Column<Advice>,
    /// Signals whether validator is slashed.
    pub slashed: Column<Advice>,
    /// Epoch when validator activated.
    pub activation_epoch: Column<Advice>,
    /// Epoch when validator exited.
    pub exit_epoch: Column<Advice>,
    /// Public key of a validator/committee.
    pub pubkey: [Column<Advice>; 2],
    /// Commitments to `is_attested` of validator per committee. Length = `Spec::attest_digits_len::<F>()`
    pub attest_digits: Vec<Column<Advice>>,
    /// Accumulated balance for *all* committees.
    pub total_balance_acc: Column<Advice>,
}

impl<F: Field> LookupTable<F> for ValidatorsTable {
    fn columns(&self) -> Vec<Column<Any>> {
        itertools::chain!(
            vec![
                self.id.into(),
                self.is_active.into(),
                self.attest_bit.into(),
                self.balance.into(),
                self.slashed.into(),
                self.activation_epoch.into(),
                self.exit_epoch.into(),
                self.pubkey[0].into(),
                self.pubkey[1].into(),
                self.total_balance_acc.into(),
            ],
            self.attest_digits.iter().map(|c| (*c).into()),
        )
        .collect()
    }

    fn annotations(&self) -> Vec<String> {
        itertools::chain!(
            vec![
                String::from("id"),
                String::from("is_active"),
                String::from("is_attested"),
                String::from("balance"),
                String::from("slashed"),
                String::from("activation_epoch"),
                String::from("exit_epoch"),
                String::from("pubkey[0]"),
                String::from("pubkey[1]"),
                String::from("total_balance_acc"),
            ],
            (0..self.attest_digits.len()).map(|i| format!("attest_digits[{i}]")),
        )
        .collect()
    }
}

impl ValidatorsTable {
    /// Construct a new [`ValidatorsTable`]
    pub fn construct<S: Spec, F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let config = Self {
            id: meta.advice_column(),
            is_active: meta.advice_column(),
            attest_bit: meta.advice_column(),
            balance: meta.advice_column_in(SecondPhase),
            slashed: meta.advice_column_in(SecondPhase),
            activation_epoch: meta.advice_column_in(SecondPhase),
            exit_epoch: meta.advice_column_in(SecondPhase),
            pubkey: [
                meta.advice_column_in(SecondPhase),
                meta.advice_column_in(SecondPhase),
            ],
            attest_digits: (0..S::attest_digits_len::<F>())
                .map(|_| meta.advice_column())
                .collect(),
            total_balance_acc: meta.advice_column(),
        };

        itertools::chain![&config.pubkey, &config.attest_digits,]
            .for_each(|&col| meta.enable_equality(col));

        config
    }

    pub fn assign_with_region<S: Spec, F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &ValidatorRow<F>,
        pubkey_cells: &mut Vec<[Cell; 2]>,
        attest_digits_cells: &mut Vec<Vec<Cell>>,
    ) -> Result<(), Error> {
        let [attest_bit, pubkey_lo, pubkey_hi, ..] = [
            (self.attest_bit, row.is_attested),
            (self.pubkey[0], row.pubkey[0]),
            (self.pubkey[1], row.pubkey[1]),
            (self.id, row.id),
            (self.is_active, row.is_active),
            (self.balance, row.balance),
            (self.slashed, row.slashed),
            (self.activation_epoch, row.activation_epoch),
            (self.exit_epoch, row.exit_epoch),
            (self.total_balance_acc, row.total_balance_acc),
        ]
        .map(|(column, value)| {
            region
                .assign_advice(
                    || "assign validator row into validators table",
                    column,
                    offset,
                    || value,
                )
                .expect("validator field assign")
                .cell()
        });

        let attest_digit_cells = self
            .attest_digits
            .iter()
            .zip(row.attest_digits.iter().copied())
            .map(|(column, value)| {
                region
                    .assign_advice(
                        || "assign attest digit into validators table",
                        *column,
                        offset,
                        || value,
                    )
                    .expect("attest digit assign")
                    .cell()
            })
            .collect();

        pubkey_cells.push([pubkey_lo, pubkey_hi]);
        if (offset + 1) % S::MAX_VALIDATORS_PER_COMMITTEE == 0 {
            attest_digits_cells.push(attest_digit_cells);
        }

        Ok(())
    }

    /// Load the validators table into the circuit.
    pub fn dev_load<S: Spec, F: Field>(
        &mut self,
        layouter: &mut impl Layouter<F>,
        validators: &[Validator],
        challenge: Value<F>,
    ) -> Result<ValidatorsCircuitOutput, Error> {
        let padded_validators = pad_to_max_per_committee::<S>(validators.iter());
        let num_committees = padded_validators.len() / S::MAX_VALIDATORS_PER_COMMITTEE;

        layouter.assign_region(
            || "dev load validators table",
            |mut region| {
                self.annotate_columns_in_region(&mut region);
                let mut committees_balances = vec![0; num_committees];
                let mut attest_digits = vec![vec![0; S::attest_digits_len::<F>()]; num_committees];
                let mut pubkey_cells = vec![];
                let mut attest_digits_cells = vec![];
                for (offset, row) in padded_validators
                    .iter()
                    .flat_map(|(committee, v)| {
                        v.table_assignment::<S, F>(
                            *committee,
                            challenge,
                            &mut attest_digits,
                            &mut committees_balances,
                        )
                    })
                    .enumerate()
                {
                    self.assign_with_region::<S, F>(
                        &mut region,
                        offset,
                        &row,
                        &mut pubkey_cells,
                        &mut attest_digits_cells,
                    )?;
                }

                Ok(ValidatorsCircuitOutput {
                    pubkey_cells,
                    attest_digits_cells,
                })
            },
        )
    }

    pub fn queries<S: Spec, F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
    ) -> ValidatorTableQueries<S, F> {
        ValidatorTableQueries {
            id: meta.query_advice(self.id, Rotation::cur()),
            is_active: meta.query_advice(self.is_active, Rotation::cur()),
            attest_bit: meta.query_advice(self.attest_bit, Rotation::cur()),
            balance: meta.query_advice(self.balance, Rotation::cur()),
            slashed: meta.query_advice(self.slashed, Rotation::cur()),
            activation_epoch: meta.query_advice(self.activation_epoch, Rotation::cur()),
            exit_epoch: meta.query_advice(self.exit_epoch, Rotation::cur()),
            pubkey_rlc: [
                meta.query_advice(self.pubkey[0], Rotation::cur()),
                meta.query_advice(self.pubkey[1], Rotation::cur()),
            ],
            balance_acc: meta.query_advice(self.total_balance_acc, Rotation::cur()),
            balance_acc_prev: meta.query_advice(self.total_balance_acc, Rotation::prev()),
            attest_digits: self
                .attest_digits
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect(),
            attest_digits_prev: self
                .attest_digits
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::prev()))
                .collect(),
            _spec: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct ValidatorTableQueries<S: Spec, F: Field> {
    id: Expression<F>,
    is_active: Expression<F>,
    attest_bit: Expression<F>,
    balance: Expression<F>,
    activation_epoch: Expression<F>,
    exit_epoch: Expression<F>,
    slashed: Expression<F>,
    pubkey_rlc: [Expression<F>; 2],
    balance_acc: Expression<F>,
    balance_acc_prev: Expression<F>,
    attest_digits: Vec<Expression<F>>,
    attest_digits_prev: Vec<Expression<F>>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> ValidatorTableQueries<S, F> {
    pub fn id(&self) -> Expression<F> {
        self.id.clone()
    }

    pub fn is_active(&self) -> Expression<F> {
        self.is_active.clone()
    }

    pub fn attest_bit(&self) -> Expression<F> {
        self.attest_bit.clone()
    }

    pub fn balance_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_GINDEX.expr() + self.id())
            * 2u64.pow(3).expr() // 3 levels deeper
            + 2.expr() // skip pubkeyRoot and withdrawalCredentials
    }

    pub fn balance(&self) -> Expression<F> {
        self.balance.clone()
    }

    pub fn slashed(&self) -> Expression<F> {
        self.slashed.clone()
    }

    pub fn activation_epoch(&self) -> Expression<F> {
        self.activation_epoch.clone()
    }

    pub fn exit_epoch(&self) -> Expression<F> {
        self.exit_epoch.clone()
    }

    pub fn pubkey_lo_rlc(&self) -> Expression<F> {
        self.pubkey_rlc[0].clone()
    }

    pub fn pubkey_hi_rlc(&self) -> Expression<F> {
        self.pubkey_rlc[1].clone()
    }

    pub fn slashed_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_GINDEX.expr() + self.id()) * 2u64.pow(3).expr() + 3.expr()
    }

    pub fn activation_epoch_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_GINDEX.expr() + self.id()) * 2u64.pow(3).expr() + 5.expr()
        // skip activationEligibilityEpoch
    }

    pub fn exit_epoch_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_GINDEX.expr() + self.id()) * 2u64.pow(3).expr() + 6.expr()
    }

    pub fn pubkey_lo_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_GINDEX.expr() + self.id()) * 2u64.pow(4).expr() // 4 levels deeper
    }

    pub fn pubkey_hi_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_GINDEX.expr() + self.id()) * 2u64.pow(4).expr() + 1.expr()
    }

    pub fn balance_acc(&self) -> Expression<F> {
        self.balance_acc.clone()
    }

    pub fn balance_acc_prev(&self) -> Expression<F> {
        self.balance_acc_prev.clone()
    }

    pub fn attest_digit(&self, index: usize) -> Expression<F> {
        self.attest_digits[index].clone()
    }

    pub fn attest_digit_prev(&self, index: usize) -> Expression<F> {
        self.attest_digits_prev[index].clone()
    }
}
