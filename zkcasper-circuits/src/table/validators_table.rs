use gadgets::util::{not, Expr};

use crate::{
    witness::{into_casper_entities, CasperEntityRow, Committee, Validator},
    VALIDATOR0_GINDEX,
};

use super::*;

/// The StateTable contains records of the state of the beacon chain.
#[derive(Clone, Debug)]
pub struct ValidatorsTable {
    /// ValidatorIndex when tag == 'Validator', CommitteeIndex otherwise.
    pub id: Column<Advice>,
    /// Validator or Committee
    pub tag: Column<Advice>,
    /// Signals whether validator is active during that epoch.
    pub is_active: Column<Advice>,
    /// Signals whether validator have attested during that epoch.
    pub is_attested: Column<Advice>,
    /// Effective balance of validator/committee.
    pub balance: Column<Advice>,
    /// Signals whether validator is slashed.
    pub slashed: Column<Advice>,
    /// Epoch when validator activated.
    pub activation_epoch: Column<Advice>,
    /// Epoch when validator exited.
    pub exit_epoch: Column<Advice>,
    /// Public key of a validator/committee.
    pub pubkey: [Column<Advice>; 2],
}

impl<F: Field> LookupTable<F> for ValidatorsTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.id.into(),
            self.tag.into(),
            self.is_active.into(),
            self.is_attested.into(),
            self.balance.into(),
            self.slashed.into(),
            self.activation_epoch.into(),
            self.exit_epoch.into(),
            self.pubkey[0].into(),
            self.pubkey[1].into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("id"),
            String::from("tag"),
            String::from("is_active"),
            String::from("is_attested"),
            String::from("balance"),
            String::from("slashed"),
            String::from("activation_epoch"),
            String::from("exit_epoch"),
            String::from("pubkey[0]"),
            String::from("pubkey[1]"),
        ]
    }
}

impl ValidatorsTable {
    /// Construct a new [`ValidatorsTable`]
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            id: meta.advice_column(),
            tag: meta.advice_column(),
            is_active: meta.advice_column(),
            is_attested: meta.advice_column(),
            balance: meta.advice_column_in(SecondPhase),
            slashed: meta.advice_column_in(SecondPhase),
            activation_epoch: meta.advice_column_in(SecondPhase),
            exit_epoch: meta.advice_column_in(SecondPhase),
            pubkey: [
                meta.advice_column_in(SecondPhase),
                meta.advice_column_in(SecondPhase),
            ],
        }
    }

    pub fn assign_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &CasperEntityRow<F>,
    ) -> Result<(), Error> {
        // println!("assigning row.ssz_rlc: {:?}", row.ssz_rlc);
        for (column, value) in [
            (self.id, row.id),
            (self.tag, row.tag),
            (self.is_active, row.is_active),
            (self.is_attested, row.is_attested),
            (self.balance, row.balance),
            (self.slashed, row.slashed),
            (self.activation_epoch, row.activation_epoch),
            (self.exit_epoch, row.exit_epoch),
            (self.pubkey[0], row.pubkey[0]),
            (self.pubkey[1], row.pubkey[1]),
        ] {
            region.assign_advice(
                || "assign state row on state table",
                column,
                offset,
                || value,
            )?;
        }
        Ok(())
    }

    /// Load the validators table into the circuit.
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        validators: &[Validator],
        committees: &[Committee],
        challenge: Value<F>,
    ) -> Result<(), Error> {
        let casper_entities = into_casper_entities(validators.iter(), committees.iter());

        layouter.assign_region(
            || "dev load state table",
            |mut region| {
                self.annotate_columns_in_region(&mut region);
                for (offset, row) in casper_entities
                    .iter()
                    .flat_map(|e| e.table_assignment(challenge))
                    .enumerate()
                {
                    self.assign_with_region(&mut region, offset, &row)?;
                }

                Ok(())
            },
        )
    }

    pub fn queries<F: Field>(&self, meta: &mut VirtualCells<'_, F>) -> ValidatorTableQueries<F> {
        ValidatorTableQueries {
            id: meta.query_advice(self.id, Rotation::cur()),
            tag: meta.query_advice(self.tag, Rotation::cur()),
            is_active: meta.query_advice(self.is_active, Rotation::cur()),
            is_attested: meta.query_advice(self.is_attested, Rotation::cur()),
            balance: meta.query_advice(self.balance, Rotation::cur()),
            slashed: meta.query_advice(self.slashed, Rotation::cur()),
            activation_epoch: meta.query_advice(self.activation_epoch, Rotation::cur()),
            exit_epoch: meta.query_advice(self.exit_epoch, Rotation::cur()),
            pubkey_rlc: [
                meta.query_advice(self.pubkey[0], Rotation::cur()),
                meta.query_advice(self.pubkey[1], Rotation::cur()),
            ],
        }
    }
}

#[derive(Clone)]
pub struct ValidatorTableQueries<F: Field> {
    pub id: Expression<F>,
    pub tag: Expression<F>,
    pub is_active: Expression<F>,
    pub is_attested: Expression<F>,
    pub balance: Expression<F>,
    pub activation_epoch: Expression<F>,
    pub exit_epoch: Expression<F>,
    pub slashed: Expression<F>,
    pub pubkey_rlc: [Expression<F>; 2],
}

impl<F: Field> ValidatorTableQueries<F> {
    pub fn is_validator(&self) -> Expression<F> {
        self.tag.clone()
    }

    pub fn is_committee(&self) -> Expression<F> {
        not::expr(self.tag.clone())
    }

    pub fn id(&self) -> Expression<F> {
        self.id.clone()
    }

    pub fn tag(&self) -> Expression<F> {
        self.tag.clone()
    }

    pub fn is_active(&self) -> Expression<F> {
        self.is_active.clone()
    }

    pub fn is_attested(&self) -> Expression<F> {
        self.is_attested.clone()
    }

    pub fn balance_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id())
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
        (VALIDATOR0_GINDEX.expr() + self.id()) * 2u64.pow(3).expr() + 3.expr()
    }

    pub fn activation_epoch_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id()) * 2u64.pow(3).expr() + 5.expr() // skip activationEligibilityEpoch
    }

    pub fn exit_epoch_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id()) * 2u64.pow(3).expr() + 6.expr()
    }

    pub fn pubkey_lo_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id()) * 2u64.pow(4).expr() // 4 levels deeper
    }

    pub fn pubkey_hi_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id()) * 2u64.pow(4).expr() + 1.expr()
    }
}
