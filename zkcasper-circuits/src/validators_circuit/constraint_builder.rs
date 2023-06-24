use super::cell_manager::*;
use crate::{
    gadget::LtGadget,
    util::{Cell, CellType, ConstrainBuilderCommon, Constraint, Expr, Lookup},
    witness::{StateEntry, StateRow, StateTag},
    N_BYTES_U64,
};
use eth_types::Field;
use gadgets::binary_number::BinaryNumberConfig;
use halo2_proofs::{circuit::Region, plonk::Expression};
use strum::IntoEnumIterator;

#[derive(Clone, Debug)]
pub struct ConstraintBuilder<F: Field> {
    pub constraints: Vec<Constraint<F>>,
    lookups: Vec<Lookup<F>>,
    condition: Expression<F>,
    pub(crate) cell_manager: CellManager<F>,
    target_gte_activation: Option<LtGadget<F, N_BYTES_U64>>,
    target_lt_exit: Option<LtGadget<F, N_BYTES_U64>>,
}

impl<F: Field> ConstraintBuilder<F> {
    pub fn new(cell_manager: CellManager<F>) -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],
            condition: 1.expr(),
            cell_manager,
            target_gte_activation: None,
            target_lt_exit: None,
        }
    }

    pub fn gate(&self, condition: Expression<F>) -> Vec<(&'static str, Expression<F>)> {
        self.constraints
            .iter()
            .cloned()
            .map(|(name, expression)| (name, condition.clone() * expression))
            .collect()
    }

    pub fn lookups(&self) -> Vec<Lookup<F>> {
        self.lookups.clone()
    }

    pub fn build(&mut self, q: &Queries<F>) {
        self.condition(q.tag_matches(StateTag::Validator), |cb| {
            cb.build_validator_constraints(q)
        });

        self.condition(q.tag_matches(StateTag::Committee), |cb| {
            cb.build_committee_constraints(q)
        });
    }

    fn build_validator_constraints(&mut self, q: &Queries<F>) {
        self.require_boolean("is_active is boolean", q.is_active());
        self.require_boolean("is_attested is boolean", q.is_attested());
        self.require_boolean("slashed is boolean", q.slashed());

        self.condition(q.is_attested(), |cb| {
            cb.require_true("is_active is true when is_attested is true", q.is_active());
        });

        let target_gte_activation =
            LtGadget::<_, N_BYTES_U64>::construct(self, q.activation_epoch(), q.next_epoch());
        let target_lt_exit =
            LtGadget::<_, N_BYTES_U64>::construct(self, q.target_epoch(), q.exit_epoch());

        self.condition(q.is_active(), |cb| {
            cb.require_boolean("slashed is false for active validators", q.slashed());

            cb.require_true(
                "activation_epoch <= target_epoch > exit_epoch for active validators",
                target_gte_activation.expr() * target_lt_exit.expr(),
            )
        });

        self.target_gte_activation.insert(target_gte_activation);
        self.target_lt_exit.insert(target_lt_exit);
    }

    fn build_committee_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("is_active is 0 for committees", q.is_active());
        self.require_boolean("is_attested is 0 for committees", q.is_attested());
        self.require_boolean("slashed is 0 for committees", q.slashed());
    }

    fn add_lookup(&mut self, name: &'static str, lookup: Vec<(Expression<F>, Expression<F>)>) {
        let mut lookup = lookup;
        for (expression, _) in lookup.iter_mut() {
            *expression = expression.clone() * self.condition.clone();
        }
        self.lookups.push((name, lookup));
    }

    fn condition(&mut self, condition: Expression<F>, build: impl FnOnce(&mut Self)) {
        let original_condition = self.condition.clone();
        self.condition = self.condition.clone() * condition;
        build(self);
        self.condition = original_condition;
    }

    pub fn assign_with_region(
        &self,
        region: &mut Region<F>,
        offset: usize,
        data: &StateEntry,
        target_epoch: u64,
    ) {
        let target_gte_activation = self
            .target_gte_activation
            .as_ref()
            .expect("target_gte_activation gadget is expected");
        let target_lt_exit = self
            .target_lt_exit
            .as_ref()
            .expect("target_lt_exited gadget is expected");

        match data {
            StateEntry::Validator {
                activation_epoch,
                exit_epoch,
                ..
            } => {
                target_gte_activation.assign(
                    region,
                    offset,
                    F::from(*activation_epoch),
                    F::from(target_epoch + 1),
                );
                target_lt_exit.assign(
                    region,
                    offset,
                    F::from(target_epoch),
                    F::from(*exit_epoch),
                );
            }
            StateEntry::Committee { .. } => {}
        }
    }
}

impl<F: Field> ConstrainBuilderCommon<F> for ConstraintBuilder<F> {
    fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.constraints
            .push((name, self.condition.clone() * constraint));
    }

    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        self.cell_manager.query_cells(cell_type, count)
    }
}

#[derive(Clone)]
pub struct Queries<F: Field> {
    pub selector: Expression<F>,
    pub target_epoch: Expression<F>,
    pub state_table: StateQueries<F>,
    pub tag_bits: [Expression<F>; 3],
}

#[derive(Clone)]
pub struct StateQueries<F: Field> {
    pub id: Expression<F>,
    pub order: Expression<F>,
    pub tag: Expression<F>,
    pub is_active: Expression<F>,
    pub is_attested: Expression<F>,
    pub balance: Expression<F>,
    pub activation_epoch: Expression<F>,
    pub exit_epoch: Expression<F>,
    pub slashed: Expression<F>,
    pub pubkey_lo: Expression<F>,
    pub pubkey_hi: Expression<F>,
    pub field_tag: Expression<F>,
    pub index: Expression<F>,
    pub g_index: Expression<F>,
    pub value: Expression<F>,
}

impl<F: Field> Queries<F> {
    fn selector(&self) -> Expression<F> {
        self.selector.clone()
    }

    fn target_epoch(&self) -> Expression<F> {
        self.target_epoch.clone()
    }

    fn next_epoch(&self) -> Expression<F> {
        self.target_epoch.clone() + 1.expr()
    }

    fn id(&self) -> Expression<F> {
        self.state_table.id.clone()
    }

    fn tag(&self) -> Expression<F> {
        self.state_table.tag.clone()
    }

    fn is_active(&self) -> Expression<F> {
        self.state_table.is_active.clone()
    }

    fn is_attested(&self) -> Expression<F> {
        self.state_table.is_attested.clone()
    }

    fn balance(&self) -> Expression<F> {
        self.state_table.balance.clone()
    }

    fn activation_epoch(&self) -> Expression<F> {
        self.state_table.activation_epoch.clone()
    }

    fn exit_epoch(&self) -> Expression<F> {
        self.state_table.exit_epoch.clone()
    }

    fn slashed(&self) -> Expression<F> {
        self.state_table.slashed.clone()
    }

    fn pubkey_lo(&self) -> Expression<F> {
        self.state_table.pubkey_lo.clone()
    }

    fn pubkey_hi(&self) -> Expression<F> {
        self.state_table.pubkey_hi.clone()
    }

    fn tag_matches(&self, tag: StateTag) -> Expression<F> {
        BinaryNumberConfig::<StateTag, 3>::value_equals_expr(tag, self.tag_bits.clone())
    }
}
