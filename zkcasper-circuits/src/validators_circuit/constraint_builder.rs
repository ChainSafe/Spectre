use super::cell_manager::*;
use crate::{
    gadget::LtGadget,
    table::{state_table::StateTables, validators_table::ValidatorTableQueries},
    util::{Cell, CellType, ConstrainBuilderCommon, Constraint, Expr, Lookup},
    witness::{CasperEntity, CasperEntityRow, Committee, StateTag, Validator},
    N_BYTES_U64,
};
use eth_types::Field;
use gadgets::{binary_number::BinaryNumberConfig, util::not};
use halo2_proofs::{circuit::Region, plonk::Expression};
use strum::IntoEnumIterator;

pub struct ConstraintBuilder<'a, F: Field> {
    pub constraints: Vec<Constraint<F>>,
    lookups: Vec<Lookup<F>>,
    pub max_degree: usize,
    condition: Expression<F>,
    pub(crate) cell_manager: &'a mut CellManager<F>,
}

impl<'a, F: Field> ConstraintBuilder<'a, F> {
    pub fn new(
        cell_manager: &'a mut CellManager<F>,
        max_degree: usize,
        selector: Expression<F>,
    ) -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],
            max_degree,
            condition: selector,
            cell_manager,
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

    pub fn add_lookup(&mut self, name: &'static str, lookup: Vec<(Expression<F>, Expression<F>)>) {
        let mut lookup = lookup;
        for (expression, _) in lookup.iter_mut() {
            *expression = expression.clone() * self.condition.clone();
        }
        self.lookups.push((name, lookup));
    }

    fn validate_degree(&self, degree: usize, name: &'static str) {
        if self.max_degree > 0 {
            debug_assert!(
                degree <= self.max_degree,
                "Expression {} degree too high: {} > {}",
                name,
                degree,
                self.max_degree,
            );
        }
    }
}

impl<'a, F: Field> ConstrainBuilderCommon<F> for ConstraintBuilder<'a, F> {
    fn condition<R>(&mut self, condition: Expression<F>, build: impl FnOnce(&mut Self) -> R) -> R {
        let original_condition = self.condition.clone();
        self.condition = self.condition.clone() * condition;
        let res = build(self);
        self.condition = original_condition;
        res
    }

    fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.validate_degree(constraint.degree(), name);
        self.constraints
            .push((name, self.condition.clone() * constraint));
    }

    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        self.cell_manager.query_cells(cell_type, count)
    }
}

#[derive(Clone)]
pub struct Queries<F: Field> {
    pub q_enabled: Expression<F>,
    pub target_epoch: Expression<F>,
    pub table: ValidatorTableQueries<F>,
}

impl<F: Field> Queries<F> {
    pub fn selector(&self) -> Expression<F> {
        self.q_enabled.clone()
    }

    pub fn target_epoch(&self) -> Expression<F> {
        self.target_epoch.clone()
    }

    pub fn next_epoch(&self) -> Expression<F> {
        self.target_epoch.clone() + 1.expr()
    }
}
