use super::cell_manager::*;
use crate::{
    table::validators_table::ValidatorTableQueries,
    util::{Cell, CellType, ConstrainBuilderCommon, Constraint, Expr, Lookup},
};
use eth_types::{Field, Spec};

use halo2_proofs::plonk::Expression;

pub struct ConstraintBuilder<'a, F: Field> {
    pub constraints: Vec<Constraint<F>>,
    lookups: Vec<Lookup<F>>,
    pub max_degree: usize,
    condition: Option<Expression<F>>,
    pub(crate) cell_manager: &'a mut CellManager<F>,
}

impl<'a, F: Field> ConstraintBuilder<'a, F> {
    pub fn new(cell_manager: &'a mut CellManager<F>, max_degree: usize) -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],
            max_degree,
            cell_manager,
            condition: None,
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
            *expression = match &self.condition {
                Some(condition) => condition.clone() * expression.clone(),
                None => expression.clone(),
            };
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
        self.condition.insert(
            self.condition
                .clone()
                .map_or(condition.clone(), |inner| inner * condition),
        );
        let res = build(self);
        self.condition = original_condition;
        res
    }

    fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        let constraint = match &self.condition {
            Some(condition) => condition.clone() * constraint,
            None => constraint,
        };
        self.validate_degree(constraint.degree(), name);
        self.constraints.push((name, constraint));
    }

    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        self.cell_manager.query_cells(cell_type, count)
    }
}

#[derive(Clone)]
pub struct Queries<S: Spec, F: Field> {
    pub q_enabled: Expression<F>,
    pub q_first: Expression<F>,
    pub q_last: Expression<F>,
    pub q_attest_digits: Vec<Expression<F>>,
    pub q_committee_first: Expression<F>,
    pub target_epoch: Expression<F>,
    pub table: ValidatorTableQueries<S, F>,
}

impl<S: Spec, F: Field> Queries<S, F> {
    pub fn q_enabled(&self) -> Expression<F> {
        self.q_enabled.clone()
    }

    pub fn q_first(&self) -> Expression<F> {
        self.q_first.clone()
    }

    pub fn q_last(&self) -> Expression<F> {
        self.q_last.clone()
    }

    pub fn q_attest_digits(&self, i: usize) -> Expression<F> {
        self.q_attest_digits[i].clone()
    }

    pub fn q_committee_first(&self) -> Expression<F> {
        self.q_committee_first.clone()
    }

    pub fn target_epoch(&self) -> Expression<F> {
        self.target_epoch.clone()
    }

    pub fn next_epoch(&self) -> Expression<F> {
        self.target_epoch.clone() + 1.expr()
    }
}
