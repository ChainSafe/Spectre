use super::cell_manager::*;
use crate::{
    state_circuit::*,
    util::{Cell, CellType, ConstrainBuilderCommon, Constraint, Expr, Lookup},
};
use eth_types::Field;
use halo2_proofs::plonk::Expression;

pub struct ConstraintBuilder<F: Field> {
    pub constraints: Vec<Constraint<F>>,
    lookups: Vec<Lookup<F>>,
    condition: Expression<F>,
}

impl<F: Field> ConstraintBuilder<F> {
    pub fn new() -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],
            condition: 1.expr(),
        }
    }

    pub fn gate(&self, condition: Expression<F>) -> Vec<(&'static str, Expression<F>)> {
        self.constraints
            .iter()
            .cloned()
            .map(|(name, expression)| (name, condition.clone() * expression))
            .collect()
    }
}

impl<F: Field> ConstrainBuilderCommon<F> for ConstraintBuilder<F> {
    fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.constraints
            .push((name, self.condition.clone() * constraint));
    }

    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        // self.cell_manager.query_cells(cell_type, count)
        unimplemented!()
    }

    fn condition<R>(
        &mut self,
        condition: Expression<F>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        let original_condition = self.condition.clone();
        self.condition = self.condition.clone() * condition;
        let res = constraint(self);
        self.condition = original_condition;
        res
    }
}
