use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::Expression;

use super::{Cell, CellType};

pub type Constraint<F> = (&'static str, Expression<F>);
pub type Lookup<F> = (&'static str, Vec<(Expression<F>, Expression<F>)>);

pub(crate) trait ConstrainBuilderCommon<F: Field> {
    fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>);

    fn require_zero(&mut self, name: &'static str, constraint: Expression<F>) {
        self.add_constraint(name, constraint);
    }

    fn require_equal(&mut self, name: &'static str, lhs: Expression<F>, rhs: Expression<F>) {
        self.add_constraint(name, lhs - rhs);
    }

    fn require_boolean(&mut self, name: &'static str, value: Expression<F>) {
        self.add_constraint(name, value.clone() * (1.expr() - value));
    }

    fn require_true(&mut self, name: &'static str, e: Expression<F>) {
        self.require_equal(name, e, 1.expr());
    }

    fn require_in_set(
        &mut self,
        name: &'static str,
        value: Expression<F>,
        set: Vec<Expression<F>>,
    ) {
        self.add_constraint(
            name,
            set.iter()
                .fold(1.expr(), |acc, item| acc * (value.clone() - item.clone())),
        );
    }

    fn add_constraints(&mut self, constraints: Vec<(&'static str, Expression<F>)>) {
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }

    fn query_bool(&mut self) -> Cell<F> {
        let cell = self.query_cell();
        self.require_boolean("Constrain cell to be a bool", cell.expr());
        cell
    }

    fn query_bytes<const N: usize>(&mut self) -> [Cell<F>; N] {
        self.query_bytes_dyn(N).try_into().unwrap()
    }

    fn query_bytes_dyn(&mut self, count: usize) -> Vec<Cell<F>> {
        self.query_cells(CellType::LookupByte, count)
    }

    fn query_cell(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePhase1)
    }

    fn query_cell_phase2(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePhase2)
    }

    fn query_copy_cell(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePermutation)
    }

    fn query_cell_with_type(&mut self, cell_type: CellType) -> Cell<F> {
        self.query_cells(cell_type, 1).first().unwrap().clone()
    }

    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>>;
}
