use crate::{
    state_circuit::TREE_LEVEL_AUX_COLUMNS,
    util::{query_expression, Cell, CellType, Challenges, Expr},
    witness::*,
};
use eth_types::*;
use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
};

#[derive(Clone, Debug)]
pub(crate) struct CellColumn {
    pub(crate) index: usize,
    pub(crate) cell_type: CellType,
    pub(crate) height: usize,
}

#[derive(Clone, Debug)]
pub struct CellManager<F> {
    width: usize,
    height: usize,
    cells: Vec<Cell<F>>,
    columns: [CellColumn; 9 + TREE_LEVEL_AUX_COLUMNS],
}

impl<F: Field> CellManager<F> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        height: usize,
        layout: &[Column<Advice>; 10],
        aux: &[Column<Advice>; TREE_LEVEL_AUX_COLUMNS],
        offset: usize,
    ) -> Self {
        // Setup the columns and query the cells
        let width = layout.len() + aux.len();
        let mut cells: Vec<Cell<F>> = Vec::with_capacity(height * width);
        let mut columns = Vec::with_capacity(width);
        query_expression(meta, |meta| {
            for c in 0..layout.len() {
                for r in 0..height {
                    cells.push(Cell::new(meta, layout[c], offset + r, c));
                }
                columns.push(CellColumn {
                    index: c,
                    cell_type: CellType::storage_for_column::<F>(&layout[c]),
                    height: height,
                });
            }
            for c in 0..aux.len() {
                for r in 0..height {
                    cells.push(Cell::new(meta, aux[c], offset + r, c));
                }
                columns.push(CellColumn {
                    index: c,
                    cell_type: CellType::StoragePhase1,
                    height: 0,
                });
            }
        });

        Self {
            width,
            height,
            cells,
            columns: columns.try_into().unwrap(),
        }
    }

    pub(crate) fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        let mut cells = Vec::with_capacity(count);
        while cells.len() < count {
            let column_idx = self.next_column(cell_type);
            let column = &mut self.columns[column_idx];
            cells.push(self.cells[column_idx * self.height + column.height].clone());
            column.height += 1;
        }
        cells
    }

    pub(crate) fn query_cell(&mut self, cell_type: CellType) -> Cell<F> {
        self.query_cells(cell_type, 1)[0].clone()
    }

    fn next_column(&self, cell_type: CellType) -> usize {
        let mut best_index: Option<usize> = None;
        let mut best_height = self.height;
        for column in self.columns.iter() {
            if column.cell_type == cell_type && column.height < best_height {
                best_index = Some(column.index);
                best_height = column.height;
            }
        }
        match best_index {
            Some(index) => index,
            // If we reach this case, it means that all the columns of cell_type have assignments
            // taking self.height rows, so there's no more space.
            None => panic!("not enough cells for query: {:?}", cell_type),
        }
    }

    pub(crate) fn query_exact(&self, column: usize, row: usize) -> Cell<F> {
        self.cells[column * self.height + row].clone()
    }

    pub(crate) fn get_height(&self) -> usize {
        self.columns
            .iter()
            .map(|column| column.height)
            .max()
            .unwrap()
    }
}
