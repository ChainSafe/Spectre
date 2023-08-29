use std::marker::PhantomData;

use super::{compression::SpreadU32, util::*};
use eth_types::Field;
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::halo2_proofs::{
    circuit::{AssignedCell, Cell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector, TableColumn,
        VirtualCells,
    },
    poly::Rotation,
};
use halo2_base::utils::decompose;
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus},
    AssignedValue, Context,
};
use halo2_proofs::plonk::Any;
use itertools::Itertools;
use num_bigint::BigUint;

#[derive(Debug, Clone)]
pub struct SpreadConfig<F: Field> {
    denses: Vec<Column<Advice>>,
    spreads: Vec<Column<Advice>>,
    table_dense: TableColumn,
    table_spread: TableColumn,
    num_bits_lookup: usize,
    num_advice_columns: usize,
    num_limb_sum: usize,
    row_offset: usize,
    _f: PhantomData<F>,
}

impl<F: Field> SpreadConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        num_bits_lookup: usize,
        num_advice_columns: usize,
    ) -> Self {
        debug_assert_eq!(16 % num_bits_lookup, 0);
        // debug_assert_eq!(16 % (num_bits_lookup * num_advice_columns), 0);
        let denses = (0..num_advice_columns)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect_vec();
        let spreads = (0..num_advice_columns)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect_vec();

        let table_dense = meta.lookup_table_column();
        let table_spread = meta.lookup_table_column();
        for (idx, (dense, spread)) in denses.iter().zip(spreads.iter()).enumerate() {
            meta.lookup("spread lookup", |meta| {
                let dense = meta.query_advice(*dense, Rotation::cur());
                let spread = meta.query_advice(*spread, Rotation::cur());
                vec![(dense, table_dense), (spread, table_spread)]
            });
        }
        Self {
            denses,
            spreads,
            table_dense,
            table_spread,
            num_bits_lookup,
            num_advice_columns,
            num_limb_sum: 0,
            row_offset: 0,
            _f: PhantomData,
        }
    }

    pub fn annotate_columns_in_region(&self, region: &mut Region<F>) {
        for (i, col) in self.denses.iter().copied().enumerate() {
            region.name_column(|| format!("dense_{}", i), col);
        }
        for (i, col) in self.spreads.iter().copied().enumerate() {
            region.name_column(|| format!("spread_{}", i), col);
        }
    }

    pub fn spread(
        &mut self,
        ctx: &mut Context<F>,
        // region: &mut Region<'a, F>,
        range: &impl RangeInstructions<F>,
        dense: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let gate = range.gate();
        let limb_bits = self.num_bits_lookup;
        let num_limbs = 16 / limb_bits;
        let limbs = decompose(dense.value(), num_limbs, limb_bits);
        let assigned_limbs = ctx.assign_witnesses(limbs);
        {
            let mut limbs_sum = ctx.load_zero();
            for (idx, limb) in assigned_limbs.iter().copied().enumerate() {
                limbs_sum = gate.mul_add(
                    ctx,
                    QuantumCell::Existing(limb),
                    QuantumCell::Constant(F::from(1 << (limb_bits * idx))),
                    QuantumCell::Existing(limbs_sum),
                );
            }
            ctx.constrain_equal(&limbs_sum, dense);
        }
        let mut assigned_spread = ctx.load_zero();
        // println!("dense: {:?}", dense.value());
        for (idx, limb) in assigned_limbs.iter().enumerate() {
            // println!("idx {}, limb {:?}", idx, limb.value());
            let spread_limb = self.spread_limb(ctx, gate, limb)?;
            assigned_spread = gate.mul_add(
                ctx,
                QuantumCell::Existing(spread_limb),
                QuantumCell::Constant(F::from(1 << (2 * limb_bits * idx))),
                QuantumCell::Existing(assigned_spread),
            );
        }
        Ok(assigned_spread)
    }

    // pub fn dense<'v: 'a, 'a>(
    //     &mut self,
    //     ctx: &mut Context<F>,
    //     range: &impl RangeInstructions<F>,
    //     spread: &AssignedValue<F>,
    // ) -> Result<AssignedValue<F>, Error> {
    //     ctx.region.assign_advice(
    //         || format!("spread at offset {}", self.row_offset),
    //         self.dense,
    //         self.row_offset,
    //         || limb.value,
    //     )?;
    // }

    pub fn decompose_even_and_odd_unchecked(
        &self,
        ctx: &mut Context<F>,
        range: &impl RangeInstructions<F>,
        spread: &AssignedValue<F>,
    ) -> Result<(AssignedValue<F>, AssignedValue<F>), Error> {
        let bits = fe_to_bits_le(spread.value(), 32);
        let even_bits = (0..bits.len() / 2).map(|idx| bits[2 * idx]).collect_vec();
        let odd_bits = (0..bits.len() / 2)
            .map(|idx| bits[2 * idx + 1])
            .collect_vec();
        let (even_val, odd_val) = (bits_le_to_fe(&even_bits), bits_le_to_fe(&odd_bits));
        let even_assigned = ctx.load_witness(even_val);
        let odd_assigned = ctx.load_witness(odd_val);
        range.range_check(ctx, even_assigned, 16);
        range.range_check(ctx, odd_assigned, 16);
        Ok((even_assigned, odd_assigned))
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "spread table",
            |mut table| {
                for idx in 0..(1usize << self.num_bits_lookup) {
                    let val_dense = F::from(idx as u64);
                    let val_bits = fe_to_bits_le(&val_dense, 32);
                    let mut spread_bits = vec![false; val_bits.len() * 2];
                    for i in 0..val_bits.len() {
                        spread_bits[2 * i] = val_bits[i];
                    }
                    let val_spread: F = bits_le_to_fe(&spread_bits);
                    table.assign_cell(
                        || format!("table_dense at {}", idx),
                        self.table_dense,
                        idx,
                        || Value::known(val_dense),
                    )?;
                    table.assign_cell(
                        || format!("table_spread at {}", idx),
                        self.table_spread,
                        idx,
                        || Value::known(val_spread),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    fn spread_limb(
        &mut self,
        ctx: &mut Context<F>,
        // region: &mut Region<'a, F>,
        gate: &impl GateInstructions<F>,
        limb: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let column_idx = self.num_limb_sum % self.num_advice_columns;
        // let assigned_dense_cell = region.assign_advice(
        //     || format!("dense at offset {}", self.row_offset),
        //     self.denses[column_idx],
        //     self.row_offset,
        //     || Value::known(*limb.value()),
        // )?;
        // ctx.constrain_equal(&assigned_dense_cell, &limb);
        let spread_value: F = {
            let val_bits = fe_to_bits_le(limb.value(), 32);
            let mut spread_bits = vec![false; val_bits.len() * 2];
            for i in 0..val_bits.len() {
                spread_bits[2 * i] = val_bits[i];
            }
            bits_le_to_fe(&spread_bits)
        };
        // let assigned_spread_cell = region.assign_advice(
        //     || format!("spread at offset {}", self.row_offset),
        //     self.spreads[column_idx],
        //     self.row_offset,
        //     || Value::known(spread_value),
        // )?;
        let assigned_spread_value = ctx.load_witness(spread_value);
        // ctx.constrain_equal(&assigned_spread_cell, &assigned_spread)?;
        self.num_limb_sum += 1;
        if column_idx == self.num_advice_columns - 1 {
            self.row_offset += 1;
        }
        Ok(assigned_spread_value)
    }
}
