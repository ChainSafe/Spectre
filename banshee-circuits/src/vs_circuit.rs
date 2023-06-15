pub(crate) mod cell_manager;
pub(crate) mod constraint_builder;

use crate::{
    table::{LookupTable, StateTable},
    util::{Cell, Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, StateEntry, StateTag},
    MAX_VALIDATORS,
};
use cell_manager::CellManager;
use constraint_builder::*;
use eth_types::*;
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed, Instance,
        SecondPhase, Selector, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use std::iter;

pub(crate) const N_BYTE_LOOKUPS: usize = 8;

#[derive(Clone)]
pub struct ValidatorsCircuitConfig {
    s_row: Column<Fixed>, // TODO: use selector instead
    target_epoch: Column<Instance>,
    state_table: StateTable,
    tag: BinaryNumberConfig<StateTag, 3>,
    storage_phase1: Column<Advice>,
    byte_lookup: [Column<Advice>; N_BYTE_LOOKUPS],
}

impl<F: Field> SubCircuitConfig<F> for ValidatorsCircuitConfig {
    type ConfigArgs = StateTable;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let s_row = meta.fixed_column();
        let target_epoch = meta.instance_column();
        let state_table = args;

        let storage_phase1 = meta.advice_column_in(FirstPhase);
        let byte_lookup: [_; N_BYTE_LOOKUPS] = (0..N_BYTE_LOOKUPS)
            .map(|_| meta.advice_column_in(FirstPhase))
            .collect_vec()
            .try_into()
            .unwrap();

        let cm_advices = iter::once(storage_phase1)
            .chain(byte_lookup.iter().copied())
            .collect_vec();

        let tag: BinaryNumberConfig<StateTag, 3> =
            BinaryNumberChip::configure(meta, s_row, Some(state_table.tag));

        let cell_manager = CellManager::new(meta, MAX_VALIDATORS, &cm_advices);
        let mut constraint_builder = ConstraintBuilder::new(cell_manager);

        let config = Self {
            s_row,
            target_epoch,
            state_table,
            tag,
            storage_phase1,
            byte_lookup,
        };

        meta.create_gate("validators constraints", |meta| {
            let queries = queries(meta, &config);
            constraint_builder.build(&queries);
            constraint_builder.gate(queries.selector)
        });

        config
    }
}

fn queries<F: Field>(meta: &mut VirtualCells<'_, F>, c: &ValidatorsCircuitConfig) -> Queries<F> {
    Queries {
        selector: meta.query_fixed(c.s_row, Rotation::cur()),
        target_epoch: meta.query_instance(c.target_epoch, Rotation::cur()),
        state_table: StateQueries {
            id: meta.query_advice(c.state_table.id, Rotation::cur()),
            order: meta.query_advice(c.state_table.id, Rotation::cur()),
            tag: meta.query_advice(c.state_table.tag, Rotation::cur()),
            is_active: meta.query_advice(c.state_table.is_active, Rotation::cur()),
            is_attested: meta.query_advice(c.state_table.is_attested, Rotation::cur()),
            field_tag: meta.query_advice(c.state_table.field_tag, Rotation::cur()),
            index: meta.query_advice(c.state_table.index, Rotation::cur()),
            g_index: meta.query_advice(c.state_table.g_index, Rotation::cur()),
            value: meta.query_advice(c.state_table.value, Rotation::cur()),
            // vitual queries for tag == 'validator'
            balance: meta.query_advice(c.state_table.value, Rotation::cur()),
            activation_epoch: meta.query_advice(c.state_table.value, Rotation::next()),
            exit_epoch: meta.query_advice(c.state_table.value, Rotation(2)),
            slashed: meta.query_advice(c.state_table.value, Rotation(3)),
            pubkey_lo: meta.query_advice(c.state_table.value, Rotation(4)),
            pubkey_hi: meta.query_advice(c.state_table.value, Rotation(5)),
        },
        tag_bits: c
            .tag
            .bits
            .map(|bit| meta.query_advice(bit, Rotation::cur())),
    }
}
