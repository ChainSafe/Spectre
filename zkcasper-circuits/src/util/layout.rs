use eth_types::Field;
use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Expression, Phase, SecondPhase, VirtualCells},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct ValueRlcColumn {
    pub value: Column<Advice>,
    pub rlc: Column<Advice>,
}

impl ValueRlcColumn {
    pub fn construct_in_phase<F: Field, VP: Phase, RP: Phase>(
        meta: &mut ConstraintSystem<F>,
        val_phase: VP,
        rlc_phase: RP,
    ) -> Self {
        Self {
            value: meta.advice_column_in(val_phase),
            rlc: meta.advice_column_in(rlc_phase),
        }
    }

    pub fn query<F: Field>(&self, meta: &mut VirtualCells<'_, F>, at: Rotation) -> ValueRlcExpr<F> {
        ValueRlcExpr::<F> {
            value: meta.query_advice(self.value, at),
            rlc: meta.query_advice(self.rlc, at),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValueRlcExpr<F: Field> {
    value: Expression<F>,
    rlc: Expression<F>,
}

impl<F: Field> ValueRlcExpr<F> {
    pub fn value(&self) -> Expression<F> {
        self.value.clone()
    }

    pub fn rlc(&self) -> Expression<F> {
        self.rlc.clone()
    }
}
