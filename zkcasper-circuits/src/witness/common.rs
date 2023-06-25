use eth_types::Field;
use halo2_proofs::circuit::Value;

#[derive(Clone, Debug, Default)]
pub struct ValueRLC<F: Field> {
    pub value: Value<F>,
    pub rlc: Value<F>,
}

impl<F: Field> ValueRLC<F> {
    pub fn new(value: Value<F>, rlc: Value<F>) -> Self {
        Self { value, rlc }
    }

    pub fn empty() -> Self {
        Self {
            value: Value::known(F::zero()),
            rlc: Value::known(F::zero()),
        }
    }
}
