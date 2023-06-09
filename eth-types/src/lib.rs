use halo2_proofs::halo2curves::{
    bn256::{Fq, Fr},
    ff::{Field as Halo2Field, FromUniformBytes, PrimeField},
};

/// Trait used to reduce verbosity with the declaration of the [`PrimeField`]
/// trait and its repr.
pub trait Field: Halo2Field + PrimeField<Repr = [u8; 32]> + FromUniformBytes<64> + Ord {
    /// Gets the lower 128 bits of this field element when expressed
    /// canonically.
    fn get_lower_128(&self) -> u128 {
        let bytes = self.to_repr();
        bytes[..16]
            .iter()
            .rev()
            .fold(0u128, |acc, value| acc * 256u128 + *value as u128)
    }
    /// Gets the lower 32 bits of this field element when expressed
    /// canonically.
    fn get_lower_32(&self) -> u32 {
        let bytes = self.to_repr();
        bytes[..4]
            .iter()
            .rev()
            .fold(0u32, |acc, value| acc * 256u32 + *value as u32)
    }
}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

// Impl custom `Field` trait for BN256 Frq to be used and consistent with the
// rest of the workspace.
impl Field for Fq {}

/// Trait used to define types that can be converted to a 256 bit scalar value.
pub trait ToScalar<F> {
    /// Convert the type to a scalar value.
    fn to_scalar(&self) -> Option<F>;
}
