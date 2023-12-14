// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

pub trait WitnessFrom<T>: Sized {
    fn witness_from(value: T) -> Self;
}

pub trait IntoWitness<T>: Sized {
    fn into_witness(self) -> T;
}

impl<T, U> IntoWitness<U> for T
where
    U: WitnessFrom<T>,
{
    fn into_witness(self) -> U {
        U::witness_from(self)
    }
}

pub trait ConstantFrom<T>: Sized {
    fn constant_from(value: T) -> Self;
}

pub trait IntoConstant<T>: Sized {
    fn into_constant(self) -> T;
}

impl<T, U> IntoConstant<U> for T
where
    U: ConstantFrom<T>,
{
    fn into_constant(self) -> U {
        U::constant_from(self)
    }
}
