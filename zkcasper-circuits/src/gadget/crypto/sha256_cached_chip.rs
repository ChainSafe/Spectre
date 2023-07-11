use std::{cell::RefCell, collections::HashMap};

use eth_types::Field;
use halo2_base::{Context, QuantumCell};
use halo2_proofs::{circuit::Region, plonk::Error};

use crate::witness::HashInput;

use super::sha256_chip::{AssignedHashResult, Sha256Chip};

#[derive(Debug)]
pub struct CachedSha256Chip<'a, F: Field> {
    pub inner: Sha256Chip<'a, F>,
    cache: RefCell<HashMap<HashInput<u8>, AssignedHashResult<F>>>,
}

impl<'a, F: Field> CachedSha256Chip<'a, F> {
    pub fn new(chip: Sha256Chip<'a, F>) -> Self {
        Self {
            inner: chip,
            cache: Default::default(),
        }
    }

    pub fn digest(
        &self,
        input: HashInput<QuantumCell<F>>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
    ) -> Result<AssignedHashResult<F>, Error> {
        let mut cache = self.cache.borrow_mut();
        let bytes: HashInput<u8> = input.clone().into();
        if let Some(result) = cache.get(&bytes) {
            return Ok(result.clone());
        }

        let result = self.inner.digest(input, ctx, region)?;
        cache.insert(bytes, result.clone());
        Ok(result)
    }
}
