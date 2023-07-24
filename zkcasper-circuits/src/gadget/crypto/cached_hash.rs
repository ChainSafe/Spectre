use std::{cell::RefCell, collections::HashMap, hash::Hash};

use eth_types::Field;
use halo2_base::{safe_types::RangeChip, Context, QuantumCell};
use halo2_proofs::{circuit::Region, plonk::Error};

use crate::witness::HashInput;

use super::sha256::{AssignedHashResult, HashChip, Sha256Chip};

#[derive(Debug)]
pub struct CachedHashChip<'a, F: Field, HC: HashChip<F> + 'a> {
    pub inner: &'a HC,
    cache: RefCell<HashMap<HashInput<u8>, AssignedHashResult<F>>>,
}

impl<'a, F: Field, HC: HashChip<F>> HashChip<F> for CachedHashChip<'a, F, HC> {
    const BLOCK_SIZE: usize = HC::BLOCK_SIZE;

    const DIGEST_SIZE: usize = HC::DIGEST_SIZE;

    fn digest<const MAX_INPUT_SIZE: usize>(
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

        let result = self.inner.digest::<MAX_INPUT_SIZE>(input, ctx, region)?;
        cache.insert(bytes, result.clone());
        Ok(result)
    }

    fn take_extra_assignments(&self) -> halo2_base::gates::builder::KeygenAssignments<F> {
        self.inner.take_extra_assignments()
    }

    fn range(&self) -> &RangeChip<F> {
        self.inner.range()
    }
}

impl<'a, F: Field, HC: HashChip<F>> CachedHashChip<'a, F, HC> {
    pub fn new(chip: &'a HC) -> Self {
        Self {
            inner: chip,
            cache: Default::default(),
        }
    }
}
