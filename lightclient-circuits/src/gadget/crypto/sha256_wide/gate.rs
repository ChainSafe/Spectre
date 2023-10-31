use std::{any::TypeId, cell::RefCell, collections::HashMap, iter, mem};

use eth_types::Field;
use getset::CopyGetters;
use halo2_base::{
    gates::{circuit::CircuitBuilderStage, flex_gate::FlexGateConfig},
    halo2_proofs::{
        circuit::{self, Region, Value},
        plonk::{Advice, Column, Error, Selector},
    },
    utils::ScalarField,
    virtual_region::{
        copy_constraints::SharedCopyConstraintManager, manager::VirtualRegionManager,
    },
    Context,
};
use itertools::Itertools;

use crate::util::{CommonGateManager, GateBuilderConfig};

use super::{config::Sha256BitConfig, witness::ShaRow};

pub const FIRST_PHASE: usize = 0;

pub type Sha256BitContexts<F> = Sha256BitConfig<F, Context<F>, Context<F>>;

#[derive(Clone, Debug, CopyGetters)]
pub struct ShaBitGateManager<F: Field> {
    #[getset(get_copy = "pub")]
    witness_gen_only: bool,
    /// The `unknown` flag is used during key generation. If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    #[getset(get_copy = "pub")]
    pub(crate) use_unknown: bool,

    /// Threads for spread table assignment.
    sha_contexts: Sha256BitContexts<F>,

    sha_offset: usize,

    pub copy_manager: SharedCopyConstraintManager<F>,
}

impl<F: Field> CommonGateManager<F> for ShaBitGateManager<F> {
    type CustomContext<'a> = &'a mut Sha256BitContexts<F>;

    fn new(witness_gen_only: bool) -> Self {
        let copy_manager = SharedCopyConstraintManager::default();
        let mut context_id = 0;
        let mut new_context = || {
            Context::new(
                witness_gen_only,
                FIRST_PHASE,
                TypeId::of::<Self>(),
                context_id,
                copy_manager.clone(),
            )
        };
        Self {
            witness_gen_only,
            use_unknown: false,
            sha_contexts: Sha256BitConfig {
                q_enable: new_context(),
                q_first: new_context(),
                q_extend: new_context(),
                q_start: new_context(),
                q_compression: new_context(),
                q_end: new_context(),
                q_padding: new_context(),
                q_padding_last: new_context(),
                q_squeeze: new_context(),
                q_final_word: new_context(),
                word_w: array_init::array_init(|_| new_context()),
                word_a: array_init::array_init(|_| new_context()),
                word_e: array_init::array_init(|_| new_context()),
                is_final: new_context(),
                is_paddings: array_init::array_init(|_| new_context()),
                data_rlcs: array_init::array_init(|_| new_context()),
                round_cst: new_context(),
                h_a: new_context(),
                h_e: new_context(),
                is_enabled: new_context(),
                input_rlc: new_context(),
                input_len: new_context(),
                hash_rlc: new_context(),
                final_hash_bytes: array_init::array_init(|_| new_context()),
                _f: std::marker::PhantomData,
                offset: 0,
            },
            sha_offset: 0,
            copy_manager: SharedCopyConstraintManager::default(),
        }
    }

    fn custom_context(&mut self) -> Self::CustomContext<'_> {
        self.sha_contexts()
    }

    fn from_stage(stage: CircuitBuilderStage) -> Self {
        Self::new(stage == CircuitBuilderStage::Prover)
            .unknown(stage == CircuitBuilderStage::Keygen)
    }

    fn use_copy_manager(mut self, copy_manager: SharedCopyConstraintManager<F>) -> Self {
        self.set_copy_manager(copy_manager);
        self
    }

    fn unknown(mut self, use_unknown: bool) -> Self {
        self.use_unknown = use_unknown;
        self
    }
}

impl<F: Field> VirtualRegionManager<F> for ShaBitGateManager<F> {
    type Config = Sha256BitConfig<F>;

    fn assign_raw(&self, config: &Self::Config, region: &mut Region<F>) {
        config.annotate_columns_in_region(region);

        if self.witness_gen_only() {
            self.sha_contexts
                .assign_in_region(region, config, false, None)
                .unwrap();
        } else {
            let mut copy_manager = self.copy_manager.lock().unwrap();
            self.sha_contexts
                .assign_in_region(region, config, self.use_unknown(), Some(&mut copy_manager))
                .unwrap();
        }
    }
}

impl<F: Field> ShaBitGateManager<F> {
    pub fn sha_contexts(&mut self) -> &mut Sha256BitContexts<F> {
        &mut self.sha_contexts
    }

    /// Mutates `self` to use the given copy manager everywhere, including in all threads.
    pub fn set_copy_manager(&mut self, copy_manager: SharedCopyConstraintManager<F>) {
        self.copy_manager = copy_manager.clone();
        // TODO: set to `self.sha_contexts`.
    }
}
