use crate::util::{CommonGateManager, GateBuilderConfig};
use eth_types::Field;
use getset::CopyGetters;
use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    halo2_proofs::circuit::Region,
    virtual_region::{
        copy_constraints::SharedCopyConstraintManager, manager::VirtualRegionManager,
    },
    AssignedValue, Context,
};
use itertools::Itertools;
use std::any::TypeId;
use zkevm_hashes::{
    sha256::{
        component::circuit::LoadedSha256,
        vanilla::{
            columns::Sha256CircuitConfig,
            param::{NUM_START_ROWS, NUM_WORDS_TO_ABSORB, SHA256_NUM_ROWS},
            witness::{AssignedSha256Block, VirtualShaRow},
        },
    },
    util::word::Word,
};

use super::witness::ShaRow;

pub const FIRST_PHASE: usize = 0;

#[derive(Clone, Debug, CopyGetters)]
pub struct ShaBitGateManager<F: Field> {
    #[getset(get_copy = "pub")]
    witness_gen_only: bool,
    /// The `unknown` flag is used during key generation. If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    #[getset(get_copy = "pub")]
    pub(crate) use_unknown: bool,

    /// Threads for spread table assignment.
    virtual_rows: Vec<VirtualShaRow>,
    loaded_blocks: Vec<LoadedSha256<F>>,

    pub copy_manager: SharedCopyConstraintManager<F>,
}

impl<F: Field> CommonGateManager<F> for ShaBitGateManager<F> {
    type CustomContext<'a> = ();

    fn new(witness_gen_only: bool) -> Self {
        Self {
            witness_gen_only,
            use_unknown: false,
            virtual_rows: Vec::new(),
            loaded_blocks: Vec::new(),
            copy_manager: SharedCopyConstraintManager::default(),
        }
    }

    fn custom_context(&mut self) -> Self::CustomContext<'_> {
        ()
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
    type Config = Sha256CircuitConfig<F>;

    fn assign_raw(&self, config: &Self::Config, region: &mut Region<F>) {
        // config.annotate_columns_in_region(region);
        let mut copy_manager = self.copy_manager.lock().unwrap();

        config
            .assign_sha256_rows(region, self.virtual_rows.clone(), None, 0)
            .into_iter()
            .zip(&self.loaded_blocks)
            .for_each(|(vanilla, loaded)| {
                copy_manager
                    .assigned_advices
                    .insert(loaded.is_final.cell.unwrap(), vanilla.is_final().cell());
                copy_manager
                    .assigned_advices
                    .insert(loaded.hash.lo().cell.unwrap(), vanilla.output().lo().cell());
                copy_manager
                    .assigned_advices
                    .insert(loaded.hash.hi().cell.unwrap(), vanilla.output().hi().cell());
                vanilla
                    .word_values()
                    .iter()
                    .zip(loaded.word_values)
                    .for_each(|(vanilla_input_word, loaded_input_word)| {
                        copy_manager
                            .assigned_advices
                            .insert(loaded_input_word.cell.unwrap(), vanilla_input_word.cell());
                    });
            });

        // if self.witness_gen_only() {
        //     config
        //         .assign_in_region(region, config, false, None)
        //         .unwrap();
        // } else {
        //     let mut copy_manager = self.copy_manager.lock().unwrap();
        //     config.assign_sha256_rows(region, config, self.use_unknown(), Some(&mut copy_manager))
        //         .unwrap();
        // }
    }
}

impl<F: Field> ShaBitGateManager<F> {
    pub fn load_virtual_rows(&mut self, virtual_rows: Vec<VirtualShaRow>) -> Vec<LoadedSha256<F>> {
        struct UnassignedShaTableRow<F: Field> {
            is_final: F,
            io: F,
            // length: F,
        }
        let table_rows = virtual_rows
            .iter()
            .enumerate()
            .map(|(offset, row)| {
                let round = offset % SHA256_NUM_ROWS;
                let q_input =
                    (NUM_START_ROWS..NUM_START_ROWS + NUM_WORDS_TO_ABSORB).contains(&round);

                let io_value = if q_input {
                    F::from(row.word_value as u64)
                } else if round >= SHA256_NUM_ROWS - 2 {
                    F::from_u128(row.hash_limb)
                } else {
                    F::ZERO
                };

                UnassignedShaTableRow {
                    is_final: F::from(row.is_final),
                    io: io_value,
                    // length: F::from(row.length as u64),
                }
            })
            // .enumerate()
            .collect_vec();
        debug_assert_eq!(table_rows.len() % SHA256_NUM_ROWS, 0);
        self.virtual_rows.extend(virtual_rows);
        let mut copy_manager = self.copy_manager.lock().unwrap();

        let loaded_blocks = table_rows
            .chunks_exact(SHA256_NUM_ROWS)
            .map(|rows| {
                let last_row = rows.last().unwrap(); // rows[SHA256_NUM_ROWS - 1]
                let is_final = copy_manager.mock_external_assigned(last_row.is_final);
                let output_lo = copy_manager.mock_external_assigned(last_row.io);
                let output_hi = copy_manager.mock_external_assigned(rows[SHA256_NUM_ROWS - 2].io);
                let input_rows = &rows[NUM_START_ROWS..NUM_START_ROWS + NUM_WORDS_TO_ABSORB];
                let word_values: [_; NUM_WORDS_TO_ABSORB] = input_rows
                    .iter()
                    .map(|row| copy_manager.mock_external_assigned(row.io))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                // let length =
                //     copy_manager.mock_external_assigned(input_rows.last().unwrap().1.length);
                LoadedSha256 {
                    is_final,
                    hash: Word::new([output_lo, output_hi]),
                    word_values,
                }
            })
            .collect_vec();

        self.loaded_blocks.extend(loaded_blocks.clone());

        loaded_blocks
    }

    /// Mutates `self` to use the given copy manager everywhere, including in all threads.
    pub fn set_copy_manager(&mut self, copy_manager: SharedCopyConstraintManager<F>) {
        self.copy_manager = copy_manager.clone();
        // TODO: set to `self.sha_contexts`.
    }
}
