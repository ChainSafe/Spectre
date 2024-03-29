// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use crate::util::{CommonGateManager, GateBuilderConfig};
use eth_types::Field;
use getset::{CopyGetters, Getters};
use halo2_base::{
    gates::circuit::BaseCircuitParams,
    halo2_proofs::{
        circuit::Region,
        plonk::{ConstraintSystem, Error},
    },
    virtual_region::{
        copy_constraints::SharedCopyConstraintManager, manager::VirtualRegionManager,
    },
    AssignedValue,
};
use itertools::Itertools;
use zkevm_hashes::{
    sha256::vanilla::{
        columns::Sha256CircuitConfig,
        param::{NUM_START_ROWS, NUM_WORDS_TO_ABSORB, SHA256_NUM_ROWS},
        witness::VirtualShaRow,
    },
    util::word::Word,
};

/// `ShaBitGateManager` keeps track of halo2-lib virtual cells and assigns them to the region corresponding to the `Sha256CircuitConfig`.
/// It also loads of the copy (permutation) constraints between halo2-lib and vanilla cells in Plonk table.
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

/// Witnesses of a sha256 which are necessary to be loaded into halo2-lib.
#[derive(Clone, Copy, Debug, CopyGetters, Getters)]
pub struct LoadedSha256<F: Field> {
    /// The output of this sha256. is_final/hash_lo/hash_hi come from the first row of the last round(NUM_ROUNDS).
    #[getset(get_copy = "pub")]
    pub is_final: AssignedValue<F>,

    // Hash word consisting of two limbs - lower 16 bits and the high 16 bits, in big-endian.
    #[getset(get = "pub")]
    pub hash: Word<AssignedValue<F>>,

    /// Input words (u64) of this keccak_f.
    #[getset(get = "pub")]
    pub word_values: [AssignedValue<F>; NUM_WORDS_TO_ABSORB],
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

    fn custom_context(&mut self) -> Self::CustomContext<'_> {}

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
    }
}

impl<F: Field> ShaBitGateManager<F> {
    pub fn load_virtual_rows(&mut self, virtual_rows: Vec<VirtualShaRow>) -> Vec<LoadedSha256<F>> {
        struct UnassignedShaTableRow<F: Field> {
            is_final: F,
            io: F,
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
                let last_row = rows.last().unwrap();
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
    }
}

impl<F: Field> GateBuilderConfig<F> for Sha256CircuitConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>, _: BaseCircuitParams) -> Self {
        Sha256CircuitConfig::new(meta)
    }

    fn load(
        &self,
        _: &mut impl halo2_base::halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn annotate_columns_in_region(&self, _: &mut Region<F>) {}
}
