//! The circuit for SHA256 hash function.
//! This implementation is based on:
//! - https://github.com/SoraSuegami/zkevm-circuits/blob/main/zkevm-circuits/src/sha256_circuit/sha256_bit.rs

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::iter;
use std::marker::PhantomData;

use crate::gadget::crypto::constant_randomness;
use crate::gadget::{and, not, rlc, select, sum, xor, Expr};
use crate::util::GateBuilderConfig;
use crate::witness::HashInputChunk;
use crate::{
    util::{BaseConstraintBuilder, Challenges},
    witness::{self, HashInput},
};
use eth_types::{Field, Spec};
use halo2_base::halo2_proofs::circuit;
use halo2_base::virtual_region::copy_constraints::CopyConstraintManager;
use halo2_base::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Region, Value},
        plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
        poly::Rotation,
    },
    AssignedValue, Context, ContextCell, QuantumCell,
};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

use super::util::*;
use itertools::Itertools;
use log::debug;

use super::witness::{multi_sha256, ShaRow};

/// Configuration for [`Sha256WideChip`].
#[derive(Clone, Debug)]
pub struct Sha256BitConfig<F: Field, CF = Column<Fixed>, CA = Column<Advice>> {
    pub q_enable: CF,
    pub q_first: CF,
    pub q_extend: CF,
    pub q_start: CF,
    pub q_compression: CF,
    pub q_end: CF,
    pub q_padding: CF,
    pub q_padding_last: CF,
    pub q_squeeze: CF,
    pub q_final_word: CF,
    pub word_w: [CA; NUM_BITS_PER_WORD_W],
    pub word_a: [CA; NUM_BITS_PER_WORD_EXT],
    pub word_e: [CA; NUM_BITS_PER_WORD_EXT],
    pub is_final: CA,
    pub is_paddings: [CA; ABSORB_WIDTH_PER_ROW_BYTES],
    pub data_rlcs: [CA; ABSORB_WIDTH_PER_ROW_BYTES],
    pub round_cst: CF,
    pub h_a: CF,
    pub h_e: CF,

    // True when the row is enabled
    pub is_enabled: CA,
    // The columns for bytes of hash results
    pub input_rlc: CA,
    // Length of first+second inputs
    pub input_len: CA,
    // RLC of the hash result
    pub hash_rlc: CA,
    // Output bytes
    pub final_hash_bytes: [CA; NUM_BYTES_FINAL_HASH],

    pub _f: PhantomData<F>,

    pub offset: usize,
}

impl<F: Field> GateBuilderConfig<F> for Sha256BitConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        // consts
        let two = F::from(2);
        let f256 = F::from(256);

        let r: F = constant_randomness(); // TODO: use challenges API
        let q_enable = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_extend = meta.fixed_column();
        let q_start = meta.fixed_column();
        let q_compression = meta.fixed_column();
        let q_end = meta.fixed_column();
        let q_padding = meta.fixed_column();
        let q_padding_last = meta.fixed_column();
        let q_squeeze = meta.fixed_column();
        let q_final_word = meta.fixed_column();
        let word_w = array_init::array_init(|_| meta.advice_column());
        let word_a = array_init::array_init(|_| meta.advice_column());
        let word_e = array_init::array_init(|_| meta.advice_column());
        let is_final = meta.advice_column();

        let is_paddings = array_init::array_init(|_| meta.advice_column());
        is_paddings
            .iter()
            .for_each(|&col| meta.enable_equality(col));
        let data_rlcs = array_init::array_init(|_| meta.advice_column());

        let round_cst = meta.fixed_column();
        let h_a = meta.fixed_column();
        meta.enable_equality(h_a);
        let h_e = meta.fixed_column();
        meta.enable_equality(h_e);

        let is_enabled = meta.advice_column();
        meta.enable_equality(is_enabled);
        let input_len = meta.advice_column();
        meta.enable_equality(input_len);
        let input_rlc = meta.advice_column();
        meta.enable_equality(input_rlc);
        let hash_rlc = meta.advice_column();
        meta.enable_equality(hash_rlc);

        let final_hash_bytes = array_init::array_init(|_| meta.advice_column());
        for col in final_hash_bytes.into_iter() {
            meta.enable_equality(col);
        }
        // State bits
        let mut w_ext = vec![0u64.expr(); NUM_BITS_PER_WORD_W];
        let mut w_2 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut w_7 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut w_15 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut w_16 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut a = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut b = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut c = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut d = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut e = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut f = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut g = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut h = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut d_64 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut h_64 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut new_a_ext = vec![0u64.expr(); NUM_BITS_PER_WORD_EXT];
        let mut new_e_ext = vec![0u64.expr(); NUM_BITS_PER_WORD_EXT];

        meta.create_gate("Query state bits", |meta| {
            for k in 0..NUM_BITS_PER_WORD_W {
                w_ext[k] = meta.query_advice(word_w[k], Rotation(-0));
            }
            for i in 0..NUM_BITS_PER_WORD {
                let k = i + NUM_BITS_PER_WORD_W - NUM_BITS_PER_WORD;
                w_2[i] = meta.query_advice(word_w[k], Rotation(-2));
                w_7[i] = meta.query_advice(word_w[k], Rotation(-7));
                w_15[i] = meta.query_advice(word_w[k], Rotation(-15));
                w_16[i] = meta.query_advice(word_w[k], Rotation(-16));
                let k = i + NUM_BITS_PER_WORD_EXT - NUM_BITS_PER_WORD;
                a[i] = meta.query_advice(word_a[k], Rotation(-1));
                b[i] = meta.query_advice(word_a[k], Rotation(-2));
                c[i] = meta.query_advice(word_a[k], Rotation(-3));
                d[i] = meta.query_advice(word_a[k], Rotation(-4));
                e[i] = meta.query_advice(word_e[k], Rotation(-1));
                f[i] = meta.query_advice(word_e[k], Rotation(-2));
                g[i] = meta.query_advice(word_e[k], Rotation(-3));
                h[i] = meta.query_advice(word_e[k], Rotation(-4));
                d_64[i] = meta.query_advice(word_a[k], Rotation(-((NUM_ROUNDS + 4) as i32)));
                h_64[i] = meta.query_advice(word_e[k], Rotation(-((NUM_ROUNDS + 4) as i32)));
            }
            for k in 0..NUM_BITS_PER_WORD_EXT {
                new_a_ext[k] = meta.query_advice(word_a[k], Rotation(0));
                new_e_ext[k] = meta.query_advice(word_e[k], Rotation(0));
            }
            vec![0u64.expr()]
        });
        let w = &w_ext[NUM_BITS_PER_WORD_W - NUM_BITS_PER_WORD..NUM_BITS_PER_WORD_W];
        let new_a = &new_a_ext[NUM_BITS_PER_WORD_EXT - NUM_BITS_PER_WORD..NUM_BITS_PER_WORD_EXT];
        let new_e = &new_e_ext[NUM_BITS_PER_WORD_EXT - NUM_BITS_PER_WORD..NUM_BITS_PER_WORD_EXT];

        let xor = |a: &[Expression<F>], b: &[Expression<F>]| {
            debug_assert_eq!(a.len(), b.len(), "invalid length");
            let mut c = vec![0.expr(); a.len()];
            for (idx, (a, b)) in a.iter().zip(b.iter()).enumerate() {
                c[idx] = xor::expr(a, b);
            }
            c
        };

        let select =
            |c: &[Expression<F>], when_true: &[Expression<F>], when_false: &[Expression<F>]| {
                debug_assert_eq!(c.len(), when_true.len(), "invalid length");
                debug_assert_eq!(c.len(), when_false.len(), "invalid length");
                let mut r = vec![0.expr(); c.len()];
                for (idx, (c, (when_true, when_false))) in c
                    .iter()
                    .zip(when_true.iter().zip(when_false.iter()))
                    .enumerate()
                {
                    r[idx] = select::expr(c.clone(), when_true.clone(), when_false.clone());
                }
                r
            };

        meta.create_gate("input checks", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            for w in w_ext.iter() {
                cb.require_boolean("w bit boolean", w.clone());
            }
            for a in new_a_ext.iter() {
                cb.require_boolean("a bit boolean", a.clone());
            }
            for e in new_e_ext.iter() {
                cb.require_boolean("e bit boolean", e.clone());
            }
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("w extend", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let s0 = xor(
                &rotate::expr(&w_15, 7),
                &xor(&rotate::expr(&w_15, 18), &shift::expr(&w_15, 3)),
            );
            let s1 = xor(
                &rotate::expr(&w_2, 17),
                &xor(&rotate::expr(&w_2, 19), &shift::expr(&w_2, 10)),
            );
            let new_w =
                decode::expr(&w_16) + decode::expr(&s0) + decode::expr(&w_7) + decode::expr(&s1);
            cb.require_equal("w", new_w, decode::expr(&w_ext));
            cb.gate(meta.query_fixed(q_extend, Rotation::cur()))
        });

        meta.create_gate("compression", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let s1 = xor(
                &rotate::expr(&e, 6),
                &xor(&rotate::expr(&e, 11), &rotate::expr(&e, 25)),
            );
            let ch = select(&e, &f, &g);
            let temp1 = decode::expr(&h)
                + decode::expr(&s1)
                + decode::expr(&ch)
                + meta.query_fixed(round_cst, Rotation::cur())
                + decode::expr(w);

            let s0 = xor(
                &rotate::expr(&a, 2),
                &xor(&rotate::expr(&a, 13), &rotate::expr(&a, 22)),
            );
            let maj = select(&xor(&b, &c), &a, &b);
            let temp2 = decode::expr(&s0) + decode::expr(&maj);
            cb.require_equal(
                "compress a",
                decode::expr(&new_a_ext),
                temp1.clone() + temp2,
            );
            cb.require_equal(
                "compress e",
                decode::expr(&new_e_ext),
                decode::expr(&d) + temp1,
            );
            cb.gate(meta.query_fixed(q_compression, Rotation::cur()))
        });

        meta.create_gate("start", |meta| {
            let is_final = meta.query_advice(is_final, Rotation::cur());
            let h_a = meta.query_fixed(h_a, Rotation::cur());
            let h_e = meta.query_fixed(h_e, Rotation::cur());
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            cb.require_equal(
                "start a",
                decode::expr(&new_a_ext),
                select::expr(is_final.expr(), h_a, decode::expr(&d)),
            );
            cb.require_equal(
                "start e",
                decode::expr(&new_e_ext),
                select::expr(is_final.expr(), h_e, decode::expr(&h)),
            );
            cb.gate(meta.query_fixed(q_start, Rotation::cur()))
        });

        meta.create_gate("end", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            cb.require_equal(
                "end a",
                decode::expr(&new_a_ext),
                decode::expr(&d) + decode::expr(&d_64),
            );
            cb.require_equal(
                "end e",
                decode::expr(&new_e_ext),
                decode::expr(&h) + decode::expr(&h_64),
            );
            cb.gate(meta.query_fixed(q_end, Rotation::cur()))
        });

        // Enforce logic for when this block is the last block for a hash
        meta.create_gate("is final", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let is_padding = meta.query_advice(
                *is_paddings.last().unwrap(),
                Rotation(-((NUM_END_ROWS + NUM_ROUNDS - NUM_WORDS_TO_ABSORB) as i32) - 2),
            );
            let is_final_prev = meta.query_advice(is_final, Rotation::prev());
            let is_final = meta.query_advice(is_final, Rotation::cur());
            // On the first row is_final needs to be enabled
            cb.condition(meta.query_fixed(q_first, Rotation::cur()), |cb| {
                cb.require_equal(
                    "is_final needs to remain the same",
                    is_final.expr(),
                    1.expr(),
                );
            });
            // Get the correct is_final state from the padding selector
            cb.condition(meta.query_fixed(q_squeeze, Rotation::cur()), |cb| {
                cb.require_equal(
                    "is_final needs to match the padding selector",
                    is_final.expr(),
                    is_padding,
                );
            });
            // Copy the is_final state to the q_start rows
            cb.condition(
                meta.query_fixed(q_start, Rotation::cur())
                    - meta.query_fixed(q_first, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "is_final needs to remain the same",
                        is_final.expr(),
                        is_final_prev,
                    );
                },
            );
            cb.gate(1.expr())
        });

        meta.create_gate("is enabled", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_squeeze = meta.query_fixed(q_squeeze, Rotation::cur());
            let is_final = meta.query_advice(is_final, Rotation::cur());
            let is_enabled = meta.query_advice(is_enabled, Rotation::cur());
            // Only set is_enabled to true when is_final is true and it's a squeeze row
            cb.require_equal(
                "is_enabled := q_squeeze && is_final",
                is_enabled.expr(),
                and::expr(&[q_squeeze.expr(), is_final.expr()]),
            );
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        let start_new_hash = |meta: &mut VirtualCells<F>| {
            // A new hash is started when the previous hash is done or on the first row
            meta.query_advice(is_final, Rotation::cur())
        };

        // Create bytes from input bits
        let input_bytes = to_le_bytes::expr(w);

        // Padding
        meta.create_gate("padding", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let prev_is_padding = meta.query_advice(*is_paddings.last().unwrap(), Rotation::prev());
            let q_padding = meta.query_fixed(q_padding, Rotation::cur());
            let q_padding_last = meta.query_fixed(q_padding_last, Rotation::cur());
            let length = meta.query_advice(input_len, Rotation::cur());
            let is_final_padding_row =
                meta.query_advice(*is_paddings.last().unwrap(), Rotation(-2));
            // All padding selectors need to be boolean
            for is_padding in is_paddings.iter() {
                let is_padding = meta.query_advice(*is_padding, Rotation::cur());
                cb.condition(meta.query_fixed(q_enable, Rotation::cur()), |cb| {
                    cb.require_boolean("is_padding boolean", is_padding);
                });
            }
            // Now for each padding selector
            for idx in 0..is_paddings.len() {
                // Previous padding selector can be on the previous row
                let is_padding_prev = if idx == 0 {
                    prev_is_padding.expr()
                } else {
                    meta.query_advice(is_paddings[idx - 1], Rotation::cur())
                };
                let is_padding = meta.query_advice(is_paddings[idx], Rotation::cur());
                let is_first_padding = is_padding.clone() - is_padding_prev.clone();
                // Check padding transition 0 -> 1 done only once
                cb.condition(q_padding.expr(), |cb| {
                    cb.require_boolean("padding step boolean", is_first_padding.clone());
                });
                // Padding start/intermediate byte, all padding rows except the last one
                cb.condition(
                    and::expr([
                        (q_padding.expr() - q_padding_last.expr()),
                        is_padding.expr(),
                    ]),
                    |cb| {
                        // Input bytes need to be zero, or 128 if this is the first padding byte
                        cb.require_equal(
                            "padding start/intermediate byte",
                            input_bytes[idx].clone(),
                            is_first_padding.expr() * 128.expr(),
                        );
                    },
                );
                // Padding start/intermediate byte, last padding row but not in the final block
                cb.condition(
                    and::expr([
                        q_padding_last.expr(),
                        is_padding.expr(),
                        not::expr(is_final_padding_row.expr()),
                    ]),
                    |cb| {
                        // Input bytes need to be zero, or 128 if this is the first padding byte
                        cb.require_equal(
                            "padding start/intermediate byte",
                            input_bytes[idx].clone(),
                            is_first_padding.expr() * 128.expr(),
                        );
                    },
                );
            }
            // The last row containing input/padding data in the final block needs to
            // contain the length in bits (Only input lengths up to 2**32 - 1
            // bits are supported, which is lower than the spec of 2**64 - 1 bits)
            cb.condition(
                and::expr([q_padding_last.expr(), is_final_padding_row.expr()]),
                |cb| {
                    cb.require_equal("padding length", decode::expr(w), length.expr() * 8.expr());
                },
            );
            cb.gate(1.expr())
        });

        // Length and input data rlc
        meta.create_gate("length and data rlc", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_padding = meta.query_fixed(q_padding, Rotation::cur());
            let start_new_hash = start_new_hash(meta);
            let length_prev = meta.query_advice(input_len, Rotation::prev());
            let length = meta.query_advice(input_len, Rotation::cur());
            let data_rlc_prev = meta.query_advice(input_rlc, Rotation::prev());
            let data_rlc = meta.query_advice(input_rlc, Rotation::cur());

            // Update the length/data_rlc on rows where we absorb data
            cb.condition(q_padding.expr(), |cb| {
                // Length increases by the number of bytes that aren't padding
                // In a new block we have to start from 0 if the previous block was the final
                // one
                cb.require_equal(
                    "update length",
                    length.clone(),
                    length_prev.clone() * not::expr(start_new_hash.expr())
                        + sum::expr(is_paddings.iter().map(|is_padding| {
                            not::expr(meta.query_advice(*is_padding, Rotation::cur()))
                        })),
                );

                // Use intermediate cells to keep the degree low
                let mut new_data_rlc = data_rlc_prev.clone() * not::expr(start_new_hash.expr());

                cb.require_equal(
                    "initial data rlc",
                    meta.query_advice(data_rlcs[0], Rotation::cur()),
                    new_data_rlc,
                );
                new_data_rlc = meta.query_advice(data_rlcs[0], Rotation::cur());

                for (idx, (byte, is_padding)) in
                    input_bytes.iter().zip(is_paddings.iter()).enumerate()
                {
                    new_data_rlc = select::expr(
                        meta.query_advice(*is_padding, Rotation::cur()),
                        new_data_rlc.clone(),
                        new_data_rlc.clone() * r + byte.clone(),
                    );
                    if idx < data_rlcs.len() - 1 {
                        let next_data_rlc = meta.query_advice(data_rlcs[idx + 1], Rotation::cur());
                        cb.require_equal(
                            "intermediate data rlc",
                            next_data_rlc.clone(),
                            new_data_rlc,
                        );
                        new_data_rlc = next_data_rlc;
                    }
                }

                cb.require_equal("update data rlc", data_rlc.clone(), new_data_rlc);
            });
            cb.gate(1.expr())
        });

        // Make sure data is consistent between blocks
        meta.create_gate("cross block data consistency", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let start_new_hash = start_new_hash(meta);
            let to_const =
                |value: &String| -> &'static str { Box::leak(value.clone().into_boxed_str()) };
            let mut add = |name: &'static str, column| {
                let last_rot =
                    Rotation(-((NUM_END_ROWS + NUM_ROUNDS - NUM_WORDS_TO_ABSORB) as i32));
                let value_to_copy = meta.query_advice(column, last_rot);
                let prev_value = meta.query_advice(column, Rotation::prev());
                let cur_value = meta.query_advice(column, Rotation::cur());
                // On squeeze rows fetch the last used value
                cb.condition(meta.query_fixed(q_squeeze, Rotation::cur()), |cb| {
                    cb.require_equal(
                        to_const(&format!("{} copy check", name)),
                        cur_value.expr(),
                        value_to_copy.expr(),
                    );
                });
                // On first rows keep the length the same, or reset the length when starting a
                // new hash
                cb.condition(
                    meta.query_fixed(q_start, Rotation::cur())
                        - meta.query_fixed(q_first, Rotation::cur()),
                    |cb| {
                        cb.require_equal(
                            to_const(&format!("{} equality check", name)),
                            cur_value.expr(),
                            prev_value.expr() * not::expr(start_new_hash.expr()),
                        );
                    },
                );
                // Set the value to zero on the first row
                cb.condition(meta.query_fixed(q_first, Rotation::cur()), |cb| {
                    cb.require_equal(
                        to_const(&format!("{} initialized to 0", name)),
                        cur_value.clone(),
                        0.expr(),
                    );
                });
            };
            add("length", input_len);
            add("data_rlc", input_rlc);
            add("last padding", *is_paddings.last().unwrap());

            cb.gate(1.expr())
        });

        // Squeeze
        meta.create_gate("squeeze", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // Squeeze out the hash
            let hash_parts = [new_a, &a, &b, &c, new_e, &e, &f, &g];
            let hash_bytes = hash_parts
                .iter()
                .flat_map(|part| to_le_bytes::expr(part))
                .collect::<Vec<_>>();
            let rlc = rlc::expr(&hash_bytes, Expression::Constant(r));
            cb.condition(start_new_hash(meta), |cb| {
                cb.require_equal(
                    "hash rlc check",
                    rlc,
                    meta.query_advice(hash_rlc, Rotation::cur()),
                );
            });
            cb.gate(meta.query_fixed(q_squeeze, Rotation::cur()))
        });

        meta.create_gate("final_hash_words", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_condition = meta.query_fixed(q_final_word, Rotation::cur());

            let final_word_exprs = (0..NUM_BYTES_FINAL_HASH)
                .map(|i| {
                    meta.query_advice(final_hash_bytes[i], Rotation::cur())
                        .expr()
                })
                .collect::<Vec<Expression<F>>>();
            let rlc = rlc::expr(&final_word_exprs, Expression::Constant(r));
            cb.condition(q_condition.clone(), |cb| {
                cb.require_equal(
                    "final hash rlc check",
                    rlc,
                    meta.query_advice(hash_rlc, Rotation::cur()),
                );
            });
            cb.gate(q_condition)
        });

        debug!("sha256 circuit degree: {}", meta.degree());
        debug!("minimum rows: {}", meta.minimum_rows());

        Sha256BitConfig {
            q_enable,
            q_first,
            q_extend,
            q_start,
            q_compression,
            q_end,
            q_padding,
            q_padding_last,
            q_squeeze,
            q_final_word,
            word_w,
            word_a,
            word_e,
            is_final,
            is_paddings,
            data_rlcs,
            round_cst,
            h_a,
            h_e,
            is_enabled,
            input_len,
            input_rlc,
            hash_rlc,
            final_hash_bytes,
            _f: PhantomData,
            offset: Default::default(),
        }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<F>) {
        self.annotations().iter().for_each(|(column, name)| {
            region.name_column(|| name, *column);
        });
    }

    fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

impl<F: Field> Sha256BitConfig<F> {
    pub fn annotations(&self) -> Vec<(Column<Any>, String)> {
        let mut annotations = vec![
            (self.q_enable.into(), "q_enabled".to_string()),
            (self.q_first.into(), "q_first".to_string()),
            (self.q_extend.into(), "q_extend".to_string()),
            (self.q_start.into(), "q_start".to_string()),
            (self.q_compression.into(), "q_compression".to_string()),
            (self.q_end.into(), "q_end".to_string()),
            (self.q_padding.into(), "q_padding".to_string()),
            (self.q_padding_last.into(), "q_padding_last".to_string()),
            (self.q_squeeze.into(), "q_squeeze".to_string()),
            (self.q_final_word.into(), "q_final_word".to_string()),
            (self.is_final.into(), "is_final".to_string()),
            (self.round_cst.into(), "round_cst".to_string()),
            (self.h_a.into(), "h_a".to_string()),
            (self.h_e.into(), "h_e".to_string()),
            (self.is_enabled.into(), "is_enabled".to_string()),
            (self.input_len.into(), "input_len".to_string()),
            (self.input_rlc.into(), "input_rlc".to_string()),
            (self.hash_rlc.into(), "hash_rlc".to_string()),
        ];

        for (i, col) in self.word_w.iter().copied().enumerate() {
            annotations.push((col.into(), format!("word_w_{}", i)));
        }
        for (i, col) in self.word_a.iter().copied().enumerate() {
            annotations.push((col.into(), format!("word_a_{}", i)));
        }
        for (i, col) in self.word_e.iter().copied().enumerate() {
            annotations.push((col.into(), format!("word_e_{}", i)));
        }
        for (i, col) in self.is_paddings.iter().copied().enumerate() {
            annotations.push((col.into(), format!("is_paddings_{}", i)));
        }
        for (i, col) in self.data_rlcs.iter().copied().enumerate() {
            annotations.push((col.into(), format!("data_rlcs_{}", i)));
        }
        for (i, col) in self.final_hash_bytes.iter().copied().enumerate() {
            annotations.push((col.into(), format!("final_hash_bytes_{}", i)));
        }

        annotations
    }
}

impl<F: Field> Sha256BitConfig<F, Context<F>, Context<F>> {
    pub fn load_sha256_row(
        &mut self,
        row: &ShaRow<F>,
        assigned_rows: &mut Sha256AssignedRows<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let offset = self.offset;
        self.offset += 1;
        let round = offset % (NUM_ROUNDS + 8);
        // Fixed values
        for (ctx, value) in [
            (&mut self.q_enable, F::from(true)),
            (&mut self.q_first, F::from(offset == 0)),
            (
                &mut self.q_extend,
                F::from((4 + 16..4 + NUM_ROUNDS).contains(&round)),
            ),
            (&mut self.q_start, F::from(round < 4)),
            (
                &mut self.q_compression,
                F::from((4..NUM_ROUNDS + 4).contains(&round)),
            ),
            (&mut self.q_end, F::from(round >= NUM_ROUNDS + 4)),
            (&mut self.q_padding, F::from((4..20).contains(&round))),
            (&mut self.q_padding_last, F::from(round == 19)),
            (&mut self.q_squeeze, F::from(round == NUM_ROUNDS + 7)),
            (
                &mut self.q_final_word,
                F::from(row.is_final && round == NUM_ROUNDS + 7),
            ),
            (
                &mut self.round_cst,
                F::from(if (4..NUM_ROUNDS + 4).contains(&round) {
                    ROUND_CST[round - 4] as u64
                } else {
                    0
                }),
            ),
            (
                &mut self.h_a,
                F::from(if round < 4 { H[3 - round] } else { 0 }),
            ),
            (
                &mut self.h_e,
                F::from(if round < 4 { H[7 - round] } else { 0 }),
            ),
        ] {
            ctx.assign_cell(QuantumCell::Constant(value));
        }

        // Advice values
        for (ctxs, values) in [
            (
                self.word_w.iter_mut().collect::<Vec<&mut _>>(),
                row.w.as_slice(),
            ),
            (
                self.word_a.iter_mut().collect::<Vec<&mut _>>(),
                row.a.as_slice(),
            ),
            (
                self.word_e.iter_mut().collect::<Vec<&mut _>>(),
                row.e.as_slice(),
            ),
            (vec![&mut self.is_final], [row.is_final].as_slice()),
        ] {
            for (value, ctx) in values.iter().zip(ctxs) {
                ctx.assign_cell(QuantumCell::Witness(F::from(*value)));
            }
        }

        let padding_selectors = self
            .is_paddings
            .iter_mut()
            .zip(row.is_paddings)
            .map(|(mut ctx, val)| ctx.load_witness(F::from(val)))
            .collect_vec()
            .try_into()
            .unwrap();

        // Intermediary data rlcs
        for ((ctx, data_rlc)) in self.data_rlcs.iter_mut().zip(row.intermediary_data_rlcs) {
            ctx.assign_cell(QuantumCell::Witness(data_rlc));
        }

        // Hash data
        let [is_enabled, input_rlc, input_len, output_rlc] = [
            (
                &mut self.is_enabled,
                F::from(row.is_final && round == NUM_ROUNDS + 7),
            ),
            (&mut self.input_rlc, row.data_rlc),
            (&mut self.input_len, F::from(row.length as u64)),
            (&mut self.hash_rlc, row.hash_rlc),
        ]
        .map(|(mut ctx, value)| ctx.load_witness(value));

        if (4..20).contains(&round) {
            assigned_rows.padding_selectors.push(padding_selectors);
            assigned_rows.input_rlc.push(input_rlc);
        }

        if row.is_final && round == NUM_ROUNDS + 7 {
            assigned_rows.output_rlc.push(output_rlc);
        }

        if round == NUM_ROUNDS + 7 {
            assigned_rows.is_final.push(is_enabled);
            assigned_rows.input_len.push(input_len);
        }

        if !row.is_final || round != NUM_ROUNDS + 7 {
            self.final_hash_bytes
                .iter_mut()
                .zip(iter::repeat(F::from(0u64)))
                .for_each(|(ctx, byte)| {
                    ctx.assign_cell(QuantumCell::Witness(byte));
                });

            return Ok(vec![]);
        }

        let assigned_hash_bytes = self
            .final_hash_bytes
            .iter_mut()
            .zip(row.final_hash_bytes)
            .map(|(ctx, byte)| ctx.load_witness(byte))
            .collect_vec();

        Ok(assigned_hash_bytes)
    }

    #[allow(clippy::type_complexity)]
    pub fn assign_in_region(
        &self,
        region: &mut Region<F>,
        config: &Sha256BitConfig<F>,
        use_unknown: bool,
        mut copy_manager: Option<&mut CopyConstraintManager<F>>,
    ) -> Result<(), Error> {
        // Fixed values
        for (name, column, ctx) in [
            ("q_enable", &config.q_enable, &self.q_enable),
            ("q_first", &config.q_first, &self.q_first),
            ("q_extend", &config.q_extend, &self.q_extend),
            ("q_start", &config.q_start, &self.q_start),
            ("q_compression", &config.q_compression, &self.q_compression),
            ("q_end", &config.q_end, &self.q_end),
            ("q_padding", &config.q_padding, &self.q_padding),
            (
                "q_padding_last",
                &config.q_padding_last,
                &self.q_padding_last,
            ),
            ("q_squeeze", &config.q_squeeze, &self.q_squeeze),
            ("q_final_word", &config.q_final_word, &self.q_final_word),
            ("round_cst", &config.round_cst, &self.round_cst),
            ("h_a", &config.h_a, &self.h_a),
            ("h_e", &config.h_e, &self.h_e),
        ] {
            for (offset, &val) in ctx.advice.iter().enumerate() {
                let cell = region
                    .assign_fixed(|| name, *column, offset, || Value::known(val))?
                    .cell();

                if let Some(copy_manager) = copy_manager.as_mut() {
                    copy_manager
                        .assigned_advices
                        .insert(ContextCell::new(ctx.type_id(), ctx.id(), offset), cell);
                }
            }
        }

        // Advice values

        for (name, column, ctx) in [
            ("is_enabled", &config.is_enabled, &self.is_enabled),
            ("input_len", &config.input_len, &self.input_len),
            ("input_rlc", &config.input_rlc, &self.input_rlc),
            ("hash_rlc", &config.hash_rlc, &self.hash_rlc),
        ] {
            for (offset, &val) in ctx.advice.iter().enumerate() {
                let value = if use_unknown {
                    Value::unknown()
                } else {
                    Value::known(val)
                };
                let cell = region
                    .assign_advice(|| name, *column, offset, || value)?
                    .cell();

                if let Some(copy_manager) = copy_manager.as_mut() {
                    copy_manager
                        .assigned_advices
                        .insert(ContextCell::new(ctx.type_id(), ctx.id(), offset), cell);
                }
            }
        }

        let _ = itertools::multizip((
            config.is_paddings.iter(),
            self.is_paddings.iter(),
            iter::repeat("is_paddings"),
        ))
        .chain(itertools::multizip((
            config.data_rlcs.iter(),
            self.data_rlcs.iter(),
            iter::repeat("data_rlcs"),
        )))
        .chain(itertools::multizip((
            config.word_w.iter(),
            self.word_w.iter(),
            iter::repeat("w word"),
        )))
        .chain(itertools::multizip((
            config.word_a.iter(),
            self.word_a.iter(),
            iter::repeat("a word"),
        )))
        .chain(itertools::multizip((
            config.word_e.iter(),
            self.word_e.iter(),
            iter::repeat("e word"),
        )))
        .chain(iter::once((&config.is_final, &self.is_final, "is final")))
        .chain(itertools::multizip((
            config.final_hash_bytes.iter(),
            self.final_hash_bytes.iter(),
            iter::repeat("final hash bytes"),
        )))
        .map(|(column, ctx, name)| {
            for (offset, &val) in ctx.advice.iter().enumerate() {
                let value = if use_unknown {
                    Value::unknown()
                } else {
                    Value::known(val)
                };

                let cell = match region.assign_advice(|| name, *column, offset, || value) {
                    Ok(cell) => cell,
                    Err(e) => {
                        return Err(e);
                    }
                }
                .cell();

                if let Some(copy_manager) = copy_manager.as_mut() {
                    copy_manager
                        .assigned_advices
                        .insert(ContextCell::new(ctx.type_id(), ctx.id(), offset), cell);
                }
            }

            Ok::<_, Error>(())
        })
        .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }
}
