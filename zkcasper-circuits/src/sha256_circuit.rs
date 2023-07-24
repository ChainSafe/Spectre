//! The circuit for SHA256 hash function.
//! This implementation is based on:
//! - https://hackmd.io/@tsgAyLwURdqHzWxSmwVLjw/Sk5AOhWhc#Bit-implementation
//! - https://github.com/SoraSuegami/zkevm-circuits/blob/main/zkevm-circuits/src/sha256_circuit/sha256_bit.rs

mod sha256_bit;
pub mod util;

use std::marker::PhantomData;

use crate::{
    table::{LookupTable, SHA256Table},
    util::{not, BaseConstraintBuilder, Challenges, Expr, SubCircuit, SubCircuitConfig},
    witness::{self, HashInput},
};
use eth_types::{Field, Spec};
use gadgets::util::{and, select, sum, xor};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

use itertools::Itertools;
use log::debug;
use util::*;

use self::sha256_bit::{multi_sha256, ShaRow};

/// Configuration for [`Sha256Chip`].
#[derive(Clone, Debug)]
pub struct Sha256CircuitConfig<F> {
    q_enable: Column<Fixed>,
    q_first: Column<Fixed>,
    q_extend: Column<Fixed>,
    q_start: Column<Fixed>,
    q_compression: Column<Fixed>,
    q_end: Column<Fixed>,
    q_padding: Column<Fixed>,
    q_padding_last: Column<Fixed>,
    q_squeeze: Column<Fixed>,
    q_final_word: Column<Fixed>,
    word_w: [Column<Advice>; NUM_BITS_PER_WORD_W],
    word_a: [Column<Advice>; NUM_BITS_PER_WORD_EXT],
    word_e: [Column<Advice>; NUM_BITS_PER_WORD_EXT],
    is_final: Column<Advice>,
    is_paddings: [Column<Advice>; ABSORB_WIDTH_PER_ROW_BYTES],
    data_rlcs: [Column<Advice>; ABSORB_WIDTH_PER_ROW_BYTES],
    round_cst: Column<Fixed>,
    h_a: Column<Fixed>,
    h_e: Column<Fixed>,
    // feature: [multi input lookups]
    is_right: Column<Advice>,
    rnd_pow: Column<Advice>,
    input_rlcs: [Column<Advice>; 2],
    // feature: [lookup by value]
    u8_pow: [Column<Advice>; 2],
    is_rlc: [Column<Advice>; 2],
    is_left_value: Column<Advice>,
    is_right_value: Column<Advice>,

    /// The columns for bytes of hash results
    pub hash_table: SHA256Table,
    pub final_hash_bytes: [Column<Advice>; NUM_BYTES_FINAL_HASH],
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuitConfig<F> for Sha256CircuitConfig<F> {
    type ConfigArgs = SHA256Table;

    fn new<S: Spec>(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        // consts
        let two = F::from(2);
        let f256 = two.pow_const(8);

        let r: F = Sha256CircuitConfig::fixed_challenge();
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
        let is_right = meta.advice_column();

        let is_paddings = array_init::array_init(|_| meta.advice_column());
        is_paddings
            .iter()
            .for_each(|&col| meta.enable_equality(col));
        let data_rlcs: [Column<Advice>; 4] = array_init::array_init(|_| meta.advice_column());

        let round_cst = meta.fixed_column();
        let h_a = meta.fixed_column();
        meta.enable_equality(h_a);
        let h_e = meta.fixed_column();
        meta.enable_equality(h_e);

        let hash_table = args;
        let is_enabled = hash_table.is_enabled;
        meta.enable_equality(is_enabled);
        let length = hash_table.input_len;
        meta.enable_equality(length);
        let input_chunks = hash_table.input_chunks;
        let data_rlc = hash_table.input_rlc;
        meta.enable_equality(data_rlc);
        let hash_rlc = hash_table.hash_rlc;
        meta.enable_equality(hash_rlc);
        // feature: [multi input lookups]
        let rnd_pow = meta.advice_column();
        let input_rlcs = array_init::array_init(|_| meta.advice_column());
        // feature: [lookup by value]
        let is_rlc = array_init::array_init(|_| meta.advice_column());
        let is_left_value = meta.advice_column();
        let is_right_value = meta.advice_column();
        let u8_pow = array_init::array_init(|_| meta.advice_column());
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

        // circuit annotation
        hash_table.annotate_columns(meta);

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
            let length = meta.query_advice(length, Rotation::cur());
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

        // feature: [multi input lookups]
        // TODO: constraint is_right == 1 when leanth >= right_len
        // end

        // Length and input data rlc
        meta.create_gate("length and data rlc", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_padding = meta.query_fixed(q_padding, Rotation::cur());
            let is_right = meta.query_advice(is_right, Rotation::cur());
            let is_left_value: Expression<F> = meta.query_advice(is_left_value, Rotation::cur());
            let is_right_value: Expression<F> = meta.query_advice(is_right_value, Rotation::cur());
            let start_new_hash = start_new_hash(meta);
            let length_prev = meta.query_advice(length, Rotation::prev());
            let length = meta.query_advice(length, Rotation::cur());
            let data_rlc_prev = meta.query_advice(data_rlc, Rotation::prev());
            let data_rlc = meta.query_advice(data_rlc, Rotation::cur());
            let data_vals_prev = [
                meta.query_advice(input_chunks[0], Rotation::prev()),
                meta.query_advice(input_chunks[1], Rotation::prev()),
            ];
            let u8_pow_prev = [
                meta.query_advice(u8_pow[0], Rotation::prev()),
                meta.query_advice(u8_pow[1], Rotation::prev()),
            ];
            let u8_pow = [
                meta.query_advice(u8_pow[0], Rotation::cur()),
                meta.query_advice(u8_pow[1], Rotation::cur()),
            ];
            let input_chunks = [
                meta.query_advice(input_chunks[0], Rotation::cur()),
                meta.query_advice(input_chunks[1], Rotation::cur()),
            ];

            let rnd_pow_prev = meta.query_advice(rnd_pow, Rotation::prev());
            let rnd_pow = meta.query_advice(rnd_pow, Rotation::cur());

            // Update the length/data_rlc on rows where we absorb data
            cb.condition(q_padding.expr(), |cb| {
                cb.require_boolean("is_right boolean", is_right.clone()); // feature: [multi input lookups]

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
                let mut new_data_val = data_vals_prev
                    .clone()
                    .map(|e| e * not::expr(start_new_hash.expr()));
                let mut new_u8_pow = u8_pow_prev
                    .clone()
                    .map(|e| e * not::expr(start_new_hash.expr()));

                cb.require_equal(
                    "initial data rlc",
                    meta.query_advice(data_rlcs[0], Rotation::cur()),
                    new_data_rlc,
                );
                new_data_rlc = meta.query_advice(data_rlcs[0], Rotation::cur());

                let _new_data_rlc_cur = new_data_rlc.clone();
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
                    for (new_data_val, new_u8_pow) in
                        new_data_val.iter_mut().zip(new_u8_pow.iter_mut())
                    {
                        *new_data_val = new_data_val.clone() + new_u8_pow.clone() * byte.clone();
                        *new_u8_pow = new_u8_pow.clone() * f256;
                    }
                }

                cb.require_equal("update data rlc", data_rlc.clone(), new_data_rlc);

                // feature: [multi input lookups]
                let new_rnd_pow = rnd_pow_prev.clone() * r.pow_const(4);
                cb.require_equal(
                    "update rnd pow",
                    rnd_pow.clone() * is_right.clone(),
                    new_rnd_pow * is_right.clone(),
                );

                // feature: [lookup by value]
                let is_enabled = [is_left_value, is_right_value];
                for (i, (new_data_val, new_u8_pow)) in
                    new_data_val.into_iter().zip(new_u8_pow).enumerate()
                {
                    cb.require_equal(
                        ["update data val left", "update data val right"][i],
                        input_chunks[i].clone() * is_enabled[i].clone(),
                        new_data_val * is_enabled[i].clone(),
                    );
                    cb.require_equal(
                        ["update u8 pow left", "update u8 pow right"][i],
                        u8_pow[i].clone() * is_enabled[i].clone(),
                        new_u8_pow * is_enabled[i].clone(),
                    );
                }
            });
            cb.gate(1.expr())
        });

        // feature: [multi input lookups]
        meta.create_gate("chunk rlcs", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let is_enabled = meta.query_advice(is_enabled, Rotation::cur());
            let input_rlcs = input_rlcs
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect_vec();
            let input_chunks = input_chunks
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect_vec();
            let data_rlc = meta.query_advice(data_rlc, Rotation::cur());
            let base_pow = meta.query_advice(rnd_pow, Rotation::cur());
            let is_rlc = [
                meta.query_advice(is_rlc[0], Rotation::cur()),
                meta.query_advice(is_rlc[1], Rotation::cur()),
            ];

            for (i, (input_rlc, input_chunk)) in input_rlcs.iter().zip(input_chunks).enumerate() {
                cb.condition(is_rlc[i].clone(), |cb| {
                    cb.require_equal(
                        "input_rlc == input_hunk when is_rlc",
                        input_rlc.clone(),
                        input_chunk,
                    );
                });
            }

            cb.condition(is_enabled, |cb| {
                cb.require_equal(
                    "data_rlc = left_rlc * r^right.len() + right_rlc",
                    input_rlcs[0].clone() * base_pow + input_rlcs[1].clone(),
                    data_rlc,
                );
            });

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });
        // end

        // Make sure data is consistent between blocks
        meta.create_gate("cross block data consistency", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let start_new_hash = start_new_hash(meta);
            let to_const =
                |value: &String| -> &'static str { Box::leak(value.clone().into_boxed_str()) };
            let mut add = |name: &'static str, column: Column<Advice>| {
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
            add("length", length);
            add("data_rlc", data_rlc);
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
            let rlc = compose_rlc::expr(&hash_bytes, r);
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
            let rlc = compose_rlc::expr(&final_word_exprs, r);
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

        Sha256CircuitConfig {
            q_enable,
            q_first,
            q_extend,
            q_start,
            q_compression,
            is_right,
            q_end,
            q_padding,
            q_padding_last,
            q_squeeze,
            q_final_word,
            hash_table,
            word_w,
            word_a,
            word_e,
            is_final,
            is_paddings,
            data_rlcs,
            is_rlc,
            is_left_value,
            is_right_value,
            u8_pow,
            rnd_pow,
            input_rlcs,
            round_cst,
            h_a,
            h_e,
            final_hash_bytes,
            _marker: PhantomData,
        }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<F>) {
        self.hash_table.annotate_columns_in_region(region);
        self.annotations().iter().for_each(|(column, name)| {
            region.name_column(|| name, *column);
        });
    }
}

impl<F: Field> Sha256CircuitConfig<F> {
    /// Given the input, returns a vector of the assigned cells for the hash
    /// results.
    pub fn digest(
        &self,
        layouter: &mut impl Layouter<F>,
        input: HashInput<u8>,
    ) -> Result<[AssignedCell<F, F>; NUM_BYTES_FINAL_HASH], Error> {
        let witness = multi_sha256(&[input], Sha256CircuitConfig::fixed_challenge());
        let mut hashes = self.assign(layouter, &witness)?;
        assert_eq!(hashes.len(), 1);
        Ok(hashes.pop().unwrap().try_into().unwrap())
    }

    pub fn digest_with_region(
        &self,
        region: &mut Region<'_, F>,
        input: HashInput<u8>,
        assigned_rows: &mut Sha256AssignedRows<F>,
    ) -> Result<[AssignedCell<F, F>; NUM_BYTES_FINAL_HASH], Error> {
        let witness = multi_sha256(&[input], Sha256CircuitConfig::fixed_challenge());
        let mut hashes = self.assign_with_region(region, &witness, assigned_rows)?;
        assert_eq!(hashes.len(), 1);
        Ok(hashes.pop().unwrap().try_into().unwrap())
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness: &[ShaRow<F>],
    ) -> Result<Vec<Vec<AssignedCell<F, F>>>, Error> {
        layouter.assign_region(
            || "assign sha256 data",
            |mut region| {
                let mut assigned_rows = Sha256AssignedRows::new(0);
                self.assign_with_region(&mut region, witness, &mut assigned_rows)
            },
        )
    }

    fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &[ShaRow<F>],
        assigned_rows: &mut Sha256AssignedRows<F>,
    ) -> Result<Vec<Vec<AssignedCell<F, F>>>, Error> {
        self.annotate_columns_in_region(region);
        let vec_vecs = witness
            .iter()
            .map(|sha256_row| self.set_row(region, sha256_row, assigned_rows))
            .collect::<Result<Vec<Vec<AssignedCell<F, F>>>, Error>>()?;
        let filtered = vec_vecs
            .into_iter()
            .filter(|vec| !vec.is_empty())
            .collect::<Vec<Vec<AssignedCell<F, F>>>>();
        Ok(filtered)
    }

    fn set_row(
        &self,
        region: &mut Region<'_, F>,
        row: &ShaRow<F>,
        assigned_rows: &mut Sha256AssignedRows<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let offset = assigned_rows.offset;
        assigned_rows.offset += 1;
        let round = offset % (NUM_ROUNDS + 8);
        // Fixed values
        for (name, column, value) in &[
            ("q_enable", self.q_enable, F::from(true)),
            ("q_first", self.q_first, F::from(offset == 0)),
            (
                "q_extend",
                self.q_extend,
                F::from((4 + 16..4 + NUM_ROUNDS).contains(&round)),
            ),
            ("q_start", self.q_start, F::from(round < 4)),
            (
                "q_compression",
                self.q_compression,
                F::from((4..NUM_ROUNDS + 4).contains(&round)),
            ),
            ("q_end", self.q_end, F::from(round >= NUM_ROUNDS + 4)),
            (
                "q_padding",
                self.q_padding,
                F::from((4..20).contains(&round)),
            ),
            ("q_padding_last", self.q_padding_last, F::from(round == 19)),
            (
                "q_squeeze",
                self.q_squeeze,
                F::from(round == NUM_ROUNDS + 7),
            ),
            (
                "q_final_word",
                self.q_final_word,
                F::from(row.is_final && round == NUM_ROUNDS + 7),
            ),
            (
                "round_cst",
                self.round_cst,
                F::from(if (4..NUM_ROUNDS + 4).contains(&round) {
                    ROUND_CST[round - 4] as u64
                } else {
                    0
                }),
            ),
            (
                "Ha",
                self.h_a,
                F::from(if round < 4 { H[3 - round] } else { 0 }),
            ),
            (
                "He",
                self.h_e,
                F::from(if round < 4 { H[7 - round] } else { 0 }),
            ),
        ] {
            region.assign_fixed(
                || format!("assign {} {}", name, offset),
                *column,
                offset,
                || Value::known(*value),
            )?;
        }

        // Advice values
        for (name, columns, values) in [
            ("w bits", self.word_w.as_slice(), row.w.as_slice()),
            ("a bits", self.word_a.as_slice(), row.a.as_slice()),
            ("e bits", self.word_e.as_slice(), row.e.as_slice()),
            (
                "is_final",
                [self.is_final].as_slice(),
                [row.is_final].as_slice(),
            ),
            // feature: [multi input lookups]
            (
                "is_right",
                [self.is_right].as_slice(),
                [row.is_right].as_slice(),
            ),
            // end
        ] {
            for (idx, (value, column)) in values.iter().zip(columns.iter()).enumerate() {
                region.assign_advice(
                    || format!("assign {} {} {}", name, idx, offset),
                    *column,
                    offset,
                    || Value::known(F::from(*value)),
                )?;
            }
        }

        let padding_selectors = self
            .is_paddings
            .iter()
            .zip(row.is_paddings.iter())
            .enumerate()
            .map(|(idx, (&col, &val))| {
                region.assign_advice(
                    || format!("assign {} {} {}", "padding selector", idx, offset),
                    col,
                    offset,
                    || Value::known(F::from(val)),
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();

        // Intermediary data rlcs
        for (idx, (data_rlc, column)) in row
            .intermediary_data_rlcs
            .iter()
            .zip(self.data_rlcs.iter())
            .enumerate()
        {
            region.assign_advice(
                || format!("assign data rlcs {} {}", idx, offset),
                *column,
                offset,
                || Value::known(*data_rlc),
            )?;
        }

        // feature: [multi input lookups]
        region.assign_advice(
            || format!("assign rnd pow {}", offset),
            self.rnd_pow,
            offset,
            || Value::known(row.rnd_pow),
        )?;
        // end

        // feature: [lookup by value]
        for i in 0..2 {
            region.assign_advice(
                || format!("assign u8_pow[{i}] pow {}", offset),
                self.u8_pow[i],
                offset,
                || Value::known(row.u8_pow[i]),
            )?;
            region.assign_advice(
                || format!("assign is_rlc[{i}] {}", offset),
                self.is_rlc[i],
                offset,
                || Value::known(F::from(row.is_rlc[i] as u64)),
            )?;
            region.assign_advice(
                || format!("assign input_rlcs[{i}] {}", offset),
                self.input_rlcs[i],
                offset,
                || Value::known(row.chunks_rlc[i]),
            )?;
        }

        region.assign_advice(
            || format!("assign is_left_value {}", offset),
            self.is_left_value,
            offset,
            || Value::known(F::from((!row.is_rlc[0] && !row.is_right) as u64)),
        )?;
        region.assign_advice(
            || format!("assign is_right_value {}", offset),
            self.is_right_value,
            offset,
            || Value::known(F::from((!row.is_rlc[1] && row.is_right) as u64)),
        )?;
        // end

        // Hash data
        let [is_final, _, _, input_word, input_len, output_word] = self.hash_table.assign_row(
            region,
            offset,
            [
                Value::known(F::from(row.is_final && round == NUM_ROUNDS + 7)),
                if row.is_rlc[0] {
                    Value::known(row.chunks_rlc[0])
                } else {
                    Value::known(row.chunks_val[0])
                },
                if row.is_rlc[1] {
                    Value::known(row.chunks_rlc[1])
                } else {
                    Value::known(row.chunks_val[1])
                },
                Value::known(row.data_rlc),
                Value::known(F::from(row.length as u64)),
                Value::known(row.hash_rlc),
            ],
        )?;

        if (4..20).contains(&round) {
            assigned_rows.padding_selectors.push(padding_selectors);
            assigned_rows.input_rlc.push(input_word);
        }

        if row.is_final && round == NUM_ROUNDS + 7 {
            assigned_rows.output_rlc.push(output_word);
        }

        if round == NUM_ROUNDS + 7 {
            assigned_rows.is_final.push(is_final);
            assigned_rows.input_len.push(input_len);
        }

        let mut hash_cells = Vec::with_capacity(NUM_BYTES_FINAL_HASH);
        if !row.is_final || round != NUM_ROUNDS + 7 {
            for idx in 0..(NUM_BYTES_FINAL_HASH) {
                region.assign_advice(
                    || format!("final hash word at {}", idx),
                    self.final_hash_bytes[idx],
                    offset,
                    || Value::known(F::from(0u64)),
                )?;
            }
        } else {
            for (idx, byte) in row.final_hash_bytes.iter().enumerate() {
                let cell = region.assign_advice(
                    || format!("final hash word at {}", idx),
                    self.final_hash_bytes[idx],
                    offset,
                    || Value::known(*byte),
                )?;
                hash_cells.push(cell);
            }
        }
        Ok(hash_cells)
    }

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
            (self.is_right.into(), "is_right".to_string()),
            (self.rnd_pow.into(), "rnd_pow".to_string()),
            (self.is_left_value.into(), "is_left_value".to_string()),
            (self.is_right_value.into(), "is_right_value".to_string()),
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
        for (i, col) in self.u8_pow.iter().copied().enumerate() {
            annotations.push((col.into(), format!("u8_pow_{}", i)));
        }
        for (i, col) in self.final_hash_bytes.iter().copied().enumerate() {
            annotations.push((col.into(), format!("final_hash_bytes_{}", i)));
        }
        for (i, col) in self.is_rlc.iter().copied().enumerate() {
            annotations.push((col.into(), format!("is_rlc{}", i)));
        }
        for (i, col) in self.input_rlcs.iter().copied().enumerate() {
            annotations.push((col.into(), format!("input_rlcs_{}", i)));
        }

        annotations
    }

    pub fn fixed_challenge() -> F {
        F::from_u128(0xca9d6022267d3bd658bf)
    }
}

/// KeccakCircuit
#[derive(Default, Clone, Debug)]
pub struct Sha256Circuit<F: Field> {
    inputs: Vec<HashInput<u8>>,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for Sha256Circuit<F> {
    type Config = Sha256CircuitConfig<F>;
    type SynthesisArgs = ();

    fn unusable_rows() -> usize {
        todo!()
    }

    /// The `block.circuits_params.keccak_padding` parmeter, when enabled, sets
    /// up the circuit to support a fixed number of permutations/keccak_f's,
    /// independently of the permutations required by `inputs`.
    fn new_from_block(_block: &witness::Block<F>) -> Self {
        // Self::new(
        //     block.circuits_params.max_keccak_rows,
        //     block.keccak_inputs.clone(),
        // )
        todo!()
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(_block: &witness::Block<F>) -> (usize, usize) {
        // let rows_per_chunk = (NUM_ROUNDS + 1) * get_num_rows_per_round();
        // (
        //     block
        //         .keccak_inputs
        //         .iter()
        //         .map(|bytes| (bytes.len() as f64 / 136.0).ceil() as usize * rows_per_chunk)
        //         .sum(),
        //     block.circuits_params.max_keccak_rows,
        // )
        todo!()
    }

    /// Make the assignments to the KeccakCircuit
    fn synthesize_sub(
        &self,
        config: &mut Self::Config,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
        _: Self::SynthesisArgs,
    ) -> Result<(), Error> {
        let witness = self.generate_witness(*challenges);
        let _ = config.assign(layouter, witness.as_slice());
        Ok(())
    }
}

impl<F: Field> Sha256Circuit<F> {
    /// Creates a new circuit instance
    pub fn new(inputs: Vec<HashInput<u8>>) -> Self {
        Sha256Circuit {
            inputs,
            _marker: PhantomData,
        }
    }

    /// Sets the witness using the data to be hashed
    pub(crate) fn generate_witness(&self, _challenges: Challenges<F, Value<F>>) -> Vec<ShaRow<F>> {
        multi_sha256(&self.inputs, Sha256CircuitConfig::fixed_challenge())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::witness::MerkleTrace;

    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    use eth_types::Test as S;

    #[derive(Default, Debug, Clone)]
    struct TestSha256<F: Field> {
        inner: Sha256Circuit<F>,
    }

    impl<F: Field> Circuit<F> for TestSha256<F> {
        type Config = (Sha256CircuitConfig<F>, Challenges<F>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let hash_table = SHA256Table::construct(meta);
            (
                Sha256CircuitConfig::new::<S>(meta, hash_table),
                Challenges::construct(meta),
            )
        }

        fn synthesize(
            &self,
            mut config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            self.inner.synthesize_sub(
                &mut config.0,
                &config.1.values(&mut layouter),
                &mut layouter,
                (),
            )
        }
    }

    #[test]
    fn test_sha256_single() {
        let k = 11;
        let inputs = vec![vec![0u8; 64].into(); 1];
        let circuit = TestSha256 {
            inner: Sha256Circuit::new(inputs),
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_sha256_two2one_simple() {
        let k = 11;
        let inputs = vec![(vec![0u8; 32], vec![0u8; 32],).into(); 10];
        let circuit = TestSha256 {
            inner: Sha256Circuit::new(inputs),
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_sha256_two2one_val_and_rlc() {
        let k = 10;
        let inputs = vec![(vec![vec![2u8; 4], vec![0u8; 28]].concat(), vec![3u8; 4],).into(); 1];
        let circuit = TestSha256 {
            inner: Sha256Circuit::new(inputs),
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_sha256_circuit() {
        let k = 13;
        let merkle_trace: MerkleTrace =
            serde_json::from_slice(&fs::read("../test_data/merkle_trace.json").unwrap()).unwrap();
        let inputs = merkle_trace.sha256_inputs();
        println!("inputs: {:?}", inputs.len());
        let circuit = TestSha256 {
            inner: Sha256Circuit::new(inputs),
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
