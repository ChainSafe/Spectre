pub use crate::sha256_circuit::util::H;
use crate::sha256_circuit::util::*;
use crate::{
    util::{BaseConstraintBuilder, not, rlc},
    // table::KeccakTable,
    util::Expr,
};
use eth_types::Field;
use gadgets::util::{and, select, sum, xor};
use halo2_proofs::plonk::Instance;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use log::{debug, info};
use std::{marker::PhantomData, vec};

/// Witness values per row.
#[derive(Clone, Debug, PartialEq)]
pub struct ShaRow<F> {
    w: [bool; NUM_BITS_PER_WORD_W],
    a: [bool; NUM_BITS_PER_WORD_EXT],
    e: [bool; NUM_BITS_PER_WORD_EXT],
    h_a_in: u32,
    h_e_in: u32,
    h_a_out: u32,
    h_e_out: u32,
    // is_final: bool,
    // is_dummy: bool,
    // length: usize,
    // data_rlc: F,
    // hash_rlc: F,
    // is_paddings: [bool; ABSORB_WIDTH_PER_ROW_BYTES],
    // data_rlcs: [F; ABSORB_WIDTH_PER_ROW_BYTES],
    input_word: F,
    // output_word: F,
}

/// Configuration for [`Sha256BitChip`].
#[derive(Clone, Debug)]
pub struct Sha256CompressionConfig<F> {
    q_enable: Column<Fixed>,
    // q_first: Column<Fixed>,
    q_extend: Column<Fixed>,
    q_start: Column<Fixed>,
    q_compression: Column<Fixed>,
    q_end: Column<Fixed>,
    q_padding: Column<Fixed>,
    // q_padding_last: Column<Fixed>,
    q_squeeze: Column<Fixed>,
    round_cst: Column<Fixed>,
    // q_init_state: Column<Fixed>,
    // q_init_h_a: Column<Fixed>,
    // q_init_h_e: Column<Fixed>,
    word_w: [Column<Advice>; NUM_BITS_PER_WORD_W],
    word_a: [Column<Advice>; NUM_BITS_PER_WORD_EXT],
    word_e: [Column<Advice>; NUM_BITS_PER_WORD_EXT],
    // is_final: Column<Advice>,
    // is_paddings: [Column<Advice>; ABSORB_WIDTH_PER_ROW_BYTES],
    /// The columns for bits representing whether the round is dummy or not.
    // pub is_dummy: Column<Advice>,
    // data_rlcs: [Column<Advice>; ABSORB_WIDTH_PER_ROW_BYTES],
    /// Init hash values of a,b,c,d.
    pub h_a_in: Column<Advice>,
    /// Init hash values of e,f,g,h.
    pub h_e_in: Column<Advice>,
    /// Output hash values of a,b,c,d.
    pub h_a_out: Column<Advice>,
    /// Output hash values of e,f,g,h.
    pub h_e_out: Column<Advice>,
    /// The columns for other circuits to lookup hash results
    /// Byte array input length
    // pub input_len: Column<Advice>,
    /// The input words (4 bytes) result,
    pub input_words: Column<Advice>,
    /// The enable flag of the output hash.
    // pub is_output_enabled: Column<Advice>,
    /// The hash words (8 bytes) result,
    // pub output_words: Column<Advice>,
    // max_input_len: usize,
    /// The column for the randomness used to compute random linear
    /// combinations.
    //pub randomness: Column<Advice>,
    _marker: PhantomData<F>,
}

/// Chip for the SHA256 hash function.
// #[derive(Clone, Debug)]
// pub struct Sha256BitChip<F: Field> {
//     config: Sha256BitConfig<F>,
//     max_input_len: usize,
// }

/// Assigned values for each row.
#[derive(Clone, Debug)]
pub struct Sha256AssignedRows<F: Field> {
    /// Offset of the row.
    pub offset: usize,
    /// Input length at the row.
    // pub input_len: Vec<AssignedCell<F, F>>,
    /// Input words at the row.
    pub input_words: Vec<AssignedCell<F, F>>,
    /// Whether the output word is enabled at the row.
    // pub is_output_enabled: Vec<AssignedCell<F, F>>,
    /// Output words at the row.
    // pub output_words: Vec<AssignedCell<F, F>>,
    /// Whether the round is dummy at the row.
    // pub is_dummy: Vec<AssignedCell<F, F>>,
    /// Assigned h_a,h_b,h_c,h_d.
    pub h_a_in: Vec<AssignedCell<F, F>>,
    /// Assigned h_e,h_f,h_g,h_h.
    pub h_e_in: Vec<AssignedCell<F, F>>,
    /// Assigned h_a,h_b,h_c,h_d.
    pub h_a_out: Vec<AssignedCell<F, F>>,
    /// Assigned h_e,h_f,h_g,h_h.
    pub h_e_out: Vec<AssignedCell<F, F>>,
}

// impl<F: Field> Sha256BitChip<F> {
//     fn r() -> F {
//         F::from(123456)
//     }
// }

impl<F: Field> Sha256AssignedRows<F> {
    const ROW_H_IN_PER_BLOCK: usize = 4;
    const ROW_H_OUT_PER_BLOCK: usize = 4;
    const ROW_INPUT_PER_BLOCK: usize = 16;
    /// Init [`Sha256AssignedRows`]
    pub fn new(offset: usize) -> Self {
        Self {
            offset,
            // input_len: vec![],
            input_words: vec![],
            // is_output_enabled: vec![],
            // output_words: vec![],
            // is_dummy: vec![],
            h_a_in: vec![],
            h_e_in: vec![],
            h_a_out: vec![],
            h_e_out: vec![],
        }
    }

    /// Get assigned input words.
    pub fn get_input_words(&self) -> Vec<Vec<AssignedCell<F, F>>> {
        self.input_words
            .chunks(Self::ROW_INPUT_PER_BLOCK)
            .map(|words| words.to_vec())
            .collect()
    }

    /// Get H_IN assigned values.
    pub fn get_h_ins(&self) -> Vec<Vec<AssignedCell<F, F>>> {
        let mut assigned_h_ins = Vec::new();
        let num_block = self.h_a_in.len() / Self::ROW_H_IN_PER_BLOCK;
        for idx in 0..num_block {
            let h_a_in =
                &self.h_a_in[Self::ROW_H_IN_PER_BLOCK * idx..Self::ROW_H_IN_PER_BLOCK * (idx + 1)];
            let h_e_in =
                &self.h_e_in[Self::ROW_H_IN_PER_BLOCK * idx..Self::ROW_H_IN_PER_BLOCK * (idx + 1)];
            assigned_h_ins.push(vec![
                h_a_in[3].clone(),
                h_a_in[2].clone(),
                h_a_in[1].clone(),
                h_a_in[0].clone(),
                h_e_in[3].clone(),
                h_e_in[2].clone(),
                h_e_in[1].clone(),
                h_e_in[0].clone(),
            ]);
        }
        assigned_h_ins
    }

    /// Get H_OUR assigned values.
    pub fn get_h_outs(&self) -> Vec<Vec<AssignedCell<F, F>>> {
        let mut assigned_h_outs = Vec::new();
        let num_block = self.h_a_out.len() / Self::ROW_H_OUT_PER_BLOCK;
        for idx in 0..num_block {
            let h_a_out = &self.h_a_out
                [Self::ROW_H_OUT_PER_BLOCK * idx..Self::ROW_H_OUT_PER_BLOCK * (idx + 1)];
            let h_e_out = &self.h_e_out
                [Self::ROW_H_OUT_PER_BLOCK * idx..Self::ROW_H_OUT_PER_BLOCK * (idx + 1)];
            assigned_h_outs.push(vec![
                h_a_out[3].clone(),
                h_a_out[2].clone(),
                h_a_out[1].clone(),
                h_a_out[0].clone(),
                h_e_out[3].clone(),
                h_e_out[2].clone(),
                h_e_out[1].clone(),
                h_e_out[0].clone(),
            ]);
        }
        assigned_h_outs
    }

    /// Append other assigned rows to myself.
    pub fn append(&mut self, other: &mut Self) {
        self.offset += other.offset;
        self.input_words.append(&mut other.input_words);
        // self.output_words.append(&mut other.output_words);
        self.h_a_in.append(&mut other.h_a_in);
        self.h_e_in.append(&mut other.h_e_in);
        self.h_a_out.append(&mut other.h_a_out);
        self.h_e_out.append(&mut other.h_e_out);
    }
}

// impl<F: Field> Sha256BitChip<F> {
//     /// Create a new [`Sha256BitChip`] from the configuration.
//     ///
//     /// # Arguments
//     /// * config - a configuration for [`Sha256BitChip`].
//     ///
//     /// # Return values
//     /// Returns a new [`Sha256BitChip`]
//     pub fn new(config: Sha256BitConfig<F>, max_input_len: usize) -> Self {
//         assert_eq!(max_input_len % 64, 0);
//         Sha256BitChip {
//             config,
//             max_input_len,
//         }
//     }

//     /*/// The number of sha256 permutations that can be done in this circuit
//     pub fn capacity(&self) -> usize {
//         // Subtract one for unusable rows
//         self.size / (NUM_ROUNDS + 8) - 1
//     }*/
//     /// Given the input, returns a vector of the assigned cells for the hash
//     /// results.
//     ///
//     /// # Arguments
//     /// * region - a region where the witnesses are assigned.
//     /// * inputs - a vector of input bytes.
//     ///
//     /// # Return values
//     /// Returns a vector of the assigned cells for the hash results.
//     pub fn digest(
//         &self,
//         region: &mut Region<'_, F>,
//         input: &[u8],
//     ) -> Result<Sha256AssignedRows<F>, Error> {
//         assert!(input.len() <= self.max_input_len);
//         let witness = sha256(input, self.max_input_len, self.max_input_len);
//         let mut assigned_rows = Sha256AssignedRows::new(0);
//         self.assign_witness(region, &witness, &mut assigned_rows)?;
//         Ok(assigned_rows)
//     }
// }

impl<F: Field> Sha256CompressionConfig<F> {
    /// The number of rows per 64 bytes input block.
    pub const ROWS_PER_BLOCK: usize = 72;
    /// Configure constraints for [`Sha256BitChip`]
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        //let r = Sha256BitChip::r();
        let q_enable = meta.fixed_column();
        // let q_first = meta.fixed_column();
        let q_extend = meta.fixed_column();
        let q_start = meta.fixed_column();
        let q_compression = meta.fixed_column();
        let q_end = meta.fixed_column();
        let q_padding = meta.fixed_column();
        // let q_padding_last = meta.fixed_column();
        let q_squeeze = meta.fixed_column();
        // let q_init_state = meta.fixed_column();
        // let q_init_h_a = meta.fixed_column();
        // let q_init_h_e = meta.fixed_column();
        let word_w = array_init::array_init(|_| meta.advice_column());
        let word_a = array_init::array_init(|_| meta.advice_column());
        let word_e = array_init::array_init(|_| meta.advice_column());
        // let is_final = meta.advice_column();
        // let is_paddings = array_init::array_init(|_| meta.advice_column());
        // let is_dummy = meta.advice_column();
        // meta.enable_equality(is_dummy);
        // let data_rlcs = array_init::array_init(|_| meta.advice_column());
        let round_cst = meta.fixed_column();
        let h_a_in = meta.advice_column();
        meta.enable_equality(h_a_in);
        let h_e_in = meta.advice_column();
        meta.enable_equality(h_e_in);
        let h_a_out = meta.advice_column();
        meta.enable_equality(h_a_out);
        let h_e_out = meta.advice_column();
        meta.enable_equality(h_e_out);
        //let hash_table = KeccakTable::construct(meta);
        // let randomness = meta.advice_column();
        // meta.enable_equality(randomness);
        // let input_len = meta.advice_column();
        // meta.enable_equality(input_len);
        let input_words = meta.advice_column();
        meta.enable_equality(input_words);
        // let is_output_enabled = meta.advice_column();
        // meta.enable_equality(is_output_enabled);
        // let output_words = meta.advice_column();
        // meta.enable_equality(output_words);
        // let data_rlc = hash_table.input_rlc;
        // let hash_rlc = hash_table.output_rlc;
        // let final_hash_bytes = array_init::array_init(|_| meta.advice_column());
        // for col in final_hash_bytes.into_iter() {
        //     meta.enable_equality(col);
        // }
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
            let h_a_in = meta.query_advice(h_a_in, Rotation::cur());
            let h_e_in = meta.query_advice(h_e_in, Rotation::cur());
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let new_a_ext = decode::expr(&new_a_ext);
            let new_e_ext = decode::expr(&new_e_ext);
            let q_start = meta.query_fixed(q_start, Rotation::cur());
            // let q_first = meta.query_fixed(q_first, Rotation::cur());
            cb.require_equal(
                "start a", new_a_ext,
                h_a_in, //select::expr(q_first.expr(), h_a_in.expr(), decode::expr(&d)),
            );
            cb.require_equal(
                "start e", new_e_ext,
                h_e_in, //select::expr(q_first.expr(), h_e_in.expr(), decode::expr(&h)),
            );
            // cb.condition(q_first, |cb| {
            //     cb.require_equal(
            //         "h_a should be the init_h_a value when q_first==1",
            //         h_a.expr(),
            //         meta.query_fixed(q_init_h_a, Rotation::cur()),
            //     );
            //     cb.require_equal(
            //         "h_e should be the init_h_e value when q_first==1",
            //         h_e.expr(),
            //         meta.query_fixed(q_init_h_e, Rotation::cur()),
            //     );
            // });

            cb.gate(q_start)
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

        // // Enforce logic for when this block is the last block for a hash
        // meta.create_gate("is final", |meta| {
        //     let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
        //     let is_padding = meta.query_advice(
        //         *is_paddings.last().unwrap(),
        //         Rotation(-((NUM_END_ROWS + NUM_ROUNDS - NUM_WORDS_TO_ABSORB) as i32)
        // - 2),     ); // let is_final_prev = meta.query_advice(is_final,
        //   Rotation(-((NUM_ROUNDS
        // + 8)     // as i32)));
        //     let is_final = meta.query_advice(is_final, Rotation::cur()); // On the
        // first row is_final needs to be enabled
        // //     cb.condition(meta.query_fixed(q_first, Rotation::cur()), |cb| {
        //                                                                  //
        // cb.require_equal(
        // //             "is_final needs to remain the same",
        // //             is_final.expr(),
        // //             1.expr(),
        // //         );
        // //     }); // Get the correct is_final state from the padding selector
        //                                                                  //
        // cb.condition(
        // //         and::expr(&[
        // //             meta.query_fixed(q_squeeze, Rotation::cur()),
        //                                                                  //
        // not::expr(meta.query_advice(is_dummy, Rotation::cur())),
        // //         ]),
        // //         |cb| {
        // //             cb.require_equal(
        // //                 "is_final needs to match the padding
        // //   selector",
        // //                 is_final.expr(),
        // //                 is_padding,
        // //             );
        // //         },
        // //     ); // Copy the is_final state to the q_start rows
        // //     cb.condition(
        // //         and::expr(&[
        // //             meta.query_fixed(q_start, Rotation::cur())
        // //                 - meta.query_fixed(q_first, Rotation::cur()),
        //                                                                  //
        // 1.expr() - is_final_prev.expr(),
        // //         ]),
        // //         |cb| {
        // //             cb.require_equal(
        // //                 "is_final needs to remain the same",
        // //                 is_final.expr(),
        // //                 is_final_prev,
        // //             );
        // //         },
        // //     );     let not_dummy = not::expr(meta.query_advice(is_dummy,
        // Rotation::cur()));     cb.condition(meta.query_fixed(q_squeeze,
        // Rotation::cur()), |cb| {         cb.require_equal(
        //             "is_final := is_padding and not(is_dummy)",
        //             is_final,
        //             and::expr(&[is_padding, not_dummy]),
        //         )
        //     });
        //     // cb.condition(meta.query_fixed(q_first, Rotation::cur()), |cb| {
        //     //     cb.require_zero("is_final at the first row should be zero",
        // is_final)     // });
        //     // cb.condition(
        //     //     and::expr(&[
        //     //         meta.query_fixed(q_squeeze, Rotation::cur()),
        //     //         not::expr(meta.query_advice(is_dummy, Rotation::cur())),
        //     //     ]),
        //     //     |cb| {
        //     //         cb.require_equal(
        //     //             "is_final needs to match the padding selector",
        //     //             is_final,
        //     //             is_padding,
        //     //         );
        //     //     },
        //     // );

        //     cb.gate(1.expr())
        // });

        // meta.create_gate("is enabled", |meta| {
        //     let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
        //     let q_squeeze = meta.query_fixed(q_squeeze, Rotation::cur());
        //     let is_final = meta.query_advice(is_final, Rotation::cur());
        //     let is_output_enabled = meta.query_advice(is_output_enabled,
        // Rotation::cur());     // Only set is_enabled to true when is_final is
        // true and it's a squeeze row     cb.require_equal(
        //         "is_output_enabled := q_squeeze && is_final",
        //         is_output_enabled.expr(),
        //         and::expr(&[q_squeeze.expr(), is_final.expr()]),
        //     );
        //     cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        // });

        // let start_new_hash = |meta: &mut VirtualCells<F>| {
        //     // A new hash is started when the previous hash is done or on the first
        // row     meta.query_advice(is_final, Rotation::cur())
        // };

        // Create bytes from input bits
        let input_bytes = to_le_bytes::expr(w);

        // Input bytes
        meta.create_gate("input bytes", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let input_words = meta.query_advice(input_words, Rotation::cur());
            let sum = input_bytes[0].clone()
                + (1u64 << 8).expr() * input_bytes[1].clone()
                + (1u64 << 16).expr() * input_bytes[2].clone()
                + (1u64 << 24).expr() * input_bytes[3].clone();
            cb.require_equal("input_bytes = input_words", sum, input_words);
            cb.gate(meta.query_fixed(q_padding, Rotation::cur()))
        });

        // Padding
        // meta.create_gate("padding", |meta| {
        //     let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
        //     let prev_is_padding = meta.query_advice(*is_paddings.last().unwrap(),
        // Rotation::prev());     let q_padding = meta.query_fixed(q_padding,
        // Rotation::cur());     let q_padding_last =
        // meta.query_fixed(q_padding_last, Rotation::cur());     let length =
        // meta.query_advice(input_len, Rotation::cur());
        //     let is_final_padding_row =
        //         meta.query_advice(*is_paddings.last().unwrap(), Rotation(-2));
        //     // All padding selectors need to be boolean
        //     for is_padding in is_paddings.iter() {
        //         let is_padding = meta.query_advice(*is_padding, Rotation::cur());
        //         cb.condition(meta.query_fixed(q_enable, Rotation::cur()), |cb| {
        //             cb.require_boolean("is_padding boolean", is_padding);
        //         });
        //     }
        //     // Now for each padding selector
        //     for idx in 0..is_paddings.len() {
        //         // Previous padding selector can be on the previous row
        //         let is_padding_prev = if idx == 0 {
        //             prev_is_padding.expr()
        //         } else {
        //             meta.query_advice(is_paddings[idx - 1], Rotation::cur())
        //         };
        //         let is_padding = meta.query_advice(is_paddings[idx],
        // Rotation::cur());         let is_first_padding = is_padding.clone() -
        // is_padding_prev.clone(); // Check padding transition 0 -> 1 done only once
        //         cb.condition(q_padding.expr(), |cb| {
        //             cb.require_boolean("padding step boolean",
        // is_first_padding.clone());         });
        //         // Padding start/intermediate byte, all padding rows except the last
        // one         cb.condition(
        //             and::expr([
        //                 (q_padding.expr() - q_padding_last.expr()),
        //                 is_padding.expr(),
        //             ]),
        //             |cb| {
        //                 // Input bytes need to be zero, or 128 if this is the first
        // padding byte                 cb.require_equal(
        //                     "padding start/intermediate byte",
        //                     input_bytes[idx].clone(),
        //                     is_first_padding.expr() * 128.expr(),
        //                 );
        //             },
        //         );
        //         // Padding start/intermediate byte, last padding row but not in the
        // final block         cb.condition(
        //             and::expr([
        //                 q_padding_last.expr(),
        //                 is_padding.expr(),
        //                 not::expr(is_final_padding_row.expr()),
        //             ]),
        //             |cb| {
        //                 // Input bytes need to be zero, or 128 if this is the first
        // padding byte                 cb.require_equal(
        //                     "padding start/intermediate byte",
        //                     input_bytes[idx].clone(),
        //                     is_first_padding.expr() * 128.expr(),
        //                 );
        //             },
        //         );
        //     }
        //     // The last row containing input/padding data in the final block needs to
        //     // contain the length in bits (Only input lengths up to 2**32 - 1
        //     // bits are supported, which is lower than the spec of 2**64 - 1 bits)
        //     cb.condition(
        //         and::expr([
        //             q_padding_last.expr(),
        //             is_final_padding_row.expr(),
        //             not::expr(meta.query_advice(is_dummy, Rotation::cur())),
        //         ]),
        //         |cb| {
        //             cb.require_equal("padding length", decode::expr(w), length.expr()
        // * 8.expr());         }, ); cb.gate(1.expr())
        // });

        // Length
        // meta.create_gate("length", |meta| {
        //     let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
        //     let q_padding = meta.query_fixed(q_padding, Rotation::cur());
        //     // let is_final = meta.query_advice(is_final, Rotation::cur());
        //     // let start_new_hash = start_new_hash(meta);
        //     let length_prev = meta.query_advice(input_len, Rotation::prev());
        //     let length = meta.query_advice(input_len, Rotation::cur());
        //     //let data_rlc_prev = meta.query_advice(data_rlc, Rotation::prev());
        //     //let data_rlc = meta.query_advice(data_rlc, Rotation::cur());
        //     // Update the length/data_rlc on rows where we absorb data
        //     cb.condition(q_padding.expr(), |cb| {
        //         // Length increases by the number of bytes that aren't padding
        //         // In a new block we have to start from 0 if the previous block was
        // the final         // one
        //         cb.require_equal(
        //             "update length",
        //             length.clone(),
        //             length_prev.clone()
        //                 + sum::expr(is_paddings.iter().map(|is_padding| {
        //                     not::expr(meta.query_advice(*is_padding,
        // Rotation::cur()))                 })),
        //         );
        //     });
        //     cb.gate(1.expr())
        // });

        // Make sure data is consistent between blocks
        // meta.create_gate("cross block data consistency", |meta| {
        //     let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
        //     let to_const =
        //         |value: &String| -> &'static str {
        // Box::leak(value.clone().into_boxed_str()) };     let q_first =
        // meta.query_fixed(q_first, Rotation::cur());     let q_init_state =
        // meta.query_fixed(q_init_state, Rotation::cur());     let mut add =
        // |name: &'static str, column: Column<Advice>| {         let last_rot =
        //             Rotation(-((NUM_END_ROWS + NUM_ROUNDS - NUM_WORDS_TO_ABSORB) as
        // i32));         let value_to_copy = meta.query_advice(column,
        // last_rot);         let prev_value = meta.query_advice(column,
        // Rotation::prev());         let cur_value = meta.query_advice(column,
        // Rotation::cur()); // On squeeze rows fetch the last used value
        //         cb.condition(meta.query_fixed(q_squeeze, Rotation::cur()), |cb| {
        //             cb.require_equal(
        //                 to_const(&format!("{} copy check", name)),
        //                 cur_value.expr(),
        //                 value_to_copy.expr(),
        //             );
        //         });
        //         // On first rows keep the length the same, or reset the length when
        // starting a         // new hash
        //         cb.condition(
        //             meta.query_fixed(q_start, Rotation::cur()) - q_init_state.expr(),
        //             |cb| {
        //                 cb.require_equal(
        //                     to_const(&format!("{} equality check", name)),
        //                     cur_value.expr(),
        //                     prev_value.expr(), // * not::expr(start_new_hash.expr()),
        //                 );
        //             },
        //         );
        //         // Set the value to zero on the first row
        //         cb.condition(q_first.expr(), |cb| {
        //             cb.require_equal(
        //                 to_const(&format!("{} initialized to 0", name)),
        //                 cur_value.clone(),
        //                 0.expr(),
        //             );
        //         });
        //     };
        //     add("length", input_len);
        //     // add("data_rlc", data_rlc);
        //     add("last padding", *is_paddings.last().unwrap());

        //     cb.gate(1.expr())
        // });

        // Squeeze
        meta.create_gate("squeeze", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // Squeeze out the hash
            let hash_parts = [new_a, &a, &b, &c, new_e, &e, &f, &g];
            let hash_bytes = hash_parts
                .into_iter()
                .flat_map(|bits| to_le_bytes::expr(bits))
                .collect::<Vec<Expression<F>>>();
            let hash_words = hash_bytes
                .chunks(4)
                .map(|vals| {
                    let mut sum = 0u64.expr();
                    for idx in 0..4 {
                        sum = sum + vals[idx].clone() * (1u64 << (24 - 8 * idx)).expr();
                    }
                    sum
                })
                .collect::<Vec<Expression<F>>>();
            // let r = meta.query_advice(randomness, Rotation::cur());
            // let rlc = compose_rlc::expr(&hash_bytes, r);
            let h_a_outs = (0..4)
                .map(|idx| meta.query_advice(h_a_out, Rotation(-idx)))
                .collect::<Vec<Expression<F>>>();
            let h_e_outs = (0..4)
                .map(|idx| meta.query_advice(h_e_out, Rotation(-idx)))
                .collect::<Vec<Expression<F>>>();
            for idx in 0..4 {
                cb.require_equal(
                    "equal ouputs of a,b,c,d",
                    h_a_outs[idx].expr(),
                    hash_words[idx].expr(),
                );
                cb.require_equal(
                    "equal ouputs of e,f,g,h",
                    h_e_outs[idx].expr(),
                    hash_words[4 + idx].expr(),
                );
            }
            // let output_words = (0..8)
            //     .map(|idx| meta.query_advice(output_words, Rotation(-(7 - idx))))
            //     .collect::<Vec<Expression<F>>>();
            // for (hash_word, output_word) in hash_words.into_iter().zip(output_words) {
            //     // cb.condition(meta.query_advice(is_final, Rotation::cur()), |cb| {
            //     //     cb.require_equal("output words check", hash_word, output_word);
            //     // });
            //     cb.require_equal("output words check", hash_word, output_word);
            // }
            cb.gate(meta.query_fixed(q_squeeze, Rotation::cur()))
        });

        // meta.create_gate("is_dummy check", |meta| {
        //     let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
        //     let is_dummy_change = meta.query_advice(is_dummy, Rotation::cur())
        //         - meta.query_advice(is_dummy, Rotation::prev());
        //     let is_final_prev = meta.query_advice(is_final, Rotation::prev());
        //     cb.require_boolean(
        //         "is_dummy_change should be boolean (1->0 is not allowed)",
        //         is_dummy_change.expr(),
        //     );
        //     cb.condition(is_dummy_change.expr(), |cb| {
        //         cb.require_equal("is_final_prev==1", is_final_prev, 1.expr());
        //     });
        //     cb.gate(and::expr(&[
        //         not::expr(meta.query_fixed(q_init_state, Rotation::cur())),
        //         meta.query_fixed(q_enable, Rotation::cur()),
        //     ]))
        // });

        info!("degree: {}", meta.degree());

        Self {
            q_enable,
            // q_first,
            q_extend,
            q_start,
            q_compression,
            q_end,
            q_padding,
            // q_padding_last,
            q_squeeze,
            // q_init_state,
            // q_init_h_a,
            // q_init_h_e,
            word_w,
            word_a,
            word_e,
            // is_final,
            // is_paddings,
            // is_dummy,
            round_cst,
            h_a_in,
            h_e_in,
            h_a_out,
            h_e_out,
            // input_len,
            input_words,
            // is_output_enabled,
            // output_words,
            _marker: PhantomData,
        }
    }

    // fn assign(
    //     &self,
    //     region: &mut Region<'_, F>,
    //     witness: &[ShaRow<F>],
    //     assigned_rows: &mut Sha256AssignedRows<F>,
    // ) -> Result<Sha256AssignedRows<F>, Error> {
    //     let mut assigned_rows = Sha256AssignedRows::new();
    //     for (offset, sha256_row) in witness.iter().enumerate() {
    //         self.set_row(region, sha256_row, &mut assigned_rows)?
    //     }
    //     Ok(assigned_rows)
    // }

    /// Given the input, returns a vector of the assigned cells for the hash
    /// results.
    ///
    /// # Arguments
    /// * region - a region where the witnesses are assigned.
    /// * inputs - a vector of input bytes.
    ///
    /// # Return values
    /// Returns a vector of the assigned cells for the hash results.
    pub fn digest(
        &self,
        region: &mut Region<'_, F>,
        input: &[u8],
        hs: [u64; 8],
    ) -> Result<(Sha256AssignedRows<F>, [u64; 8]), Error> {
        let (witness, next_hs) = self.compute_witness(input, hs);
        let mut assigned_rows = Sha256AssignedRows::new(0);
        self.assign_witness(region, &witness, &mut assigned_rows)?;
        Ok((assigned_rows, next_hs))
    }
    /// Given the witness for each row, returns a vector of the assigned cells
    /// for the hash.
    pub fn assign_witness(
        &self,
        region: &mut Region<'_, F>,
        witness: &[ShaRow<F>],
        assigned_rows: &mut Sha256AssignedRows<F>,
    ) -> Result<(), Error> {
        // let mut assigned_rows = Sha256AssignedRows::new();
        for sha256_row in witness.iter() {
            self.set_row(region, sha256_row, assigned_rows)?
        }
        Ok(())
    }

    fn set_row(
        &self,
        region: &mut Region<'_, F>,
        row: &ShaRow<F>,
        assigned_rows: &mut Sha256AssignedRows<F>,
    ) -> Result<(), Error> {
        let offset = assigned_rows.offset;
        assigned_rows.offset += 1;
        let round = offset % (NUM_ROUNDS + 8);
        // let cur_offset = offset - pre_sha2_row_numbers;
        // Fixed values
        for (name, column, value) in &[
            ("q_enable", self.q_enable, F::from(true)),
            // (
            //     "q_first",
            //     self.q_first,
            //     F::from(4 * (offset / 4) == pre_sha2_row_numbers),
            // ),
            ("q_start", self.q_start, F::from(round < 4)),
            (
                "q_extend",
                self.q_extend,
                F::from((4 + 16..4 + NUM_ROUNDS).contains(&round)),
            ),
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
            // ("q_padding_last", self.q_padding_last, F::from(round == 19)),
            (
                "q_squeeze",
                self.q_squeeze,
                F::from(round == NUM_ROUNDS + 7),
            ),
            // (
            //     "q_init_state",
            //     self.q_init_state,
            //     F::from(4 * (offset / 4) == pre_sha2_row_numbers),
            // ),
            (
                "round_cst",
                self.round_cst,
                F::from(if (4..NUM_ROUNDS + 4).contains(&round) {
                    ROUND_CST[round - 4] as u64
                } else {
                    0
                }),
            ),
            // (
            //     "q_init_h_a",
            //     self.q_init_h_a,
            //     F::from(if offset < 4 { H[3 - offset] as u64 } else { 0 }),
            // ),
            // (
            //     "q_init_h_e",
            //     self.q_init_h_e,
            //     F::from(if offset < 4 { H[7 - offset] as u64 } else { 0 }),
            // ),
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
            // (
            //     "padding selectors",
            //     self.is_paddings.as_slice(),
            //     row.is_paddings.as_slice(),
            // ),
            // (
            //     "is_final",
            //     [self.is_final].as_slice(),
            //     [row.is_final].as_slice(),
            // ),
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

        let h_a_in = region.assign_advice(
            || format!("assign {} {} {}", "h_a_in", 0, offset),
            self.h_a_in,
            offset,
            || Value::known(F::from(row.h_a_in as u64)),
        )?;
        let h_e_in = region.assign_advice(
            || format!("assign {} {} {}", "h_e_in", 0, offset),
            self.h_e_in,
            offset,
            || Value::known(F::from(row.h_e_in as u64)),
        )?;
        let h_a_out = region.assign_advice(
            || format!("assign {} {} {}", "h_a_out", 0, offset),
            self.h_a_out,
            offset,
            || Value::known(F::from(row.h_a_out as u64)),
        )?;
        let h_e_out = region.assign_advice(
            || format!("assign {} {} {}", "h_e_out", 0, offset),
            self.h_e_out,
            offset,
            || Value::known(F::from(row.h_e_out as u64)),
        )?;

        // let is_output_enabled = region.assign_advice(
        //     || format!("assign {} {} {}", "is_output_enabled", 0, cur_offset),
        //     self.is_output_enabled,
        //     cur_offset,
        //     || Value::known(F::from(row.is_final && round == NUM_ROUNDS + 7)),
        // )?;

        // let input_len = region.assign_advice(
        //     || format!("assign {} {} {}", "length", 0, cur_offset),
        //     self.input_len,
        //     cur_offset,
        //     || Value::known(F::from(row.length as u64)),
        // )?;

        let input_word = region.assign_advice(
            || format!("assign {} {} {}", "input_word", 0, offset),
            self.input_words,
            offset,
            || Value::known(row.input_word),
        )?;

        // let output_word = region.assign_advice(
        //     || format!("assign {} {} {}", "output_word", 0, offset),
        //     self.output_words,
        //     offset,
        //     || Value::known(row.output_word),
        // )?;

        // let is_dummy = region.assign_advice(
        //     || format!("assign {} {} {}", "is_dummy", 0, cur_offset),
        //     self.is_dummy,
        //     cur_offset,
        //     || Value::known(F::from(row.is_dummy)),
        // )?;

        if round < 4 {
            assigned_rows.h_a_in.push(h_a_in);
            assigned_rows.h_e_in.push(h_e_in);
        }

        if (4..20).contains(&round) {
            assigned_rows.input_words.push(input_word);
            // assigned_rows.is_dummy.push(is_dummy);
        }

        if round >= NUM_ROUNDS + 4 {
            assigned_rows.h_a_out.push(h_a_out);
            assigned_rows.h_e_out.push(h_e_out);
        }

        Ok(())
    }

    /// Compute the witness values.
    pub fn compute_witness(&self, input_bytes: &[u8], hs: [u64; 8]) -> (Vec<ShaRow<F>>, [u64; 8]) {
        let bits = into_bits(input_bytes);
        assert_eq!(bits.len(), 8 * 64);
        let mut rows = Vec::<ShaRow<F>>::new();
        let mut hs = hs;
        // Padding
        // let length = bits.len();
        // let mut length_in_bits = into_bits(&(length as u64).to_be_bytes());
        // assert!(length_in_bits.len() == NUM_BITS_PADDING_LENGTH);
        // bits.push(1);
        // while (bits.len() + NUM_BITS_PADDING_LENGTH) % RATE_IN_BITS != 0 {
        //     bits.push(0);
        // }
        // bits.append(&mut length_in_bits);
        // assert!(bits.len() % RATE_IN_BITS == 0);
        // let target_round = bits.len() / RATE_IN_BITS - 1;
        // let mut dummy_inputs = vec![0u8; 8 * max_input_len - bits.len()];
        // bits.append(&mut dummy_inputs);

        // Set the initial state
        // let mut hs: [u64; 8] = H
        //     .iter()
        //     .map(|v| *v as u64)
        //     .collect::<Vec<_>>()
        //     .try_into()
        //     .unwrap();
        // let mut length = 0usize;
        // let mut in_padding = false;

        // assert_eq!(max_input_len % input_byte_per_circuit, 0);
        // assert_eq!(input_byte_per_circuit % (RATE_IN_BITS / 8), 0);
        // let num_chunks_per_circuit = input_byte_per_circuit / (RATE_IN_BITS / 8);

        // Process a block.
        let mut add_row = |w: u64,
                           a: u64,
                           e: u64,
                           input_word,
                           h_a_in: u32,
                           h_e_in: u32,
                           h_a_out: u32,
                           h_e_out: u32| {
            let word_to_bits = |value: u64, num_bits: usize| {
                into_bits(&value.to_be_bytes())[64 - num_bits..64]
                    .iter()
                    .map(|b| *b != 0)
                    .into_iter()
                    .collect::<Vec<_>>()
            };
            rows.push(ShaRow {
                w: word_to_bits(w, NUM_BITS_PER_WORD_W).try_into().unwrap(),
                a: word_to_bits(a, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
                e: word_to_bits(e, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
                input_word,
                h_a_in,
                h_e_in,
                h_a_out,
                h_e_out,
            });
        };

        // Set the state
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (hs[0], hs[1], hs[2], hs[3], hs[4], hs[5], hs[6], hs[7]);

        let mut add_row_start =
            |a: u64, e: u64| add_row(0, a, e, F::zero(), a as u32, e as u32, 0, 0);
        add_row_start(d, h);
        add_row_start(c, g);
        add_row_start(b, f);
        add_row_start(a, e);

        let mut ws = Vec::new();
        for (round, round_cst) in ROUND_CST.iter().enumerate() {
            // Padding/Length/Data rlc
            // let mut is_paddings = [false; ABSORB_WIDTH_PER_ROW_BYTES];
            //let mut data_rlcs = [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES];
            // if round < NUM_WORDS_TO_ABSORB {
            //     // padding/length
            //     for is_padding in is_paddings.iter_mut() {
            //         *is_padding = if length == bytes.len() {
            //             true
            //         } else {
            //             length += 1;
            //             false
            //         };
            //     }
            //     in_padding = *is_paddings.last().unwrap();
            // }

            // w
            let w_ext = if round < NUM_WORDS_TO_ABSORB {
                decode::value(&bits[round * 32..(round + 1) * 32])
            } else {
                let get_w = |offset: usize| ws[ws.len() - offset] & 0xFFFFFFFF;
                let s0 = rotate::value(get_w(15), 7)
                    ^ rotate::value(get_w(15), 18)
                    ^ shift::value(get_w(15), 3);
                let s1 = rotate::value(get_w(2), 17)
                    ^ rotate::value(get_w(2), 19)
                    ^ shift::value(get_w(2), 10);
                get_w(16) + s0 + get_w(7) + s1
            };
            let input_word = if round < NUM_WORDS_TO_ABSORB {
                let bytes = to_le_bytes::value(&bits[round * 32..(round + 1) * 32]);
                let sum: u64 = (bytes[0] as u64)
                    + (1u64 << 8) * (bytes[1] as u64)
                    + (1u64 << 16) * (bytes[2] as u64)
                    + (1u64 << 24) * (bytes[3] as u64);
                F::from(sum)
            } else {
                F::zero()
            };
            let w = w_ext & 0xFFFFFFFF;
            ws.push(w);

            // compression
            let s1 = rotate::value(e, 6) ^ rotate::value(e, 11) ^ rotate::value(e, 25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h + s1 + ch + (*round_cst as u64) + w;
            let s0 = rotate::value(a, 2) ^ rotate::value(a, 13) ^ rotate::value(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;

            // Add the row
            add_row(w_ext, a, e, input_word, 0, 0, 0, 0);

            // Truncate the newly calculated values
            a &= 0xFFFFFFFF;
            e &= 0xFFFFFFFF;
        }

        // Accumulate
        hs[0] += a;
        hs[1] += b;
        hs[2] += c;
        hs[3] += d;
        hs[4] += e;
        hs[5] += f;
        hs[6] += g;
        hs[7] += h;

        let hash_words = {
            let hash_bytes = hs
                .iter()
                .flat_map(|h| (*h as u32).to_be_bytes())
                .collect::<Vec<_>>();
            hash_bytes
                .chunks(8)
                .map(|vals| {
                    let mut sum = 0u64;
                    for idx in 0..8 {
                        sum = sum + (vals[idx] as u64) * (1u64 << (8 * idx));
                    }
                    sum
                })
                .collect::<Vec<u64>>()
        };
        if cfg!(debug_assertions) {
            dbg!("hash words {:x?}", hash_words.clone());
        }

        // Add end rows
        let mut add_row_end =
            |a: u64, e: u64| add_row(0, a, e, F::zero(), 0, 0, a as u32, e as u32);
        add_row_end(hs[3], hs[7]);
        add_row_end(hs[2], hs[6]);
        add_row_end(hs[1], hs[5]);
        add_row_end(hs[0], hs[4]);

        // Now truncate the results
        for h in hs.iter_mut() {
            *h &= 0xFFFFFFFF;
        }

        // // Process each block
        // let chunks = bits.chunks(RATE_IN_BITS);
        // for (idx, chunk) in chunks.enumerate() {
        //     // Adds a row
        //     let mut add_row = |w: u64,
        //                        a: u64,
        //                        e: u64,
        //                        is_final,
        //                        is_dummy,
        //                        length,
        //                        is_paddings,
        //                        input_word,
        //                        output_word,
        //                        h_a: u64,
        //                        h_e: u64| {
        //         let word_to_bits = |value: u64, num_bits: usize| {
        //             into_bits(&value.to_be_bytes())[64 - num_bits..64]
        //                 .iter()
        //                 .map(|b| *b != 0)
        //                 .into_iter()
        //                 .collect::<Vec<_>>()
        //         };
        //         rows.push(ShaRow {
        //             w: word_to_bits(w, NUM_BITS_PER_WORD_W).try_into().unwrap(),
        //             a: word_to_bits(a, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
        //             e: word_to_bits(e, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
        //             is_final,
        //             is_dummy,
        //             length,
        //             is_paddings,
        //             input_word,
        //             output_word,
        //             h_a,
        //             h_e,
        //         });
        //     };

        //     // Last block for this hash
        //     let is_final_block = idx == target_round; //num_chunks - 1;

        //     // Set the state
        //     let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
        //         (hs[0], hs[1], hs[2], hs[3], hs[4], hs[5], hs[6], hs[7]);

        //     // Add start rows
        //     let mut add_row_start = |a: u64, e: u64, h_a: u64, h_e: u64| {
        //         add_row(
        //             0,
        //             a,
        //             e,
        //             false,
        //             idx > target_round,
        //             length,
        //             [false, false, false, in_padding],
        //             F::zero(),
        //             F::zero(),
        //             h_a,
        //             h_e,
        //         )
        //     };
        //     let (h_a, h_b, h_c, h_d, h_e, h_f, h_g, h_h) =
        //         if idx % num_chunks_per_circuit == 0 && idx / num_chunks_per_circuit
        // != 0 {             (a, b, c, d, e, f, g, h)
        //         } else {
        //             (
        //                 H[0] as u64,
        //                 H[1] as u64,
        //                 H[2] as u64,
        //                 H[3] as u64,
        //                 H[4] as u64,
        //                 H[5] as u64,
        //                 H[6] as u64,
        //                 H[7] as u64,
        //             )
        //         };
        //     add_row_start(d, h, h_d, h_h);
        //     add_row_start(c, g, h_c, h_g);
        //     add_row_start(b, f, h_b, h_f);
        //     add_row_start(a, e, h_a, h_e);

        //     let mut ws = Vec::new();
        //     for (round, round_cst) in ROUND_CST.iter().enumerate() {
        //         // Padding/Length/Data rlc
        //         let mut is_paddings = [false; ABSORB_WIDTH_PER_ROW_BYTES];
        //         //let mut data_rlcs = [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES];
        //         if round < NUM_WORDS_TO_ABSORB {
        //             // padding/length
        //             for is_padding in is_paddings.iter_mut() {
        //                 *is_padding = if length == bytes.len() {
        //                     true
        //                 } else {
        //                     length += 1;
        //                     false
        //                 };
        //             }
        //             in_padding = *is_paddings.last().unwrap();
        //         }

        //         // w
        //         let w_ext = if round < NUM_WORDS_TO_ABSORB {
        //             decode::value(&chunk[round * 32..(round + 1) * 32])
        //         } else {
        //             let get_w = |offset: usize| ws[ws.len() - offset] & 0xFFFFFFFF;
        //             let s0 = rotate::value(get_w(15), 7)
        //                 ^ rotate::value(get_w(15), 18)
        //                 ^ shift::value(get_w(15), 3);
        //             let s1 = rotate::value(get_w(2), 17)
        //                 ^ rotate::value(get_w(2), 19)
        //                 ^ shift::value(get_w(2), 10);
        //             get_w(16) + s0 + get_w(7) + s1
        //         };
        //         let input_word = if round < NUM_WORDS_TO_ABSORB {
        //             let bytes = to_le_bytes::value(&chunk[round * 32..(round + 1) *
        // 32]);             let sum: u64 = (bytes[0] as u64)
        //                 + (1u64 << 8) * (bytes[1] as u64)
        //                 + (1u64 << 16) * (bytes[2] as u64)
        //                 + (1u64 << 24) * (bytes[3] as u64);
        //             F::from(sum)
        //         } else {
        //             F::zero()
        //         };
        //         let w = w_ext & 0xFFFFFFFF;
        //         ws.push(w);

        //         // compression
        //         let s1 = rotate::value(e, 6) ^ rotate::value(e, 11) ^
        // rotate::value(e, 25);         let ch = (e & f) ^ (!e & g);
        //         let temp1 = h + s1 + ch + (*round_cst as u64) + w;
        //         let s0 = rotate::value(a, 2) ^ rotate::value(a, 13) ^
        // rotate::value(a, 22);         let maj = (a & b) ^ (a & c) ^ (b & c);
        //         let temp2 = s0 + maj;

        //         h = g;
        //         g = f;
        //         f = e;
        //         e = d + temp1;
        //         d = c;
        //         c = b;
        //         b = a;
        //         a = temp1 + temp2;

        //         // Add the row
        //         add_row(
        //             w_ext,
        //             a,
        //             e,
        //             false,
        //             idx > target_round,
        //             if round < NUM_WORDS_TO_ABSORB {
        //                 length
        //             } else {
        //                 0
        //             },
        //             is_paddings,
        //             input_word,
        //             F::zero(),
        //             0,
        //             0,
        //         );

        //         // Truncate the newly calculated values
        //         a &= 0xFFFFFFFF;
        //         e &= 0xFFFFFFFF;
        //     }

        //     // Accumulate
        //     hs[0] += a;
        //     hs[1] += b;
        //     hs[2] += c;
        //     hs[3] += d;
        //     hs[4] += e;
        //     hs[5] += f;
        //     hs[6] += g;
        //     hs[7] += h;

        //     let hash_words = if is_final_block {
        //         let hash_bytes = hs
        //             .iter()
        //             .flat_map(|h| (*h as u32).to_be_bytes())
        //             .collect::<Vec<_>>();
        //         hash_bytes
        //             .chunks(8)
        //             .map(|vals| {
        //                 let mut sum = 0u64;
        //                 for idx in 0..8 {
        //                     sum = sum + (vals[idx] as u64) * (1u64 << (8 * idx));
        //                 }
        //                 sum
        //             })
        //             .collect()
        //     } else {
        //         vec![0u64; 4]
        //     };
        //     if cfg!(debug_assertions) && idx == target_round {
        //         dbg!("hash words {:x?}", hash_words.clone());
        //     }

        //     // Add end rows
        //     let mut add_row_end = |a: u64, e: u64, output_word: F| {
        //         add_row(
        //             0,
        //             a,
        //             e,
        //             false,
        //             idx > target_round,
        //             0,
        //             [false; ABSORB_WIDTH_PER_ROW_BYTES],
        //             F::zero(),
        //             output_word,
        //             0,
        //             0,
        //         )
        //     };
        //     add_row_end(hs[3], hs[7], F::from(hash_words[0]));
        //     add_row_end(hs[2], hs[6], F::from(hash_words[1]));
        //     add_row_end(hs[1], hs[5], F::from(hash_words[2]));
        //     add_row(
        //         0,
        //         hs[0],
        //         hs[4],
        //         is_final_block,
        //         idx > target_round,
        //         length,
        //         [false, false, false, in_padding],
        //         F::zero(),
        //         F::from(hash_words[3]),
        //         0,
        //         0,
        //     );

        //     // Now truncate the results
        //     for h in hs.iter_mut() {
        //         *h &= 0xFFFFFFFF;
        //     }
        // }
        (rows, hs)
    }
}

/// Compute row witness values.
// pub fn sha256<F: Field>(
//     bytes: &[u8],
//     max_input_len: usize,
//     input_byte_per_circuit: usize,
// ) -> Vec<ShaRow<F>> {
//     let mut bits = into_bits(bytes);
//     let mut rows = Vec::<ShaRow<F>>::new();
//     // Padding
//     let length = bits.len();
//     let mut length_in_bits = into_bits(&(length as u64).to_be_bytes());
//     assert!(length_in_bits.len() == NUM_BITS_PADDING_LENGTH);
//     bits.push(1);
//     while (bits.len() + NUM_BITS_PADDING_LENGTH) % RATE_IN_BITS != 0 {
//         bits.push(0);
//     }
//     bits.append(&mut length_in_bits);
//     assert!(bits.len() % RATE_IN_BITS == 0);
//     let target_round = bits.len() / RATE_IN_BITS - 1;
//     let mut dummy_inputs = vec![0u8; 8 * max_input_len - bits.len()];
//     bits.append(&mut dummy_inputs);

//     // Set the initial state
//     let mut hs: [u64; 8] = H
//         .iter()
//         .map(|v| *v as u64)
//         .collect::<Vec<_>>()
//         .try_into()
//         .unwrap();
//     let mut length = 0usize;
//     let mut in_padding = false;

//     assert_eq!(max_input_len % input_byte_per_circuit, 0);
//     assert_eq!(input_byte_per_circuit % (RATE_IN_BITS / 8), 0);
//     let num_chunks_per_circuit = input_byte_per_circuit / (RATE_IN_BITS / 8);

//     // Process each block
//     let chunks = bits.chunks(RATE_IN_BITS);
//     for (idx, chunk) in chunks.enumerate() {
//         // Adds a row
//         let mut add_row = |w: u64,
//                            a: u64,
//                            e: u64,
//                            is_final,
//                            is_dummy,
//                            length,
//                            is_paddings,
//                            input_word,
//                            output_word,
//                            h_a: u64,
//                            h_e: u64| {
//             let word_to_bits = |value: u64, num_bits: usize| {
//                 into_bits(&value.to_be_bytes())[64 - num_bits..64]
//                     .iter()
//                     .map(|b| *b != 0)
//                     .into_iter()
//                     .collect::<Vec<_>>()
//             };
//             rows.push(ShaRow {
//                 w: word_to_bits(w, NUM_BITS_PER_WORD_W).try_into().unwrap(),
//                 a: word_to_bits(a, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
//                 e: word_to_bits(e, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
//                 is_final,
//                 is_dummy,
//                 length,
//                 is_paddings,
//                 input_word,
//                 output_word,
//                 h_a,
//                 h_e,
//             });
//         };

//         // Last block for this hash
//         let is_final_block = idx == target_round; //num_chunks - 1;

//         // Set the state
//         let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
//             (hs[0], hs[1], hs[2], hs[3], hs[4], hs[5], hs[6], hs[7]);

//         // Add start rows
//         let mut add_row_start = |a: u64, e: u64, h_a: u64, h_e: u64| {
//             add_row(
//                 0,
//                 a,
//                 e,
//                 false,
//                 idx > target_round,
//                 length,
//                 [false, false, false, in_padding],
//                 F::zero(),
//                 F::zero(),
//                 h_a,
//                 h_e,
//             )
//         };
//         let (h_a, h_b, h_c, h_d, h_e, h_f, h_g, h_h) =
//             if idx % num_chunks_per_circuit == 0 && idx / num_chunks_per_circuit != 0 {
//                 (a, b, c, d, e, f, g, h)
//             } else {
//                 (
//                     H[0] as u64,
//                     H[1] as u64,
//                     H[2] as u64,
//                     H[3] as u64,
//                     H[4] as u64,
//                     H[5] as u64,
//                     H[6] as u64,
//                     H[7] as u64,
//                 )
//             };
//         add_row_start(d, h, h_d, h_h);
//         add_row_start(c, g, h_c, h_g);
//         add_row_start(b, f, h_b, h_f);
//         add_row_start(a, e, h_a, h_e);

//         let mut ws = Vec::new();
//         for (round, round_cst) in ROUND_CST.iter().enumerate() {
//             // Padding/Length/Data rlc
//             let mut is_paddings = [false; ABSORB_WIDTH_PER_ROW_BYTES];
//             //let mut data_rlcs = [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES];
//             if round < NUM_WORDS_TO_ABSORB {
//                 // padding/length
//                 for is_padding in is_paddings.iter_mut() {
//                     *is_padding = if length == bytes.len() {
//                         true
//                     } else {
//                         length += 1;
//                         false
//                     };
//                 }
//                 in_padding = *is_paddings.last().unwrap();
//             }

//             // w
//             let w_ext = if round < NUM_WORDS_TO_ABSORB {
//                 decode::value(&chunk[round * 32..(round + 1) * 32])
//             } else {
//                 let get_w = |offset: usize| ws[ws.len() - offset] & 0xFFFFFFFF;
//                 let s0 = rotate::value(get_w(15), 7)
//                     ^ rotate::value(get_w(15), 18)
//                     ^ shift::value(get_w(15), 3);
//                 let s1 = rotate::value(get_w(2), 17)
//                     ^ rotate::value(get_w(2), 19)
//                     ^ shift::value(get_w(2), 10);
//                 get_w(16) + s0 + get_w(7) + s1
//             };
//             let input_word = if round < NUM_WORDS_TO_ABSORB {
//                 let bytes = to_le_bytes::value(&chunk[round * 32..(round + 1) * 32]);
//                 let sum: u64 = (bytes[0] as u64)
//                     + (1u64 << 8) * (bytes[1] as u64)
//                     + (1u64 << 16) * (bytes[2] as u64)
//                     + (1u64 << 24) * (bytes[3] as u64);
//                 F::from(sum)
//             } else {
//                 F::zero()
//             };
//             let w = w_ext & 0xFFFFFFFF;
//             ws.push(w);

//             // compression
//             let s1 = rotate::value(e, 6) ^ rotate::value(e, 11) ^ rotate::value(e, 25);
//             let ch = (e & f) ^ (!e & g);
//             let temp1 = h + s1 + ch + (*round_cst as u64) + w;
//             let s0 = rotate::value(a, 2) ^ rotate::value(a, 13) ^ rotate::value(a, 22);
//             let maj = (a & b) ^ (a & c) ^ (b & c);
//             let temp2 = s0 + maj;

//             h = g;
//             g = f;
//             f = e;
//             e = d + temp1;
//             d = c;
//             c = b;
//             b = a;
//             a = temp1 + temp2;

//             // Add the row
//             add_row(
//                 w_ext,
//                 a,
//                 e,
//                 false,
//                 idx > target_round,
//                 if round < NUM_WORDS_TO_ABSORB {
//                     length
//                 } else {
//                     0
//                 },
//                 is_paddings,
//                 input_word,
//                 F::zero(),
//                 0,
//                 0,
//             );

//             // Truncate the newly calculated values
//             a &= 0xFFFFFFFF;
//             e &= 0xFFFFFFFF;
//         }

//         // Accumulate
//         hs[0] += a;
//         hs[1] += b;
//         hs[2] += c;
//         hs[3] += d;
//         hs[4] += e;
//         hs[5] += f;
//         hs[6] += g;
//         hs[7] += h;

//         let hash_words = if is_final_block {
//             let hash_bytes = hs
//                 .iter()
//                 .flat_map(|h| (*h as u32).to_be_bytes())
//                 .collect::<Vec<_>>();
//             hash_bytes
//                 .chunks(8)
//                 .map(|vals| {
//                     let mut sum = 0u64;
//                     for idx in 0..8 {
//                         sum = sum + (vals[idx] as u64) * (1u64 << (8 * idx));
//                     }
//                     sum
//                 })
//                 .collect()
//         } else {
//             vec![0u64; 4]
//         };
//         if cfg!(debug_assertions) && idx == target_round {
//             dbg!("hash words {:x?}", hash_words.clone());
//         }

//         // Add end rows
//         let mut add_row_end = |a: u64, e: u64, output_word: F| {
//             add_row(
//                 0,
//                 a,
//                 e,
//                 false,
//                 idx > target_round,
//                 0,
//                 [false; ABSORB_WIDTH_PER_ROW_BYTES],
//                 F::zero(),
//                 output_word,
//                 0,
//                 0,
//             )
//         };
//         add_row_end(hs[3], hs[7], F::from(hash_words[0]));
//         add_row_end(hs[2], hs[6], F::from(hash_words[1]));
//         add_row_end(hs[1], hs[5], F::from(hash_words[2]));
//         add_row(
//             0,
//             hs[0],
//             hs[4],
//             is_final_block,
//             idx > target_round,
//             length,
//             [false, false, false, in_padding],
//             F::zero(),
//             F::from(hash_words[3]),
//             0,
//             0,
//         );

//         // Now truncate the results
//         for h in hs.iter_mut() {
//             *h &= 0xFFFFFFFF;
//         }
//     }
//     rows
// }

// fn multi_sha256<F: Field>(bytes: &[Vec<u8>], r: F) -> Vec<ShaRow<F>> {
//     let mut rows: Vec<ShaRow<F>> = Vec::new();
//     for bytes in bytes {
//         sha256(&mut rows, bytes, r);
//     }
//     rows
// }

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    #[derive(Debug, Clone)]
    struct TestSha256Config<F: Field> {
        sha256_config: Sha256CompressionConfig<F>,
    }

    #[derive(Default, Debug, Clone)]
    struct TestSha256<F: Field> {
        input: Vec<u8>,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestSha256<F> {
        type Config = TestSha256Config<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha256_config = Sha256CompressionConfig::configure(meta);
            Self::Config { sha256_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // let sha256chip =
            //     Sha256CompressionConfig::new(config.sha256_config.clone(),
            // self.max_input_len);
            let init_hs = H;
            layouter.assign_region(
                || "digest",
                |mut region| {
                    config
                        .sha256_config
                        .digest(&mut region, &self.input[0..64], init_hs)
                },
            )?;
            //layouter.constrain_instance(first_r.cell(), config.instance, 0)?;
            Ok(())
        }
    }

    fn verify<F: Field>(k: u32, input: Vec<u8>, success: bool) {
        let circuit = TestSha256 {
            input,
            _f: PhantomData,
        };

        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        let verify_result = prover.verify();
        if verify_result.is_ok() != success {
            if let Some(errors) = verify_result.err() {
                for error in errors.iter() {
                    println!("{}", error);
                }
            }
            panic!();
        }
    }

    #[test]
    fn bit_sha256_simple1() {
        let k = 8;
        let inputs = (0u8..64).collect::<Vec<_>>();
        verify::<Fr>(k, inputs, true);
    }

    // #[test]
    // fn bit_sha256_simple2() {
    //     let k = 11;
    //     let inputs = vec![1u8; 1000];
    //     verify::<Fr>(k, inputs, 1024, true);
    // }

    // #[test]
    // fn bit_sha256_simple3() {
    //     let k = 11;
    //     let inputs = vec![0u8];
    //     verify::<Fr>(k, inputs, 128, true);
    // }

    #[derive(Debug, Clone)]
    struct TestSha256DoubleConfig<F: Field> {
        sha256_configs: [Sha256CompressionConfig<F>; 2],
    }

    #[derive(Debug, Clone)]
    enum Sha256Strategy {
        Vertical,
        Horizontal,
    }

    #[derive(Debug, Clone)]
    struct TestSha256Double<F: Field> {
        input: Vec<u8>,
        strategy: Sha256Strategy,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestSha256Double<F> {
        type Config = TestSha256DoubleConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha256_config1 = Sha256CompressionConfig::configure(meta);
            let sha256_config2 = Sha256CompressionConfig::configure(meta);
            Self::Config {
                sha256_configs: [sha256_config1, sha256_config2],
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // assert!(self.max_input_len % 2 == 0);
            // let sha256chip1 =
            //     Sha256BitChip::new(config.sha256_configs[0].clone(), self.max_input_len /
            // 2); let sha256chip2 =
            //     Sha256BitChip::new(config.sha256_configs[1].clone(), self.max_input_len /
            // 2);
            let init_hs = H;
            let (witness0, next_hs) = config.sha256_configs[0]
                .compute_witness(&self.input[0..self.input.len() / 2], init_hs);
            let (witness1, _) = config.sha256_configs[1]
                .compute_witness(&self.input[self.input.len() / 2..self.input.len()], next_hs);

            layouter.assign_region(
                || "digest double",
                |mut region| {
                    // sha256chip1.digest(&mut region, &self.input[0..self.input.len() / 2]);
                    let mut assigned_rows1 = Sha256AssignedRows::<F>::new(0);
                    config.sha256_configs[0].assign_witness(
                        &mut region,
                        &witness0,
                        &mut assigned_rows1,
                    )?;
                    let mut assigned_rows2 = match self.strategy {
                        Sha256Strategy::Vertical => {
                            Sha256AssignedRows::new(Sha256CompressionConfig::<F>::ROWS_PER_BLOCK)
                        }
                        Sha256Strategy::Horizontal => Sha256AssignedRows::new(0),
                    };
                    let next_config = match self.strategy {
                        Sha256Strategy::Vertical => &config.sha256_configs[0],
                        Sha256Strategy::Horizontal => &config.sha256_configs[1],
                    };
                    next_config.assign_witness(&mut region, &witness1, &mut assigned_rows2)?;
                    let h_outs = assigned_rows1.get_h_outs();
                    assert_eq!(h_outs.len(), 1);
                    let h_ins = assigned_rows2.get_h_ins();
                    assert_eq!(h_ins.len(), 1);
                    for (h_in, h_out) in h_ins[0].iter().zip(h_outs[0].iter()) {
                        region.constrain_equal(h_in.cell(), h_out.cell())?;
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    fn verify_double<F: Field>(k: u32, input: Vec<u8>, strategy: Sha256Strategy, success: bool) {
        let circuit = TestSha256Double {
            input,
            strategy,
            _f: PhantomData,
        };

        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        let verify_result = prover.verify();
        if verify_result.is_ok() != success {
            if let Some(errors) = verify_result.err() {
                for error in errors.iter() {
                    println!("{}", error);
                }
            }
            panic!();
        }
    }

    #[test]
    fn bit_sha256_double_vertical() {
        let k = 11;
        let inputs = vec![0u8; 128];
        verify_double::<Fr>(k, inputs, Sha256Strategy::Vertical, true);
    }

    #[test]
    fn bit_sha256_double_horizontal() {
        let k = 11;
        let inputs = vec![0u8; 128];
        verify_double::<Fr>(k, inputs, Sha256Strategy::Horizontal, true);
    }
}
