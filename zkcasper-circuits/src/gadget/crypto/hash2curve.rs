//! The chip that implements `draft-irtf-cfrg-hash-to-curve-16`
//! https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16

use std::{cell::RefCell, iter, marker::PhantomData};

use crate::{
    util::{bigint_to_le_bytes, decode_into_field, decode_into_field_be},
    witness::HashInput,
};
use eth_types::{AppCurveExt, Field, HashCurveExt, Spec};
use gadgets::binary_number::AsBits;
use halo2_base::{
    safe_types::{GateInstructions, RangeInstructions, SafeBytes32, SafeTypeChip},
    utils::ScalarField,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{CRTInteger, ProperUint},
    ecc::EccChip,
    fields::{
        fp::FpChip, vector::FieldVector, FieldChip, FieldExtConstructor, PrimeField, Selectable,
    },
};
use halo2_proofs::{circuit::Region, plonk::Error};
use halo2curves::group::GroupEncoding;
use itertools::Itertools;
use lazy_static::{__Deref, lazy_static};
use num_bigint::{BigInt, BigUint};
use pasta_curves::arithmetic::SqrtRatio;

use super::{
    sha256::HashChip,
    util::{fp2_sgn0, i2osp, strxor},
    Fp2Chip, Fp2Point, G1Point, G2Point,
};

const G2_EXT_DEGREE: usize = 2;

// L = ceil((ceil(log2(p)) + k) / 8) (see section 5 of ietf draft link above)
const L: usize = 64;

#[derive(Debug)]
pub struct HashToCurveChip<'a, S: Spec, F: Field, HC: HashChip<F>> {
    hash_chip: &'a HC,
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<'a, S: Spec, F: Field, HC: HashChip<F> + 'a> HashToCurveChip<'a, S, F, HC> {
    pub fn new(hash_chip: &'a HC) -> Self {
        Self {
            hash_chip,
            _f: PhantomData,
            _spec: PhantomData,
        }
    }

    pub fn hash_to_curve<C: HashCurveExt>(
        &self,
        msg: HashInput<QuantumCell<F>>,
        fp_chip: &FpChip<F, C::Fp>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
        cache: &mut HashToCurveCache<F>,
    ) -> Result<G2Point<F>, Error>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        let u = self.hash_to_field::<C>(msg, fp_chip, ctx, region, cache)?;
        let p = self.map_to_curve::<C>(u, fp_chip, ctx, cache)?;
        Ok(p)
    }

    /// Implements [section 5.2 of `draft-irtf-cfrg-hash-to-curve-16`][hash_to_field].
    ///
    /// [hash_to_field]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.2
    ///
    /// References:
    /// - https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/6ce20a1/poc/hash_to_field.py#L49
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/hash-to-curve.ts#L128
    /// - https://github.com/succinctlabs/telepathy-circuits/blob/d5c7771/circuits/hash_to_field.circom#L11
    fn hash_to_field<C: HashCurveExt>(
        &self,
        msg: HashInput<QuantumCell<F>>,
        fp_chip: &FpChip<F, C::Fp>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
        cache: &mut HashToCurveCache<F>,
    ) -> Result<[Fp2Point<F>; 2], Error> {
        //
        let range = self.hash_chip.range();
        let gate = range.gate();
        let safe_types = SafeTypeChip::new(range);

        // constants
        let zero = ctx.load_zero();
        let one = ctx.load_constant(F::one());

        let assigned_msg = msg.into_assigned(ctx).to_vec();

        let len_in_bytes = 2 * G2_EXT_DEGREE * L;
        let extended_msg = Self::expand_message_xmd(
            assigned_msg,
            len_in_bytes,
            self.hash_chip,
            ctx,
            region,
            cache,
        )?;

        let limb_bases = cache.binary_bases.get_or_insert_with(|| {
            C::limb_bytes_bases()
                .into_iter()
                .map(|base| ctx.load_constant(base))
                .collect()
        });

        // 2^256
        let two_pow_256 = fp_chip.load_constant_uint(ctx, BigUint::from(2u8).pow(256));
        let fq_bytes = C::BYTES_FQ / 2;

        let mut fst = true;
        let u = extended_msg
            .chunks(L)
            .chunks(G2_EXT_DEGREE)
            .into_iter()
            .map(|elm_chunk| {
                FieldVector(
                    elm_chunk
                        .map(|tv| {
                            let mut buf = vec![zero; fq_bytes];
                            let rem = fq_bytes - 32;
                            buf[rem..].copy_from_slice(&tv[..32]);
                            let lo = decode_into_field_be::<F, C, _>(
                                buf.to_vec(),
                                &fp_chip.limb_bases,
                                gate,
                                ctx,
                            );

                            buf[rem..].copy_from_slice(&tv[32..]);
                            let hi = decode_into_field_be::<F, C, _>(
                                buf.to_vec(),
                                &fp_chip.limb_bases,
                                gate,
                                ctx,
                            );

                            let lo_2_256 = fp_chip.mul_no_carry(ctx, lo, two_pow_256.clone());
                            let lo_2_356_hi = fp_chip.add_no_carry(ctx, lo_2_256, hi);
                            fp_chip.carry_mod(ctx, lo_2_356_hi)
                        })
                        .collect_vec(),
                )
            })
            .collect_vec()
            .try_into()
            .unwrap();

        Ok(u)
    }

    pub fn map_to_curve<C: HashCurveExt>(
        &self,
        u: [Fp2Point<F>; 2],
        fp_chip: &FpChip<F, C::Fp>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> Result<G2Point<F>, Error>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        let fp2_chip = Fp2Chip::<_, C>::new(fp_chip);
        let ecc_chip = EccChip::<F, Fp2Chip<F, C>>::new(&fp2_chip);

        let [u0, u1] = u;

        let p1 = Self::map_to_curve_simple_swu::<C>(u0, &fp2_chip, ctx, cache);
        let p2 = Self::map_to_curve_simple_swu::<C>(u1, &fp2_chip, ctx, cache);

        let p_sum = ecc_chip.add_unequal(ctx, p1, p2, false);

        let iso_p = Self::isogeny_map::<C>(p_sum, &fp2_chip, ctx, cache);

        Ok(Self::clear_cofactor::<C>(iso_p, &ecc_chip, ctx, cache))
    }

    /// Implements [section 5.3 of `draft-irtf-cfrg-hash-to-curve-16`][expand_message_xmd].
    ///
    /// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3
    ///
    /// References:
    /// - https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/6ce20a1/poc/hash_to_field.py#L89
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/hash-to-curve.ts#L63
    /// - https://github.com/succinctlabs/telepathy-circuits/blob/d5c7771/circuits/hash_to_field.circom#L139
    fn expand_message_xmd(
        msg: Vec<AssignedValue<F>>,
        len_in_bytes: usize,
        hash_chip: &HC,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
        cache: &mut HashToCurveCache<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let range = hash_chip.range();
        let gate = range.gate();

        // constants
        const MAX_INPUT_SIZE: usize = 160;
        let zero = ctx.load_zero();
        let one = ctx.load_constant(F::one());

        // assign DST bytes & cache them
        let dst_len = ctx.load_constant(F::from(S::DST.len() as u64));
        let dst_prime = cache
            .dst_with_len
            .get_or_insert_with(|| {
                S::DST
                    .iter()
                    .map(|&b| ctx.load_constant(F::from(b as u64)))
                    .chain(iter::once(dst_len))
                    .collect()
            })
            .clone();

        // padding and length strings
        let z_pad = i2osp(0, HC::BLOCK_SIZE, |b| zero); // TODO: cache these
        let l_i_b_str = i2osp(len_in_bytes as u128, 2, |b| ctx.load_constant(b));

        // compute blocks
        let ell = len_in_bytes.div_ceil(HC::DIGEST_SIZE);
        let mut b_vals = Vec::with_capacity(ell);
        let msg_prime = z_pad
            .into_iter()
            .chain(msg)
            .chain(l_i_b_str)
            .chain(iter::once(zero))
            .chain(dst_prime.clone());

        let b_0 = hash_chip
            .digest::<MAX_INPUT_SIZE>(msg_prime.into(), ctx, region)?
            .output_bytes;

        b_vals.insert(
            0,
            hash_chip
                .digest::<MAX_INPUT_SIZE>(
                    b_0.into_iter()
                        .chain(iter::once(one))
                        .chain(dst_prime.clone())
                        .into(),
                    ctx,
                    region,
                )?
                .output_bytes,
        );

        for i in 1..ell {
            b_vals.insert(
                i,
                hash_chip
                    .digest::<MAX_INPUT_SIZE>(
                        strxor(b_0, b_vals[i - 1], gate, ctx)
                            .into_iter()
                            .chain(iter::once(ctx.load_constant(F::from(i as u64 + 1))))
                            .chain(dst_prime.clone())
                            .into(),
                        ctx,
                        region,
                    )?
                    .output_bytes,
            );
        }

        let uniform_bytes = b_vals
            .into_iter()
            .flatten()
            .take(len_in_bytes)
            .collect_vec();

        Ok(uniform_bytes)
    }

    /// Implements [section 6.2 of draft-irtf-cfrg-hash-to-curve-16][map_to_curve_simple_swu]
    ///
    /// [map_to_curve_simple_swu]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-F.1-3
    ///
    /// References:
    /// - https://github.com/mikelodder7/bls12_381_plus/blob/ml/0.5.6/src/hash_to_curve/map_g2.rs#L388
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/weierstrass.ts#L1175
    fn map_to_curve_simple_swu<C: HashCurveExt>(
        u: Fp2Point<F>,
        fp2_chip: &Fp2Chip<F, C>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> G2Point<F>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        let fp_chip = fp2_chip.fp_chip();
        let gate = fp_chip.range().gate();

        // constants
        let swu_a = cache
            .swu_a
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::SWU_A))
            .deref()
            .clone();
        let swu_b = cache
            .swu_b
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::SWU_B))
            .deref()
            .clone();
        let swu_z = cache
            .swu_z
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::SWU_Z))
            .deref()
            .clone();
        let fq2_one = cache
            .fq2_one
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::Fq::one()))
            .deref()
            .clone();

        let usq = fp2_chip.mul(ctx, u.clone(), u.clone()); // 1.  tv1 = u^2
        let z_usq = fp2_chip.mul(ctx, usq, swu_z.clone()); // 2.  tv1 = Z * tv1
        let zsq_u4 = fp2_chip.mul(ctx, z_usq.clone(), z_usq.clone()); // 3.  tv2 = tv1^2
        let tv2 = fp2_chip.add(ctx, zsq_u4, z_usq.clone()); // 4.  tv2 = tv2 + tv1
        let tv3 = fp2_chip.add_no_carry(ctx, tv2.clone(), fq2_one); // 5.  tv3 = tv2 + 1
        let x0_num = fp2_chip.mul(ctx, tv3, swu_b.clone()); // 6.  tv3 = B * tv3

        let x_den = {
            let tv2_is_zero = fp2_chip.is_zero(ctx, tv2.clone());
            let tv2_neg = fp2_chip.negate(ctx, tv2);

            fp2_chip.select(ctx, swu_z, tv2_neg, tv2_is_zero) // tv2_is_zero ? swu_z : tv2_neg
        }; // 7.  tv4 = tv2 != 0 ? -tv2 : Z

        let x_den = fp2_chip.mul(ctx, x_den, swu_a.clone()); // 8.  tv4 = A * tv4

        let x0_num_sqr = fp2_chip.mul(ctx, x0_num.clone(), x0_num.clone()); // 9.  tv2 = tv3^2
        let x_densq = fp2_chip.mul(ctx, x_den.clone(), x_den.clone()); // 10. tv6 = tv4^2
        let ax_densq = fp2_chip.mul(ctx, x_densq.clone(), swu_a); // 11. tv5 = A * tv6
        let tv2 = fp2_chip.add_no_carry(ctx, x0_num_sqr, ax_densq); // 12. tv2 = tv2 + tv5
        let tv2 = fp2_chip.mul(ctx, tv2, x0_num.clone()); // 13. tv2 = tv2 * tv3
        let gx_den = fp2_chip.mul(ctx, x_densq, x_den.clone()); // 14. tv6 = tv6 * tv4
        let tv5 = fp2_chip.mul(ctx, gx_den.clone(), swu_b); // 15. tv5 = B * tv6
        let gx0_num = fp2_chip.add(ctx, tv2, tv5); // 16. tv2 = tv2 + tv5

        let x = fp2_chip.mul(ctx, &z_usq, &x0_num); // 17.  x = tv1 * tv3

        let (is_gx1_square, y1) =
            Self::sqrt_ratio::<C>(gx0_num, gx_den, u.clone(), fp2_chip, ctx, cache); // 18.  (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

        let y = fp2_chip.mul(ctx, &z_usq, &u); // 19.  y = tv1 * u
        let y = fp2_chip.mul(ctx, y, y1.clone()); // 20.  y = y * y1
        let x = fp2_chip.select(ctx, x0_num, x, is_gx1_square); // 21.  x = is_gx1_square ? tv3 : x
        let y = fp2_chip.select(ctx, y1, y, is_gx1_square); // 22.  y = is_gx1_square ? y1 : y

        let to_neg = {
            let u_sgn = fp2_sgn0::<_, C>(u, ctx, fp_chip);
            let y_sgn = fp2_sgn0::<_, C>(y.clone(), ctx, fp_chip);
            gate.xor(ctx, u_sgn, y_sgn)
        }; // 23.  e1 = sgn0(u) == sgn0(y) // we implement an opposite condition: !e1 = sgn0(u) ^ sgn0(y)

        let y_neg = fp2_chip.negate(ctx, y.clone());
        let y = fp2_chip.select(ctx, y_neg, y, to_neg); // 24.  y = !e1 ? -y : y
        let x = fp2_chip.divide(ctx, x, x_den); // 25.  x = x / tv4

        G2Point::new(x, y)
    }

    /// Implements [Appendix E.3 of draft-irtf-cfrg-hash-to-curve-16][isogeny_map_g2]
    ///
    /// [isogeny_map_g2]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-E.3
    ///
    /// References:
    /// - https://github.com/mikelodder7/bls12_381_plus/blob/ml/0.5.6/src/g2.rs#L1153
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/hash-to-curve.ts#L167
    pub fn isogeny_map<C: HashCurveExt>(
        p: G2Point<F>,
        fp2_chip: &Fp2Chip<F, C>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> G2Point<F>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        // constants
        let iso_coeffs = cache
            .iso_coeffs
            .get_or_insert_with(|| {
                [
                    C::ISO_XNUM.to_vec(),
                    C::ISO_XDEN.to_vec(),
                    C::ISO_YNUM.to_vec(),
                    C::ISO_YDEN.to_vec(),
                ]
                .map(|coeffs| {
                    coeffs
                        .into_iter()
                        .map(|iso| fp2_chip.load_constant(ctx, iso))
                        .collect_vec()
                })
            })
            .deref()
            .clone();

        let fq2_zero = cache
            .fq2_zero
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::Fq::zero()))
            .deref()
            .clone();

        let [x_num, x_den, y_num, y_den] = iso_coeffs.map(|coeffs| {
            coeffs.into_iter().fold(fq2_zero.clone(), |acc, v| {
                let acc = fp2_chip.mul(ctx, acc, &p.x);
                let no_carry = fp2_chip.add_no_carry(ctx, acc, v);
                fp2_chip.carry_mod(ctx, no_carry)
            })
        });

        let x = { fp2_chip.divide_unsafe(ctx, x_num, x_den) };

        let y = {
            let tv = fp2_chip.divide_unsafe(ctx, y_num, y_den);
            fp2_chip.mul(ctx, &p.y, tv)
        };

        G2Point::new(x, y)
    }

    /// Implements [Appendix G.3 of draft-irtf-cfrg-hash-to-curve-16][clear_cofactor]
    ///
    /// [clear_cofactor]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-G.3
    ///
    /// References:
    /// - https://github.com/mikelodder7/bls12_381_plus/blob/ml/0.5.6/src/g2.rs#L956
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/bls12-381.ts#L1111
    fn clear_cofactor<C: HashCurveExt>(
        p: G2Point<F>,
        ecc_chip: &EccChip<F, Fp2Chip<F, C>>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> G2Point<F>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        let t1 = {
            // scalar multiplication is very expensive in terms of rows used
            // TODO: is there other ways to clear cofactor that avoid scalar multiplication?
            let tv = Self::mul_by_bls_x::<C>(p.clone(), ecc_chip, ctx, cache);
            ecc_chip.negate(ctx, tv)
        }; // [-x]P

        let t2 = Self::psi::<C>(p.clone(), ecc_chip.field_chip(), ctx, cache); // Ψ(P)

        let t3 = ecc_chip.double(ctx, p.clone()); // 2P
        let t3 = Self::psi2::<C>(t3, ecc_chip.field_chip(), ctx, cache); // Ψ²(2P)
        let t3 = ecc_chip.sub_unequal(ctx, t3, t2.clone(), false); // Ψ²(2P) - Ψ(P)

        let t2 = ecc_chip.add_unequal(ctx, t1.clone(), t2, false); // [-x]P + Ψ(P)
        let t2 = {
            let tv = Self::mul_by_bls_x::<C>(t2, ecc_chip, ctx, cache);
            ecc_chip.negate(ctx, tv)
        }; // [x²]P - [x]Ψ(P)

        // Ψ²(2P) - Ψ(P) + [x²]P - [x]Ψ(P)
        let t3 = ecc_chip.add_unequal(ctx, t3, t2, false);
        // Ψ²(2P) - Ψ(Plet ) + [x²]P - [x]Ψ(P) + [x]P
        let t3 = ecc_chip.sub_unequal(ctx, t3, t1, false);

        // Ψ²(2P) - Ψ(P) + [x²]P - [x]Ψ(P) + [x]P - 1P => [x²-x-1]P + [x-1]Ψ(P) + Ψ²(2P)
        ecc_chip.sub_unequal(ctx, t3, p, false)
    }

    // Implements [Appendix F.2.1 of draft-irtf-cfrg-hash-to-curve-16][sqrt_ration]
    //
    // [sqrt_ration]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-F.2.1
    fn sqrt_ratio<C: HashCurveExt>(
        num: Fp2Point<F>,
        div: Fp2Point<F>,
        u: Fp2Point<F>,
        fp2_chip: &Fp2Chip<F, C>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> (AssignedValue<F>, Fp2Point<F>)
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        let num_v = Self::assigned_fq2_to_value::<C>(&num);
        let div_v = Self::assigned_fq2_to_value::<C>(&div);
        let u = Self::assigned_fq2_to_value::<C>(&u);

        let (is_square, y) = C::Fq::sqrt_ratio(&num_v, &div_v);

        let is_square = ctx.load_witness(F::from(is_square.unwrap_u8() as u64));
        fp2_chip.fp_chip().gate().assert_bit(ctx, is_square); // assert is_square is boolean

        let y_assigned = fp2_chip.load_private(ctx, y);
        let y_sqr = fp2_chip.mul(ctx, y_assigned.clone(), y_assigned.clone()); // y_sqr = y1^2

        let ratio = fp2_chip.divide(ctx, num, div); // r = u / v

        let swu_z = cache
            .swu_z
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::SWU_Z));
        let ratio_z = fp2_chip.mul(ctx, ratio.clone(), swu_z.clone()); // r_z = r * z

        let y_check = fp2_chip.select(ctx, ratio, ratio_z, is_square); // y_check = is_square ? ratio : r_z

        fp2_chip.assert_equal(ctx, y_check, y_sqr); // assert y_check == y_sqr

        (is_square, y_assigned)
    }

    pub fn mul_by_bls_x<C: HashCurveExt>(
        p: G2Point<F>,
        ecc_chip: &EccChip<F, Fp2Chip<F, C>>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> G2Point<F>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        let bls_x_bits = cache
            .bsl_x_bits
            .get_or_insert_with(|| {
                (0..64)
                    .map(|i| ((C::BLS_X >> i) & 1) as u8)
                    .map(|b| ctx.load_constant(F::from(b as u64)))
                    .collect_vec()
            })
            .deref()
            .clone();

        ecc_chip.scalar_mult_bits(ctx, p, bls_x_bits, 4)
    }

    pub fn psi<C: HashCurveExt>(
        p: G2Point<F>,
        fp2_chip: &Fp2Chip<F, C>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> G2Point<F>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        // 1 / ((u+1) ^ ((q-1)/3))
        let psi_x = cache
            .psi_x
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::PSI_X));

        // 1 / ((u+1) ^ (p-1)/2)
        let psi_y = cache
            .psi_y
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::PSI_Y));

        let x_frob = fp2_chip.conjugate(ctx, p.x);
        let y_frob = fp2_chip.conjugate(ctx, p.y);

        let x = fp2_chip.mul(ctx, x_frob, psi_x.clone());
        let y = fp2_chip.mul(ctx, y_frob, psi_y.clone());

        G2Point::new(x, y)
    }

    pub fn psi2<C: HashCurveExt>(
        p: G2Point<F>,
        fp2_chip: &Fp2Chip<F, C>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> G2Point<F>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        // 1 / 2 ^ ((q-1)/3)
        let psi2_x = cache
            .psi2_x
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::PSI2_X));

        let x = fp2_chip.mul(ctx, p.x, psi2_x.clone());
        let y = fp2_chip.negate(ctx, p.y);

        G2Point::new(x, y)
    }

    fn assigned_fq2_to_value<C: HashCurveExt>(u: &Fp2Point<F>) -> C::Fq {
        C::get_fq(u.0.iter().map(|c| {
            bigint_to_le_bytes(
                c.limbs().iter().map(|e| *e.value()),
                C::LIMB_BITS,
                C::BYTES_FQ / 2,
            )
        }))
    }
}

#[derive(Clone, Debug, Default)]
pub struct HashToCurveCache<F: Field> {
    dst_with_len: Option<Vec<AssignedValue<F>>>,
    binary_bases: Option<Vec<AssignedValue<F>>>,
    swu_a: Option<Fp2Point<F>>,
    swu_b: Option<Fp2Point<F>>,
    swu_z: Option<Fp2Point<F>>,
    fq2_zero: Option<Fp2Point<F>>,
    fq2_one: Option<Fp2Point<F>>,
    iso_coeffs: Option<[Vec<Fp2Point<F>>; 4]>,
    psi_x: Option<Fp2Point<F>>,
    psi_y: Option<Fp2Point<F>>,
    psi2_x: Option<Fp2Point<F>>,
    bsl_x_bits: Option<Vec<AssignedValue<F>>>,
}

#[cfg(test)]
mod test {
    use std::vec;
    use std::{cell::RefCell, marker::PhantomData};

    use crate::gadget::crypto::Sha256Chip;
    use crate::sha256_circuit::Sha256CircuitConfig;
    use crate::table::Sha256Table;
    use crate::util::{print_fq2_dev, Challenges, IntoWitness, SubCircuitConfig};

    use super::*;
    use eth_types::Mainnet;
    use halo2_base::gates::range::RangeConfig;
    use halo2_base::safe_types::RangeChip;
    use halo2_base::SKIP_FIRST_PASS;
    use halo2_base::{
        gates::{builder::GateThreadBuilder, range::RangeStrategy},
        halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner},
            dev::MockProver,
            halo2curves::bn256::Fr,
            plonk::{Circuit, ConstraintSystem},
        },
    };
    use halo2_ecc::bigint::CRTInteger;
    use halo2_proofs::circuit::Value;
    use sha2::{Digest, Sha256};

    #[derive(Debug, Clone)]
    struct TestConfig<F: Field> {
        sha256_config: Sha256CircuitConfig<F>,
        pub max_byte_size: usize,
        range: RangeConfig<F>,
        challenges: Challenges<Value<F>>,
    }

    struct TestCircuit<S: Spec, F: Field> {
        builder: RefCell<GateThreadBuilder<F>>,
        range: RangeChip<F>,
        test_input: HashInput<QuantumCell<F>>,
        _spec: PhantomData<S>,
    }

    impl<S: Spec, F: Field> Circuit<F> for TestCircuit<S, F>
    where
        <S::SiganturesCurve as AppCurveExt>::Fq:
            FieldExtConstructor<<S::SiganturesCurve as AppCurveExt>::Fp, 2>,
    {
        type Config = TestConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha_table = Sha256Table::construct(meta);
            let sha256_configs = Sha256CircuitConfig::<F>::new::<Mainnet>(meta, sha_table);
            let range = RangeConfig::configure(
                meta,
                RangeStrategy::Vertical,
                &[Self::NUM_ADVICE],
                &[Self::NUM_LOOKUP_ADVICE],
                Self::NUM_FIXED,
                Self::LOOKUP_BITS,
                Self::K,
            );
            let challenges = Challenges::construct(meta);
            Self::Config {
                sha256_config: sha256_configs,
                max_byte_size: Self::MAX_BYTE_SIZE,
                range,
                challenges: Challenges::mock(Value::known(Sha256CircuitConfig::fixed_challenge())),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range.load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            let sha256 = Sha256Chip::new(
                &config.sha256_config,
                &self.range,
                config.challenges.sha256_input(),
                None,
                0,
            );

            let h2c_chip = HashToCurveChip::<Mainnet, F, _>::new(&sha256);
            let fp_chip =
                halo2_ecc::fields::fp::FpChip::<F, <S::SiganturesCurve as AppCurveExt>::Fp>::new(
                    &self.range,
                    S::SiganturesCurve::LIMB_BITS,
                    S::SiganturesCurve::NUM_LIMBS,
                );

            layouter.assign_region(
                || "hash to curve test",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    config.sha256_config.annotate_columns_in_region(&mut region);

                    let builder = &mut self.builder.borrow_mut();
                    let ctx = builder.main(0);

                    let mut cache = HashToCurveCache::<F>::default();
                    let hp = h2c_chip.hash_to_curve::<S::SiganturesCurve>(
                        self.test_input.clone(),
                        &fp_chip,
                        ctx,
                        &mut region,
                        &mut cache,
                    )?;

                    print_fq2_dev::<S::SiganturesCurve, F>(hp.x(), "res_p.x");
                    print_fq2_dev::<S::SiganturesCurve, F>(hp.y(), "res_p.y");

                    let extra_assignments = h2c_chip.hash_chip.take_extra_assignments();

                    let _ = builder.assign_all(
                        &config.range.gate,
                        &config.range.lookup_advice,
                        &config.range.q_lookup,
                        &mut region,
                        extra_assignments,
                    );

                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    impl<S: Spec, F: Field> TestCircuit<S, F> {
        const MAX_BYTE_SIZE: usize = 160;
        const NUM_ADVICE: usize = 25;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 5;
        const LOOKUP_BITS: usize = 8;
        const K: usize = 16;
    }

    #[test]
    fn test_hash_to_g2() {
        let k = TestCircuit::<Mainnet, Fr>::K as u32;

        let test_input = vec![0u8; 32];
        let range = RangeChip::default(TestCircuit::<Mainnet, Fr>::LOOKUP_BITS);
        let builder = GateThreadBuilder::new(false);
        let circuit = TestCircuit::<Mainnet, Fr> {
            builder: RefCell::new(builder),
            range,
            test_input: test_input.into_witness(),
            _spec: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
