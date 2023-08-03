use std::{marker::PhantomData, mem, iter, ops::Mul};

use eth_types::{Field, Mainnet, Spec};
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    util::Expr,
};
use halo2_base::{AssignedValue, Context, QuantumCell::{self, Constant}, safe_types::{RangeChip, SafeTypeChip, RangeInstructions, GateInstructions}, gates::range, utils::ScalarField};
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use num_bigint::BigUint;

use crate::{
    gadget::crypto::{HashChip, AssignedHashResult},
    sha256_circuit::Sha256CircuitConfig,
    // table::SHA256Table,
    util::{BaseConstraintBuilder, SubCircuitConfig},
    witness::{HashInput, HashInputChunk},
};

const SEED_SIZE: usize = 32;
const ROUND_SIZE: usize = 1;
const POSITION_WINDOW_SIZE: usize = 4;
const PIVOT_VIEW_SIZE: usize = SEED_SIZE + ROUND_SIZE;
const TOTAL_SIZE: usize = SEED_SIZE + ROUND_SIZE + POSITION_WINDOW_SIZE;

#[derive(Debug)]

pub struct ShuffleChip<'a, S: Spec, F: Field, HC: HashChip<F>> {
    hash_chip: &'a HC,
    _f: PhantomData<F>,
    _s: PhantomData<S>,
}

// // #[derive(Debug, Default)]
// // pub struct CommitteeCache {
// //     initialized_epoch: Option<Epoch>,
// //     shuffling: Vec<usize>,
// //     shuffling_positions: Vec<Option<NonZeroUsize>>,
// //     committees_per_slot: usize,
// //     slots_per_epoch: usize,
// // }

// // trait ShuffleInstructions<F: Field> {

// // }

// #[derive(Clone, Debug)]
// pub struct ShufflingConfig<F:Field, const ROUNDS: usize> {

//     pub sha256: Sha256CircuitConfig<F>,

//     pub list_items: Column<Advice>,
//     pub list_items_shuffled: [Column<Advice>; ROUNDS],

//     pub buffer: [Column<Advice>; TOTAL_SIZE],
//     pub source: Column<Advice>,

//     pub m1: Column<Advice>,
//     pub m2: Column<Advice>,

//     pub pivot: Column<Advice>,

//     pub byte_v: Column<Advice>,

//     // swap if 1 otherwise no swap
//     pub bit_v: Column<Advice>,

//     pub raw_pivot: Column<Advice>,
//     pub j: Column<Advice>,
// }

// impl <const ROUNDS: usize, F:Field> ShufflingConfig<F, ROUNDS> {
//     pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
//         let sha256_table = SHA256Table::construct(meta);
//         let sha256 = Sha256CircuitConfig::new::<Mainnet>(meta, sha256_table);

//         let list_items = meta.advice_column();
//         let list_items_shuffled = [meta.advice_column(); ROUNDS];
//         let m1 = meta.advice_column();
//         let m2 = meta.advice_column();
//         let pivot = meta.advice_column();
//         let byte_v = meta.advice_column();
//         let buffer = [();TOTAL_SIZE].map(|_| meta.advice_column());
//         let source = meta.advice_column();
//         let j = meta.advice_column();
//         let bit_v = meta.advice_column();
//         let raw_pivot = meta.advice_column();

//         // meta.create_gate("per round variables", |meta| {
//         //     let mut cb = BaseConstraintBuilder::default();
//         //     let pivot = meta.query_advice(pivot, Rotation::cur());
//         //     let m1 = meta.query_advice(m1, Rotation::cur());
//         //     let m2 = meta.query_advice(m2, Rotation::cur());

//         //     cb.require_equal("mirror m1 = (pivot + 2) / 2",
//         //     2u64.expr() * m1, pivot + 2u64.expr());
//         //     // cb.require_equal("mirror m2 = (pivot + list_size) / 2",
//         //     // 2u64.expr() * m2, pivot + )
//         //     cb.gate(1.expr())
//         // });
//         // meta.create_gate("swapped or not", |meta| {
//         //     let mut cb = BaseConstraintBuilder::default();
//         //     let pivot = meta.query_advice(pivot, Rotation::cur());

//         // });

//         Self {
//             list_items,
//             list_items_shuffled,
//             m1,
//             m2,
//             pivot,
//             buffer,
//             source,
//             byte_v,
//             j,
//             bit_v,
//             raw_pivot,
//             sha256,
//         }
//     }
// }

// pub struct ShufflingChip<F: Field, const ROUNDS: usize> {
//     pub config: ShufflingConfig<F,ROUNDS>,
//     _f:  PhantomData<F>,
// }

// impl <F: Field, const ROUNDS: usize> Chip<F> for ShufflingChip<F, ROUNDS> {
//     type Config = ShufflingConfig<F,ROUNDS>;

//     type Loaded = ();

//     fn config(&self) -> &Self::Config {
//         &self.config
//     }

//     fn loaded(&self) -> &Self::Loaded {
//         todo!()
//     }
// }

// impl <F: Field, const ROUNDS: usize> ShufflingChip<F, ROUNDS> {
//     pub fn configure(meta: &mut ConstraintSystem<F>) -> <Self as Chip<F>>::Config {
//        <Self as Chip<F>>::Config::configure(meta)
//     }

//     pub fn construct(config: <Self as Chip<F>>::Config) -> Self {
//         Self {
//             config,
//             _f: PhantomData,
//         }
//     }

// }

// pub fn shuffle<F: Field>(
//     mut layouter: impl Layouter<F>,
//     config: &ShufflingConfig<F, 1>,
//     seed: &[AssignedCell<F, F>],
//     list_items: &[AssignedCell<F, F>],
//     result_columns: &[AssignedCell<F, F>],
// ) -> Result<Vec<AssignedCell<F, F>>, Error> {
//     layouter.assign_region(|| "shuffle", |mut region| {
//         let list_size = list_items.len();
//         // HashInput::new(seed, list_size).configure(&mut reg
//         let bu = HashInputChunk::new(seed.to_vec(), false);
//         let h_input = HashInput::from( bu);
//         let buf = config.sha256.digest(&mut layouter, h_input);
//         todo!()
//     });
//     todo!()
// }
struct Buf<F: Field>([AssignedValue<F>; TOTAL_SIZE]);
use halo2_base::safe_types::SafeUint64;

impl<F: Field> Buf<F> {
    fn new(ctx: &mut Context<F>, seed: [AssignedValue<F>; SEED_SIZE]) -> Self {
        let mut buf = seed.to_vec();
        buf.extend_from_slice(&[ctx.load_zero(); TOTAL_SIZE - SEED_SIZE]);
        Self(buf.try_into().unwrap())
    }

    fn set_round(&mut self, ctx: &mut Context<F>, round: u8) {
        let r = ctx.load_constant(F::from(round as u64));
        self.0[SEED_SIZE] = r.into();
    }

    // Returns the little endian bytes representation of the raw pivot
    fn raw_pivot<HC: HashChip<F>>(
        &self,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
        hash_chip: &HC,
    ) -> Result<[AssignedValue<F>; 8], Error> {
        let hash_input = (self.0[0..PIVOT_VIEW_SIZE]).to_vec();
        let digest = hash_chip.digest::<33>(hash_input.into_iter().into(), ctx, region)?;
        let bytes = digest.output_bytes[0..mem::size_of::<u64>()].to_vec();
        Ok(bytes.try_into().unwrap())
        // let b = bytes.iter().map(|b| b.value());
        // let pivot = ctx.load_witness(F::from_bytes_le_unsecure(b));
        // Ok(pivot)
    }
    
    fn mix_in_position(&mut self, ctx: &mut Context<F>, position: &[F]) {
        // let le_bytes = position.to_le_bytes();
        let assigned_le_bytes: Vec<AssignedValue<F>> = position[0..POSITION_WINDOW_SIZE].into_iter().map(|b| ctx.load_witness(b)).collect();
        self.0[PIVOT_VIEW_SIZE..].copy_from_slice(&assigned_le_bytes);
    }
    fn hash<HC: HashChip<F>>(&mut self, ctx: &mut Context<F>, region: &mut Region<'_, F>, hash_chip: &HC) -> Result<AssignedHashResult<F>, Error> {
        let hash_input = self.0.to_vec();
        hash_chip.digest::<TOTAL_SIZE>(hash_input.into_iter().into(), ctx, region)
    }
}

impl<'a, S: Spec, F: Field, HC: HashChip<F> + 'a> ShuffleChip<'a, S, F, HC> {
    pub fn new(hash_chip: &'a HC) -> Self {
        Self {
            hash_chip,
            _f: PhantomData,
            _s: PhantomData,
        }
    }

    pub fn shuffle(
        &self,
        seed: HashInput<AssignedValue<F>>,
        list: Vec<QuantumCell<F>>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
        range_chip: &RangeChip<F>,
        safe_type_chip: &SafeTypeChip<'_, F>,
    ) -> Result<Vec<QuantumCell<F>>, Error> {
        let list_size = ctx.load_constant(F::from(list.len() as u64));
        let rounds = ctx.load_constant(F::from(90u64));
        let one = ctx.load_constant(F::one());
        let two = ctx.load_constant(F::from(2u64));

        for r in (89u8..=0) {
            let round_as_bytes = ctx.load_constant(F::from(r as u64)); // Should be u8, so 1 byte
            let hash = self.hash_chip.digest::<160>(seed.to_vec().into_iter().chain(iter::once(round_as_bytes)).into(),ctx, region)?.output_bytes;
            let pivot = bytes_le_to_uint(ctx, range_chip.gate(), &hash[0..8], 8);

            let mut hash_bytes = [ctx.load_zero(); 32];
            
            let mut mirror1 = range_chip.gate().add(ctx, pivot, two);
            mirror1 = range_chip.div_mod(ctx, mirror1, BigUint::from(2u8), 64).0;

            let mut mirror2 = range_chip.gate().add(ctx, pivot, list_size);
            mirror2 = range_chip.div_mod(ctx, mirror2, BigUint::from(2u8), 64).0;

            let mirror1_b = mirror1.value().to_bytes_le();
            let mirror1_v: u32 = u32::from_le_bytes(mirror1_b.try_into().unwrap());

            let mirror2_b = mirror2.value().to_bytes_le();
            let mirror2_v: u32 = u32::from_le_bytes(mirror2_b.try_into().unwrap());

            for i in (mirror1_v..=mirror2_v) {
                let i_a = ctx.load_constant(F::from(i as u64));
                let is_before_pivot = range_chip.is_less_than(ctx, i_a, pivot, 64);

                let flip_before_pivot = range_chip.gate().sub(ctx, pivot, i_a);
                let mut flip_after_pivot = range_chip.gate().add(ctx, pivot, list_size);
                flip_after_pivot = range_chip.gate().sub(ctx, flip_after_pivot, i_a);

                let flip = range_chip.gate().select(ctx, flip_before_pivot, flip_after_pivot, is_before_pivot);
                
            }
        }

        // TODO: Do checks on list size
        // let mut buf = Buf::new(ctx, seed.to_vec().try_into().unwrap());

        // for r in (89..=0) {
        //     let r_assigned = ctx.load_constant(F::from(r as u64));
        //     buf.set_round(ctx, r);

        //     let raw_pivot_bytes_le = buf.raw_pivot(ctx, region, self.hash_chip)?;
        //     let raw_pivot = bytes_le_to_uint(ctx, range_chip.gate(), &raw_pivot_bytes_le, 8);
        //     let (_, pivot) = range_chip.div_mod(ctx, raw_pivot, BigUint::from(list.len()), 64);
            
        //     let unshifted = range_chip.gate().add(ctx, pivot, one);
        //     let mirror = range_chip.div_mod(ctx, unshifted, BigUint::from(8u64), 64).0;

        //     buf.mix_in_position(ctx, &mirror.value().to_repr().map(|b| F::from(b as u64)));

        //     let mut source = buf.hash(ctx, region, self.hash_chip)?;
        //     let (_, mut byte_v_idx) = range_chip.div_mod(ctx, pivot, BigUint::from(256u64), 64);
        //     byte_v_idx = range_chip.div_mod(ctx, byte_v_idx, BigUint::from(8u64), 64).0;

        //    let mirror_bytes = mirror.value().to_bytes_le();
        //    let m = u64::from_le_bytes(mirror_bytes[0..8].try_into().unwrap());

        //     for i in 0..m {
        //         let i_field = F::from(i);
        //         let j = ctx.load_witness(*pivot.value() - i_field);

        //         let mut j_mod_256 = range_chip.div_mod(ctx, j, BigUint::from(256u64), 64).1;
        //         let j_mod_256_is_zero = range_chip.gate().is_zero(ctx, j_mod_256);

                
                
        //     }

        // }

        todo!()
    }
}

pub fn bytes_le_to_uint<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    input: &[AssignedValue<F>],
    num_bytes: usize,
) -> AssignedValue<F> {
    gate.inner_product(
        ctx,
        input[..num_bytes].iter().rev().copied(),
        (0..num_bytes).map(|idx| Constant(gate.pow_of_two()[8 * idx])),
    )
}


// public void shuffleList(int[] input, Bytes32 seed) {

//     int listSize = input.length;
//     if (listSize == 0) {
//       return;
//     }

//     final Sha256 sha256 = getSha256Instance();

//     for (int round = specConfig.getShuffleRoundCount() - 1; round >= 0; round--) {

//       final Bytes roundAsByte = Bytes.of((byte) round);

//       // This needs to be unsigned modulo.
//       final Bytes hash = sha256.wrappedDigest(seed, roundAsByte);
//       int pivot = bytesToUInt64(hash.slice(0, 8)).mod(listSize).intValue();

//       byte[] hashBytes = EMPTY_HASH;
//       int mirror1 = (pivot + 2) / 2;
//       int mirror2 = (pivot + listSize) / 2;
//       for (int i = mirror1; i <= mirror2; i++) {
//         int flip, bitIndex;
//         if (i <= pivot) {
//           flip = pivot - i;
//           bitIndex = i & 0xff;
//           if (bitIndex == 0 || i == mirror1) {
//             hashBytes = sha256.digest(seed, roundAsByte, uintTo4Bytes(i / 256));
//           }
//         } else {
//           flip = pivot + listSize - i;
//           bitIndex = flip & 0xff;
//           if (bitIndex == 0xff || i == pivot + 1) {
//             hashBytes = sha256.digest(seed, roundAsByte, uintTo4Bytes(flip / 256));
//           }
//         }

//         int theByte = hashBytes[bitIndex / 8];
//         int theBit = (theByte >> (bitIndex & 0x07)) & 1;
//         if (theBit != 0) {
//           int tmp = input[i];
//           input[i] = input[flip];
//           input[flip] = tmp;
//         }
//       }
//     }
//   }