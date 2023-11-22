use eth_types::Field;
use halo2_base::{
    gates::GateInstructions, halo2_proofs::plonk::Error, poseidon::hasher::PoseidonSponge,
    AssignedValue, Context,
};
use halo2_ecc::bigint::ProperCrtUint;
use halo2curves::bls12_381::Fq;
use itertools::Itertools;
use pse_poseidon::Poseidon as PoseidonNative;

const POSEIDON_SIZE: usize = 16;
const R_F: usize = 8;
const R_P: usize = 68;

pub fn fq_array_poseidon<'a, F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    fields: impl IntoIterator<Item = &'a ProperCrtUint<F>>,
) -> Result<AssignedValue<F>, Error> {
    let limbs = fields
        .into_iter()
        .flat_map(|f| f.limbs())
        .copied()
        .collect_vec();

    let mut poseidon =
        PoseidonSponge::<F, POSEIDON_SIZE, { POSEIDON_SIZE - 1 }>::new::<R_F, R_P, 0>(ctx);

    let mut current_poseidon_hash = None;

    for (i, chunk) in limbs.chunks(POSEIDON_SIZE - 3).enumerate() {
        poseidon.update(chunk);
        if i != 0 {
            poseidon.update(&[current_poseidon_hash.unwrap()]);
        }
        let _ = current_poseidon_hash.insert(poseidon.squeeze(ctx, gate));
    }

    Ok(current_poseidon_hash.unwrap())
}

pub fn fq_array_poseidon_native<F: Field>(
    elems: impl Iterator<Item = Fq>,
    limb_bits: usize,
) -> Result<F, Error> {
    let limbs = elems
        // Converts Fq elements to Fr limbs.
        .flat_map(|x| {
            x.to_bytes_le()
                .chunks(limb_bits / 8)
                .map(F::from_bytes_le)
                .collect_vec()
        })
        .collect_vec();
    let mut poseidon = PoseidonNative::<F, POSEIDON_SIZE, { POSEIDON_SIZE - 1 }>::new(R_F, R_P);
    let mut current_poseidon_hash = None;

    for (i, chunk) in limbs.chunks(POSEIDON_SIZE - 3).enumerate() {
        poseidon.update(chunk);
        if i != 0 {
            poseidon.update(&[current_poseidon_hash.unwrap()]);
        }
        let _ = current_poseidon_hash.insert(poseidon.squeeze());
    }
    Ok(current_poseidon_hash.unwrap())
}

pub fn poseidon_sponge<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    elems: Vec<AssignedValue<F>>,
) -> Result<AssignedValue<F>, Error> {
    let mut poseidon =
        PoseidonSponge::<F, POSEIDON_SIZE, { POSEIDON_SIZE - 1 }>::new::<R_F, R_P, 0>(ctx);
    let mut current_poseidon_hash = None;

    for (i, chunk) in elems.chunks(POSEIDON_SIZE - 3).enumerate() {
        poseidon.update(chunk);
        if i != 0 {
            poseidon.update(&[current_poseidon_hash.unwrap()]);
        }
        let _ = current_poseidon_hash.insert(poseidon.squeeze(ctx, gate));
    }

    Ok(current_poseidon_hash.unwrap())
}
