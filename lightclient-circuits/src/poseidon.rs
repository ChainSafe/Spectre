use crate::gadget::crypto::G1Point;
use eth_types::{AppCurveExt, Field};
use halo2_base::safe_types::ScalarField;
use halo2_base::{safe_types::GateInstructions, AssignedValue, Context};
use halo2_ecc::bigint::{ProperCrtUint, ProperUint};
use halo2_proofs::plonk::Error;
use halo2curves::bls12_381::G1Affine;
use halo2curves::bls12_381::G1;
use itertools::Itertools;
use poseidon::PoseidonChip;
use poseidon_native::Poseidon as PoseidonNative;

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

    let mut poseidon = PoseidonChip::<F, POSEIDON_SIZE, { POSEIDON_SIZE - 1 }>::new(ctx, R_F, R_P)
        .expect("failed to construct Poseidon circuit");

    let mut current_poseidon_hash = None;

    for (i, chunk) in limbs.chunks(POSEIDON_SIZE - 3).enumerate() {
        poseidon.update(chunk);
        if i != 0 {
            poseidon.update(&[current_poseidon_hash.unwrap()]);
        }

        current_poseidon_hash.insert(poseidon.squeeze(ctx, gate)?);
    }

    Ok(current_poseidon_hash.unwrap())
}

pub fn g1_array_poseidon_native<F: Field>(points: &[G1Affine]) -> Result<F, Error> {
    let limbs = points
        .iter()
        // Converts the point (usually in Fq) to limbs.
        .flat_map(|point| {
            point
                .x
                .to_bytes_le()
                .chunks(14)
                .map(F::from_bytes_le)
                .collect_vec()
        })
        // Converts the Fq point to a circuit field. It is safe because the limbs should be smaller
        // even if the bits in the Field of the point are larger than the bits of the circuit field.
        .map(|fq_limbs| F::from_bytes_le_unsecure(&fq_limbs.to_bytes_le()))
        .collect_vec();

    let mut poseidon = PoseidonNative::<F, POSEIDON_SIZE, { POSEIDON_SIZE - 1 }>::new(R_F, R_P);
    let mut current_poseidon_hash = None;

    for (i, chunk) in limbs.chunks(POSEIDON_SIZE - 3).enumerate() {
        poseidon.update(chunk);
        if i != 0 {
            poseidon.update(&[current_poseidon_hash.unwrap()]);
        }
        current_poseidon_hash.insert(poseidon.squeeze());
    }
    Ok(current_poseidon_hash.unwrap())
}

pub fn poseidon_sponge<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    elems: Vec<AssignedValue<F>>,
) -> Result<AssignedValue<F>, Error> {
    let mut poseidon = PoseidonChip::<F, POSEIDON_SIZE, { POSEIDON_SIZE - 1 }>::new(ctx, R_F, R_P)
        .expect("failed to construct Poseidon circuit");
    let mut current_poseidon_hash = None;

    for (i, chunk) in elems.chunks(POSEIDON_SIZE - 3).enumerate() {
        poseidon.update(chunk);
        if i != 0 {
            poseidon.update(&[current_poseidon_hash.unwrap()]);
        }
        current_poseidon_hash.insert(poseidon.squeeze(ctx, gate)?);
    }

    Ok(current_poseidon_hash.unwrap())
}
