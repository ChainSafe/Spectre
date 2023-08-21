use std::fs;
use std::{fs::File, path::Path};

use ark_std::{end_timer, start_timer};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::poly::VerificationStrategy;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng;
use snark_verifier_sdk::CircuitExt;

/// Generate setup artifacts for a circuit of size `k`, where 2^k represents the number of rows in the circuit.
///
/// If the trusted setup parameters are not found, the function performs an unsafe trusted setup to generate the necessary parameters
/// If the provided `k` value is larger than the `k` value of the loaded parameters, an error is returned, as the provided `k` is too large.
/// Otherwise, if the `k` value is smaller than the `k` value of the loaded parameters, the parameters are downsized to fit the requested `k`.
#[allow(clippy::type_complexity)]
pub fn gen_pkey<C: Circuit<Fr>>(
    name: impl Fn() -> &'static str,
    params: &ParamsKZG<Bn256>,
    dir_path: Option<&str>,
    circuit: C,
) -> Result<ProvingKey<G1Affine>, &'static str> {
    let dir_path = dir_path.map(Path::new);

    if let Some(path) = &dir_path {
        fs::create_dir_all(path).expect("Failed to create directory");
    }

    let (timer, vkey) = if let Some(dir) = dir_path {
        let vkey_path = dir.join(format!("{}.vkey", name()));
        match File::open(&vkey_path) {
            Ok(mut file) => (
                start_timer!(|| "Loading vkey"),
                VerifyingKey::<G1Affine>::read::<_, C>(
                    &mut file,
                    halo2_proofs::SerdeFormat::RawBytesUnchecked,
                )
                .expect("failed to read vkey"),
            ),
            Err(_) => {
                let timer = start_timer!(|| "Creating and writting vkey");
                let vk = keygen_vk(params, &circuit).expect("vk generation should not fail");
                let mut file = File::create(vkey_path).expect("couldn't create vkey file");
                vk.write(&mut file, halo2_proofs::SerdeFormat::RawBytesUnchecked)
                    .expect("Failed to write vkey");
                (timer, vk)
            }
        }
    } else {
        (
            start_timer!(|| "Loading vkey"),
            keygen_vk(params, &circuit).expect("vk generation should not fail"),
        )
    };
    end_timer!(timer);

    let timer = start_timer!(|| "Generating pkey");
    let pkey = keygen_pk(params, vkey, &circuit).expect("pk generation should not fail");
    end_timer!(timer);

    Ok(pkey)
}

/// Generates a proof given the public setup, the proving key, the initiated circuit and its public inputs.
pub fn full_prover<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    public_inputs: Vec<Vec<Fr>>,
) -> Vec<u8> {
    let pf_time = start_timer!(|| "Creating proof");

    let instance: Vec<&[Fr]> = public_inputs.iter().map(|input| &input[..]).collect();
    let instances = &[&instance[..]];

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(params, pk, &[circuit], instances, OsRng, &mut transcript)
    .expect("prover should not fail");
    let proof = transcript.finalize();
    end_timer!(pf_time);
    proof
}

pub fn full_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: Vec<u8>,
    public_inputs: Vec<Vec<Fr>>,
) -> bool {
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let instance: Vec<&[Fr]> = public_inputs.iter().map(|input| &input[..]).collect();
    let instances = &[&instance[..]];

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, vk, strategy, instances, &mut transcript)
    .is_ok()
}
