use std::fs;
use std::{fs::File, path::Path};

use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat::RawBytesUnchecked,
};

pub use halo2_base::utils::fs::{gen_srs, read_or_create_srs, read_params};

/// Generate setup artifacts for a circuit of size `k`, where 2^k represents the number of rows in the circuit.
///
/// If the trusted setup parameters are not found, the function performs an unsafe trusted setup to generate the necessary parameters
/// If the provided `k` value is larger than the `k` value of the loaded parameters, an error is returned, as the provided `k` is too large.
/// Otherwise, if the `k` value is smaller than the `k` value of the loaded parameters, the parameters are downsized to fit the requested `k`.
#[allow(clippy::type_complexity)]
pub fn read_vkey<C: Circuit<Fr>>(
    path: &Path,
    params: C::Params,
) -> Result<VerifyingKey<G1Affine>, &'static str> {
    let timer = start_timer!(|| "Loading vkey");

    let mut file = File::open(path).map_err(|_| "failed to read file")?;

    let vk = VerifyingKey::<G1Affine>::read::<_, C>(&mut file, RawBytesUnchecked, params)
        .map_err(|_| "failed to decode vkey");

    end_timer!(timer);

    vk
}

/// Generate setup artifacts for a circuit of size `k`, where 2^k represents the number of rows in the circuit.
///
/// If the trusted setup parameters are not found, the function performs an unsafe trusted setup to generate the necessary parameters
/// If the provided `k` value is larger than the `k` value of the loaded parameters, an error is returned, as the provided `k` is too large.
/// Otherwise, if the `k` value is smaller than the `k` value of the loaded parameters, the parameters are downsized to fit the requested `k`.
#[allow(clippy::type_complexity)]
pub fn gen_pkey<C: Circuit<Fr>>(
    name: impl Fn() -> &'static str,
    params: &ParamsKZG<Bn256>,
    dir_path: Option<&Path>,
    circuit: &C,
) -> Result<ProvingKey<G1Affine>, &'static str> {
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
                    RawBytesUnchecked,
                    circuit.params(),
                )
                .expect("failed to read vkey"),
            ),
            Err(_) => {
                let timer = start_timer!(|| "Creating and writting vkey");
                let vk = keygen_vk(params, circuit).expect("vk generation should not fail");
                let mut file = File::create(vkey_path).expect("couldn't create vkey file");
                vk.write(&mut file, RawBytesUnchecked)
                    .expect("Failed to write vkey");
                (timer, vk)
            }
        }
    } else {
        (
            start_timer!(|| "Generating vkey"),
            keygen_vk(params, circuit).expect("vk generation should not fail"),
        )
    };
    end_timer!(timer);

    let timer = start_timer!(|| "Generating pkey");
    let pkey = keygen_pk(params, vkey, circuit).expect("pk generation should not fail");
    end_timer!(timer);

    Ok(pkey)
}
