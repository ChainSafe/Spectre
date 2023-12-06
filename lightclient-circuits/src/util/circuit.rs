use std::env::{set_var, var};
use std::fs;
use std::{fs::File, path::Path};

use eth_types::Field;
use halo2_base::gates::circuit::{BaseCircuitParams, CircuitBuilderStage};
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::ProvingKey,
    plonk::{Circuit, Error, VerifyingKey},
    poly::commitment::Params,
    poly::kzg::commitment::ParamsKZG,
};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::evm::{
    encode_calldata, evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk,
};
use snark_verifier_sdk::halo2::gen_proof_shplonk;
use snark_verifier_sdk::{gen_pk, halo2::gen_snark_shplonk, read_pk};
use snark_verifier_sdk::{CircuitExt, Snark};

pub trait Halo2ConfigPinning: Serialize {
    type BreakPoints;
    /// Loads configuration parameters from a file and sets environmental variables.
    fn from_path<P: AsRef<Path>>(path: P) -> Self;
    /// Loads configuration parameters into environment variables.
    fn set_var(&self);
    /// Returns break points
    fn break_points(self) -> Self::BreakPoints;
    /// Constructs `Self` from environmental variables and break points
    fn from_var(break_points: Self::BreakPoints) -> Self;
    /// Degree of the circuit, log_2(number of rows)
    fn degree(&self) -> u32;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Eth2ConfigPinning {
    pub params: BaseCircuitParams,
    pub break_points: MultiPhaseThreadBreakPoints,
}

impl Halo2ConfigPinning for Eth2ConfigPinning {
    type BreakPoints = MultiPhaseThreadBreakPoints;

    fn from_path<P: AsRef<Path>>(path: P) -> Self {
        let pinning: Self = serde_json::from_reader(
            File::open(&path)
                .unwrap_or_else(|e| panic!("{:?} does not exist: {e:?}", path.as_ref())),
        )
        .unwrap();
        pinning.set_var();
        pinning
    }

    fn set_var(&self) {
        set_var(
            "GATE_CONFIG_PARAMS",
            serde_json::to_string(&self.params).unwrap(),
        );
        set_var("LOOKUP_BITS", (self.params.k - 1).to_string());
    }

    fn break_points(self) -> MultiPhaseThreadBreakPoints {
        self.break_points
    }

    fn from_var(break_points: MultiPhaseThreadBreakPoints) -> Self {
        let params: BaseCircuitParams =
            serde_json::from_str(&var("GATE_CONFIG_PARAMS").unwrap()).unwrap();
        Self {
            params,
            break_points,
        }
    }

    fn degree(&self) -> u32 {
        self.params.k as u32
    }
}

pub trait PinnableCircuit<F: Field>: CircuitExt<F> {
    type Pinning: Halo2ConfigPinning;

    fn break_points(&self) -> <Self::Pinning as Halo2ConfigPinning>::BreakPoints;

    fn write_pinning(&self, path: impl AsRef<Path>) {
        let break_points = self.break_points();
        let pinning: Self::Pinning = Halo2ConfigPinning::from_var(break_points);
        serde_json::to_writer_pretty(File::create(path).unwrap(), &pinning).unwrap();
    }
}

pub trait AppCircuit {
    type Pinning: Halo2ConfigPinning;
    type Witness: Clone;

    /// Creates a [`PinnableCircuit`], auto-configuring the circuit if not in production or prover mode.
    ///
    /// `params` should be the universal trusted setup for the present aggregation circuit.
    /// We assume the trusted setup for the previous SNARKs is compatible with `params` in the sense that
    /// the generator point and toxic waste `tau` are the same.
    fn create_circuit(
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        witness_args: &Self::Witness,
        k: u32,
    ) -> Result<impl crate::util::PinnableCircuit<Fr>, Error>;

    /// Reads the proving key for the pre-circuit.
    /// If `read_only` is true, then it is assumed that the proving key exists and can be read from `path` (otherwise the program will panic).
    fn read_pk(
        params: &ParamsKZG<Bn256>,
        path: impl AsRef<Path>,
        witness_args: &Self::Witness,
    ) -> ProvingKey<G1Affine> {
        let circuit =
            Self::create_circuit(CircuitBuilderStage::Keygen, None, witness_args, params.k())
                .unwrap();
        custom_read_pk(path, &circuit)
    }

    /// Creates the proving key for the pre-circuit if file at `pk_path` is not found.
    /// If a new proving key is created, the new pinning data is written to `pinning_path`.
    fn create_pk(
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
        witness_args: &Self::Witness,
    ) -> ProvingKey<G1Affine> {
        let circuit =
            Self::create_circuit(CircuitBuilderStage::Keygen, None, witness_args, params.k())
                .unwrap();

        let pk_exists = pk_path.as_ref().exists();
        let pk = gen_pk(params, &circuit, Some(pk_path.as_ref()));
        if !pk_exists {
            // should only write pinning data if we created a new pkey
            circuit.write_pinning(pinning_path);
        }
        pk
    }

    fn get_degree(pinning_path: impl AsRef<Path>) -> u32 {
        let pinning = Self::Pinning::from_path(pinning_path);
        pinning.degree()
    }

    fn read_or_create_pk(
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
        read_only: bool,
        witness_args: &Self::Witness,
    ) -> ProvingKey<G1Affine> {
        if read_only {
            Self::read_pk(params, pk_path, witness_args)
        } else {
            Self::create_pk(params, pk_path, pinning_path, witness_args)
        }
    }

    fn gen_proof_shplonk(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        witness_args: &Self::Witness,
    ) -> Result<Vec<u8>, Error> {
        let pinning = Self::Pinning::from_path(pinning_path);
        let circuit = Self::create_circuit(
            CircuitBuilderStage::Prover,
            Some(pinning),
            witness_args,
            params.k(),
        )?;
        let instances = circuit.instances();
        let proof = gen_proof_shplonk(params, pk, circuit, instances, None);

        Ok(proof)
    }

    fn gen_snark_shplonk(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: Option<impl AsRef<Path>>,
        witness_args: &Self::Witness,
    ) -> Result<Snark, Error> {
        let pinning = Self::Pinning::from_path(pinning_path);
        let circuit = Self::create_circuit(
            CircuitBuilderStage::Prover,
            Some(pinning),
            witness_args,
            params.k(),
        )?;
        let snark = gen_snark_shplonk(params, pk, circuit, path);

        Ok(snark)
    }

    fn gen_evm_verifier_shplonk(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        yul_path: Option<impl AsRef<Path>>,
        witness_args: &Self::Witness,
    ) -> Result<Vec<u8>, Error> {
        let circuit =
            Self::create_circuit(CircuitBuilderStage::Keygen, None, witness_args, params.k())?;
        let deployment_code =
            custom_gen_evm_verifier_shplonk(params, pk.get_vk(), &circuit, yul_path);

        Ok(deployment_code)
    }

    fn gen_evm_proof_shplonk(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        deployment_code: Option<Vec<u8>>,
        witness_args: &Self::Witness,
    ) -> Result<(Vec<u8>, Vec<Vec<Fr>>), Error> {
        let pinning = Self::Pinning::from_path(pinning_path);
        let circuit = Self::create_circuit(
            CircuitBuilderStage::Prover,
            Some(pinning),
            witness_args,
            params.k(),
        )?;
        let instances = circuit.instances();
        let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone());

        if let Some(deployment_code) = deployment_code {
            evm_verify(deployment_code, instances.clone(), proof.clone());
        }

        Ok((proof, instances))
    }

    fn gen_calldata(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        deployment_code: Option<Vec<u8>>,
        witness_args: &Self::Witness,
    ) -> Result<String, Error> {
        let pinning = Self::Pinning::from_path(pinning_path);
        let circuit = Self::create_circuit(
            CircuitBuilderStage::Prover,
            Some(pinning),
            witness_args,
            params.k(),
        )?;
        let calldata = write_calldata_generic(params, pk, circuit, path, deployment_code);

        Ok(calldata)
    }
}

pub fn custom_gen_evm_verifier_shplonk<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    circuit: &C,
    path: Option<impl AsRef<Path>>,
) -> Vec<u8> {
    gen_evm_verifier_shplonk::<C>(
        params,
        vk,
        circuit.num_instance(),
        path.as_ref().map(|p| p.as_ref()),
    )
}

pub fn write_calldata_generic<ConcreteCircuit: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: ConcreteCircuit,
    path: impl AsRef<Path>,
    deployment_code: Option<Vec<u8>>,
) -> String {
    let instances = circuit.instances();
    let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone());
    // calldata as hex string
    let calldata = hex::encode(encode_calldata(&instances, &proof));
    fs::write(path, &calldata).expect("write calldata should not fail");
    if let Some(deployment_code) = deployment_code {
        evm_verify(deployment_code, instances, proof);
    }
    calldata
}

fn custom_read_pk<C, P>(fname: P, c: &C) -> ProvingKey<G1Affine>
where
    C: Circuit<Fr>,
    P: AsRef<Path>,
{
    read_pk::<C>(fname.as_ref(), c.params())
        .unwrap_or_else(|_| panic!("proving key: {:?} should exist", fname.as_ref().to_str()))
}
