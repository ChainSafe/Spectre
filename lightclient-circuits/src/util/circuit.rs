use std::env::{args, set_var, var};
use std::fs;
use std::{fs::File, path::Path};

use halo2_base::gates::builder::{
    CircuitBuilderStage, FlexGateConfigParams, MultiPhaseThreadBreakPoints,
};
use halo2_proofs::plonk::{Circuit, Error, VerifyingKey};
use halo2_proofs::{plonk::ProvingKey, poly::kzg::commitment::ParamsKZG};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::evm::{gen_evm_proof, gen_evm_proof_shplonk, gen_evm_verifier_shplonk, encode_calldata, evm_verify};
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
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
    pub params: FlexGateConfigParams,
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
            "FLEX_GATE_CONFIG_PARAMS",
            serde_json::to_string(&self.params).unwrap(),
        );
        set_var("LOOKUP_BITS", (self.params.k - 1).to_string());
    }

    fn break_points(self) -> MultiPhaseThreadBreakPoints {
        self.break_points
    }

    fn from_var(break_points: MultiPhaseThreadBreakPoints) -> Self {
        let params: FlexGateConfigParams =
            serde_json::from_str(&var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
        Self {
            params,
            break_points,
        }
    }

    fn degree(&self) -> u32 {
        self.params.k as u32
    }
}

pub trait PinnableCircuit<F: ff::Field>: CircuitExt<F> {
    type Pinning: Halo2ConfigPinning;

    fn break_points(&self) -> <Self::Pinning as Halo2ConfigPinning>::BreakPoints;

    fn write_pinning(&self, path: impl AsRef<Path>) {
        let break_points = self.break_points();
        let pinning: Self::Pinning = Halo2ConfigPinning::from_var(break_points);
        serde_json::to_writer_pretty(File::create(path).unwrap(), &pinning).unwrap();
    }
}

pub trait AppCircuit: Sized {
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
        params: &ParamsKZG<Bn256>,
        args: &Self::Witness,
    ) -> Result<impl crate::util::PinnableCircuit<Fr>, Error>;

    /// Reads the proving key for the pre-circuit.
    /// If `read_only` is true, then it is assumed that the proving key exists and can be read from `path` (otherwise the program will panic).
    fn read_pk(
        params: &ParamsKZG<Bn256>,
        path: impl AsRef<Path>,
        args: &Self::Witness,
    ) -> ProvingKey<G1Affine> {
        let circuit =
            Self::create_circuit(CircuitBuilderStage::Keygen, None, params, args).unwrap();
        custom_read_pk(path, &circuit)
    }

    /// Creates the proving key for the pre-circuit if file at `pk_path` is not found.
    /// If a new proving key is created, the new pinning data is written to `pinning_path`.
    fn create_pk(
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
        witness: &Self::Witness,
    ) -> ProvingKey<G1Affine> {
        let circuit =
            Self::create_circuit(CircuitBuilderStage::Keygen, None, params, witness).unwrap();

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
        witness: &Self::Witness,
    ) -> ProvingKey<G1Affine> {
        if read_only {
            Self::read_pk(params, pk_path, witness)
        } else {
            Self::create_pk(params, pk_path, pinning_path, witness)
        }
    }

    fn gen_snark_shplonk(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: Option<impl AsRef<Path>>,
        witness: &Self::Witness,
    ) -> Result<Snark, Error> {
        let pinning = Self::Pinning::from_path(pinning_path);
        let circuit =
            Self::create_circuit(CircuitBuilderStage::Prover, Some(pinning), params, witness)?;
        let snark = gen_snark_shplonk(params, pk, circuit, path);

        Ok(snark)
    }

    fn gen_evm_verifier_shplonk(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        yul_path: Option<impl AsRef<Path>>,
        witness: &Self::Witness,
    ) -> Result<Vec<u8>, Error> {
        let circuit = Self::create_circuit(CircuitBuilderStage::Keygen, None, params, witness)?;
        let deployment_code =
            custom_gen_evm_verifier_shplonk(params, pk.get_vk(), &circuit, yul_path);

        Ok(deployment_code)
    }

    fn gen_evm_proof_shplonk(params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        deployment_code: Option<Vec<u8>>,
        witness: &Self::Witness) -> Result<(Vec<u8>, Vec<Vec<Fr>>), Error> {
            let pinning = Self::Pinning::from_path(pinning_path);
            let circuit =
                Self::create_circuit(CircuitBuilderStage::Prover, Some(pinning), params, witness)?;
            let instances = circuit.instances();
            let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone());

            Ok((proof, instances))
        }

    fn gen_calldata(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        deployment_code: Option<Vec<u8>>,
        witness: &Self::Witness,
    ) -> Result<String, Error> {
        let pinning = Self::Pinning::from_path(pinning_path);
        let circuit =
            Self::create_circuit(CircuitBuilderStage::Prover, Some(pinning), params, witness)?;
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

fn custom_read_pk<C, P>(fname: P, _: &C) -> ProvingKey<G1Affine>
where
    C: Circuit<Fr>,
    P: AsRef<Path>,
{
    read_pk::<C>(fname.as_ref()).expect("proving key should exist")
}
