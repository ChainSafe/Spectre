use std::{
    env::{set_var, var},
    iter,
};

use eth_types::Testnet;
use halo2_base::{
    gates::builder::{CircuitBuilderStage, MultiPhaseThreadBreakPoints},
    utils::fs::gen_srs,
};
use halo2_proofs::poly::{commitment::Params, kzg::commitment::ParamsKZG};
use halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, Snark, SHPLONK};

use crate::{
    committee_update_circuit::CommitteeUpdateCircuit,
    util::{AppCircuit, Eth2ConfigPinning, PinnableCircuit},
};

pub type AggregationConfigPinning = Eth2ConfigPinning;

impl PinnableCircuit<Fr> for AggregationCircuit {
    type Pinning = AggregationConfigPinning;

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        AggregationCircuit::break_points(self)
    }
}

impl AppCircuit for AggregationCircuit {
    type Pinning = AggregationConfigPinning;

    type Witness = Vec<Snark>;

    fn create_circuit(
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<halo2curves::bn256::Bn256>,
        snark: &Self::Witness,
    ) -> Result<impl crate::util::PinnableCircuit<Fr>, halo2_proofs::plonk::Error> {
        let lookup_bits = params.k() as usize - 1;
        let circuit = AggregationCircuit::new::<SHPLONK>(
            stage,
            pinning.map(|p| p.break_points),
            lookup_bits,
            params,
            snark.clone(),
        );

        match stage {
            CircuitBuilderStage::Prover => {}
            _ => {
                circuit.config(params.k(), Some(10));
                set_var("LOOKUP_BITS", lookup_bits.to_string());
            }
        };

        Ok(circuit)
    }
}
