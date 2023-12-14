// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use crate::util::{AppCircuit, Halo2ConfigPinning, PinnableCircuit};
use halo2_base::{
    gates::{circuit::CircuitBuilderStage, flex_gate::MultiPhaseThreadBreakPoints},
    halo2_proofs::{halo2curves::bn256::Fr, plonk::Error},
    utils::fs::gen_srs,
};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{
    halo2::aggregation::{AggregationCircuit, AggregationConfigParams},
    Snark, SHPLONK,
};
use std::{
    env::{set_var, var},
    fs::File,
    path::Path,
};

/// Configuration for the aggregation circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregationConfigPinning {
    pub params: AggregationConfigParams,
    pub break_points: MultiPhaseThreadBreakPoints,
}

impl Halo2ConfigPinning for AggregationConfigPinning {
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
            "AGG_CONFIG_PARAMS",
            serde_json::to_string(&self.params).unwrap(),
        );
        set_var("LOOKUP_BITS", (self.params.degree - 1).to_string());
    }

    fn break_points(self) -> MultiPhaseThreadBreakPoints {
        self.break_points
    }

    fn from_var(break_points: MultiPhaseThreadBreakPoints) -> Self {
        let params: AggregationConfigParams =
            serde_json::from_str(&var("AGG_CONFIG_PARAMS").unwrap()).unwrap();
        Self {
            params,
            break_points,
        }
    }

    fn degree(&self) -> u32 {
        self.params.degree
    }
}

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
        snark: &Self::Witness,
        k: u32,
    ) -> Result<impl crate::util::PinnableCircuit<Fr>, Error> {
        let lookup_bits = k as usize - 1;
        let params = gen_srs(k);
        let circuit_params = pinning.clone().map_or(
            AggregationConfigParams {
                degree: k,
                lookup_bits,
                ..Default::default()
            },
            |p| p.params,
        );
        let mut circuit = AggregationCircuit::new::<SHPLONK>(
            stage,
            circuit_params,
            &params,
            snark.clone(),
            Default::default(),
        );

        // We assume that `AggregationCircuit` will only be used for a single aggregation/compression layer.
        circuit.expose_previous_instances(false);

        match stage {
            CircuitBuilderStage::Prover => {
                circuit.set_params(circuit_params);
                circuit.set_break_points(pinning.map_or(vec![], |p| p.break_points));
            }
            _ => {
                set_var(
                    "AGG_CONFIG_PARAMS",
                    serde_json::to_string(&circuit.calculate_params(Some(10))).unwrap(),
                );
            }
        };

        Ok(circuit)
    }
}
