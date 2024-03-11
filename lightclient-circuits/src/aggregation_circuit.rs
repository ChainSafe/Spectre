// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use crate::util::{AppCircuit, Halo2ConfigPinning, PinnableCircuit};
use halo2_base::{
    gates::{circuit::CircuitBuilderStage, flex_gate::MultiPhaseThreadBreakPoints},
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        plonk::{Circuit, Error},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{
    halo2::aggregation::{AggregationCircuit, AggregationConfigParams},
    Snark, SHPLONK,
};
use std::{fs::File, path::Path};

/// Configuration for the aggregation circuit.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AggregationConfigPinning {
    pub params: AggregationConfigParams,
    pub break_points: MultiPhaseThreadBreakPoints,
}

impl AggregationConfigPinning {
    pub fn new(k: u32, lookup_bits: usize) -> Self {
        Self {
            params: AggregationConfigParams {
                degree: k,
                lookup_bits,
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

impl Halo2ConfigPinning for AggregationConfigPinning {
    type CircuitParams = AggregationConfigParams;
    type BreakPoints = MultiPhaseThreadBreakPoints;

    fn new(params: Self::CircuitParams, break_points: Self::BreakPoints) -> Self {
        Self {
            params,
            break_points,
        }
    }

    fn from_path<P: AsRef<Path>>(path: P) -> Self {
        serde_json::from_reader(
            File::open(&path)
                .unwrap_or_else(|e| panic!("{:?} does not exist: {e:?}", path.as_ref())),
        )
        .unwrap()
    }

    fn break_points(self) -> MultiPhaseThreadBreakPoints {
        self.break_points
    }

    fn degree(&self) -> u32 {
        self.params.degree
    }
}

impl PinnableCircuit<Fr> for AggregationCircuit {
    type Pinning = AggregationConfigPinning;

    fn pinning(&self) -> Self::Pinning {
        <AggregationConfigPinning as Halo2ConfigPinning>::new(self.params(), self.break_points())
    }
}

impl AppCircuit for AggregationCircuit {
    type Pinning = AggregationConfigPinning;

    type Witness = Vec<Snark>;

    fn create_circuit(
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        snark: &Self::Witness,
        params: &ParamsKZG<Bn256>,
    ) -> Result<impl crate::util::PinnableCircuit<Fr>, Error> {
        let circuit_params = pinning.clone().map_or(
            AggregationConfigParams {
                degree: params.k(),
                lookup_bits: params.k() as usize - 1,
                ..Default::default()
            },
            |p| p.params,
        );
        let mut circuit = AggregationCircuit::new::<SHPLONK>(
            stage,
            circuit_params,
            params,
            snark.clone(),
            Default::default(),
        );

        // We assume that `AggregationCircuit` will only be used for a single aggregation/compression layer.
        circuit.expose_previous_instances(false);

        if matches!(stage, CircuitBuilderStage::Prover) {
            circuit.set_params(circuit_params);
            circuit.set_break_points(pinning.map_or(vec![], |p| p.break_points));
        };

        Ok(circuit)
    }
}
