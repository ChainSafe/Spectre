// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

use eth_types::Spec;
use getset::Getters;
use lightclient_circuits::committee_update_circuit::CommitteeUpdateCircuit;
use lightclient_circuits::halo2_base::utils::fs::gen_srs;
use lightclient_circuits::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use lightclient_circuits::sync_step_circuit::StepCircuit;
use lightclient_circuits::util::AppCircuit;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Getters)]
pub struct CircuitContext {
    #[getset(get = "pub")]
    pub config_path: PathBuf,
    #[getset(get = "pub")]
    pub degree: u32,
    #[getset(get = "pub")]
    pub pk: ProvingKey<G1Affine>,
}

#[derive(Clone, Debug)]
pub struct ProverState {
    // degree -> params (use BTreeMap to find proper degree for params downsize)
    pub params: BTreeMap<u32, ParamsKZG<Bn256>>,
    pub step: CircuitContext,
    pub step_verifier: CircuitContext,
    pub committee_update: CircuitContext,
    pub committee_update_verifier: CircuitContext,
}

impl ProverState {
    pub fn new<S: Spec>(config_dir: &Path, build_dir: &Path) -> Self {
        let mut params_map = BTreeMap::new();

        fn load_ctx<Circuit: AppCircuit>(
            config_path: PathBuf,
            pk_path: PathBuf,
            params_map: &mut BTreeMap<u32, ParamsKZG<Bn256>>,
            default_witness: Circuit::Witness,
        ) -> CircuitContext {
            let degree = Circuit::get_degree(&config_path);
            let params = gen_srs(degree);

            let pk = Circuit::read_pk(&params, pk_path, &config_path, &default_witness);

            params_map.insert(degree, params);

            CircuitContext {
                config_path,
                degree,
                pk,
            }
        }

        let step = load_ctx::<StepCircuit<S, Fr>>(
            config_dir.join(format!("sync_step_{}.json", S::NAME)),
            build_dir.join(format!("sync_step_{}.pkey", S::NAME)),
            &mut params_map,
            Default::default(),
        );

        let step_snark = StepCircuit::<S, Fr>::gen_snark_shplonk(
            params_map.get(step.degree()).unwrap(),
            step.pk(),
            step.config_path(),
            None::<String>,
            &Default::default(),
        )
        .unwrap();

        let committee_update = load_ctx::<CommitteeUpdateCircuit<S, Fr>>(
            config_dir.join(format!("committee_update_{}.json", S::NAME)),
            build_dir.join(format!("committee_update_{}.pkey", S::NAME)),
            &mut params_map,
            Default::default(),
        );

        let committee_update_snark = CommitteeUpdateCircuit::<S, Fr>::gen_snark_shplonk(
            params_map.get(committee_update.degree()).unwrap(),
            committee_update.pk(),
            committee_update.config_path(),
            None::<String>,
            &Default::default(),
        )
        .unwrap();

        Self {
            step,
            step_verifier: load_ctx::<AggregationCircuit>(
                config_dir.join(format!("sync_step_verifier_{}.json", S::NAME)),
                build_dir.join(format!("sync_step_verifier_{}.pkey", S::NAME)),
                &mut params_map,
                vec![step_snark],
            ),
            committee_update,
            committee_update_verifier: load_ctx::<AggregationCircuit>(
                config_dir.join(format!("committee_update_verifier_{}.json", S::NAME)),
                build_dir.join(format!("committee_update_verifier_{}.pkey", S::NAME)),
                &mut params_map,
                vec![committee_update_snark],
            ),
            params: params_map,
        }
    }
}
