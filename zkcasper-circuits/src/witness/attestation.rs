use super::Validator;
use eth_types::Spec;
pub use ethereum_consensus::phase0::{AttestationData, IndexedAttestation};
use halo2curves::{
    bls12_381::{G1Affine, G2Affine},
    group::{prime::PrimeCurveAffine, Curve, GroupEncoding},
};
use ssz_rs::Merkleized;

#[allow(type_alias_bounds)]
pub type Attestation<S: Spec> = IndexedAttestation<{ S::MAX_VALIDATORS_PER_COMMITTEE }>;

pub fn attestations_dev<const MAX_VALIDATORS_PER_COMMITTEE: usize>(
    validators: Vec<Validator>,
) -> Vec<IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>> {
    let mut data = AttestationData {
        slot: 32,
        index: 0,
        beacon_block_root: Default::default(),
        source: ethereum_consensus::phase0::Checkpoint {
            epoch: 24,
            root: Default::default(),
        },
        target: ethereum_consensus::phase0::Checkpoint {
            epoch: 25,
            root: Default::default(),
        },
    };
    let _agg_pk = validators
        .into_iter()
        .map(|validator| {
            let pk_compressed = validator.pubkey.to_vec();
            G1Affine::from_bytes(&pk_compressed.as_slice().try_into().unwrap()).unwrap()
        })
        .fold(G1Affine::identity(), |acc, x| (acc + x).to_affine());

    let _signing_root = data.hash_tree_root().unwrap();

    // TODO: calculate signature
    // use ark_ec::hashing::HashToCurve;
    // let h2c = HashToCurve::<ark_bn254::Bn254>::new(b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").unwrap();
    // h2c.hash(signing_root.as_ref()).unwrap();

    // here we mock a random bn254 as compressed bls12-381 signature
    let signature = G2Affine::random(&mut rand::thread_rng());
    let mut signature_bytes = signature.to_bytes().as_ref().to_vec();
    signature_bytes.resize(96, 0);

    let attestation = IndexedAttestation {
        attesting_indices: vec![1; MAX_VALIDATORS_PER_COMMITTEE].try_into().unwrap(),
        data,
        signature: signature_bytes.as_slice().try_into().unwrap(),
    };

    vec![attestation]
}
