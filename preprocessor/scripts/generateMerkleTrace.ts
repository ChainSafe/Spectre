import fs from "fs";
import path from "path";
import { bn254 } from '@noble/curves/bn254';
import { bls12_381 } from '@noble/curves/bls12-381';
import {
    ContainerType,
    ListCompositeType,
    ValueOf
} from "@chainsafe/ssz";
import {
    ssz,
} from "@lodestar/types"
import {
    BeaconState
} from "@lodestar/types/phase0"
import { createProof, ProofType, MultiProof, Node } from "@chainsafe/persistent-merkle-tree";
import crypto from "crypto";
import { serialize } from "./util";
import { createNodeFromMultiProofWithTrace, printTrace } from "./merkleTrace";


const ValidatorContainer = new ContainerType(
    {
        pubkey: ssz.Bytes48,
        withdrawalCredentials: ssz.Bytes32,
        effectiveBalance: ssz.UintNum64,
        slashed: ssz.Boolean,
        activationEligibilityEpoch: ssz.EpochInf,
        activationEpoch: ssz.EpochInf,
        exitEpoch: ssz.EpochInf,
        withdrawableEpoch: ssz.EpochInf,
    },
    { typeName: "Validator", jsonCase: "eth2" }
);

type Validator = ValueOf<typeof ValidatorContainer>;

export const ValidatorsSsz = new ListCompositeType(ValidatorContainer, 10);

const N = 5;
let validators: Validator[] = [];
let gindices: bigint[] = [];
let validatorBaseGindices: bigint[] = [];

console.log("validators[0].gindex:", ValidatorsSsz.getPathInfo([0]).gindex);

let nonRlcGindices = [];
// this is pregenerated BN254 pubkeys
// for some reasone noble-curve generates pubkeys that are incompatible with Halo2curve Rust package and they are 33 bytes (not usual 32)
// if you need to icreaser number of validators icrease number of pubkeys in `bn256PubKeys` array by duplicating them
// or uncomment bls12_381 related lines below 
let pubKeysHexes = [
    "80d492fbdbe9d5fcd08fe962b3ce2b9c245c068f686c4838f57db5b4e8b1bfc729c98e93dd4e5cc78b661845d7459809",
    "80822499f96a1a8c0048f01f389dfcaaa5d8269c332dbb507fe46f270bcfd5f67c53f827fd867221592dbde77b6b37ab",
    "804c021152c3304853941847e80480fdaceba3b9676fbe018268cf77d1a1856966c2f9686bb4d4aa0c4118a7e85f83cc",
    "80b61f545f9756a2b4431f1a2690adc7b351dd82edc1eb1bb0f3ec2e730b1484da690ba636701059e51e59f34e124983",
    "811e6a5478f708495addbb1445a2ef23e39ee90287f3a23ecd3d57d4b844e4f85b828bae8fa0f1893dfcc456f86f7889"
];

function toHexString(byteArray: Uint8Array): string {
    return Array.from(byteArray).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export function bytesToHex(bytes: Uint8Array): string {
    const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
    // pre-caching improves the speed 6x
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
}

function hexToBytes(hex: string): Uint8Array {
    let bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

let pubKeysUncompressed: Uint8Array[] = [];

for (let i = 0; i < N; i++) {
    let pubkey = hexToBytes(pubKeysHexes[i]);
    let p = bls12_381.G1.ProjectivePoint.fromHex(toHexString(pubkey));
    let pubkeyUncompressed = p.toRawBytes(false);
    console.log("y:", p.toAffine());


    // covnert to little endian
    pubkey.reverse();
    pubkeyUncompressed.reverse();
    let pubKeysUncompressedLE = new Uint8Array(96);
    pubKeysUncompressedLE.set(pubkeyUncompressed.slice(0, 48), 48);
    pubKeysUncompressedLE.set(pubkeyUncompressed.slice(48, 96), 0);

    validators.push({
        pubkey: pubkey,
        withdrawalCredentials: Uint8Array.from(crypto.randomBytes(32)),
        effectiveBalance: 32000000,
        slashed: false,
        activationEligibilityEpoch: i,
        activationEpoch: i + 1,
        exitEpoch: 100,
        withdrawableEpoch: 0
    });
    pubKeysUncompressed.push(pubKeysUncompressedLE);
    validatorBaseGindices.push(ValidatorsSsz.getPathInfo([i]).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n + 1n);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'effectiveBalance']).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'slashed']).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'activationEpoch']).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'exitEpoch']).gindex);

    nonRlcGindices.push(ValidatorsSsz.getPathInfo([i, 'effectiveBalance']).gindex);
    nonRlcGindices.push(ValidatorsSsz.getPathInfo([i, 'slashed']).gindex);
    nonRlcGindices.push(ValidatorsSsz.getPathInfo([i, 'activationEpoch']).gindex);
    nonRlcGindices.push(ValidatorsSsz.getPathInfo([i, 'exitEpoch']).gindex);
}

let view = ValidatorsSsz.toView(validators);

let proof = createProof(view.node, { type: ProofType.multi, gindices: gindices }) as MultiProof;

const areEqual = (first: Uint8Array, second: Uint8Array) =>
    first.length === second.length && first.every((value, index) => value === second[index]);

let [partial_tree, trace] = createNodeFromMultiProofWithTrace(proof.leaves, proof.witnesses, proof.gindices, nonRlcGindices);

// printTrace(partial_tree, trace);

const target_epoch = 25;

fs.writeFileSync(
    `../test_data/validators.json`,
    serialize(Array.from(validators.entries()).map(([i, validator]) => ({
        id: i,
        committee: 0,
        isActive: !validator.slashed && validator.activationEpoch <= target_epoch && target_epoch < validator.exitEpoch,
        isAttested: true,
        pubkey: Array.from(validator.pubkey),
        pubkeyUncompressed: Array.from(pubKeysUncompressed[i]),
        effectiveBalance: validator.effectiveBalance,
        slashed: validator.slashed,
        activationEpoch: validator.activationEpoch,
        exitEpoch: validator.exitEpoch,
        gindex: validatorBaseGindices[i]
    })))
);

fs.writeFileSync(
    `../test_data/committees.json`,
    serialize([
        {
            id: 0,
            accumulatedBalance: Array.from(validators).reduce((acc, validator) => acc + validator.effectiveBalance, 0),
            aggregatedPubkey: Array.from(crypto.randomBytes(48)), // TODO: aggregate pubkeys
        }
    ])
);

fs.writeFileSync(
    `../test_data/merkle_trace.json`,
    serialize(trace)
);
