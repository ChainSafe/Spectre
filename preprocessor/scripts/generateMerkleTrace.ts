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
let bn256PubKeys = [
    Uint8Array.from([232, 77, 96, 187, 77, 159, 216, 25, 206, 231, 79, 184, 193, 183, 146, 242, 27, 17, 144, 51, 32, 46, 232, 77, 32, 254, 101, 116, 147, 169, 236, 39]),
    Uint8Array.from([121, 97, 145, 101, 75, 82, 252, 98, 68, 138, 239, 122, 20, 62, 100, 221, 19, 103, 188, 141, 6, 0, 12, 122, 184, 80, 1, 237, 221, 48, 192, 43]),
    Uint8Array.from([121, 120, 209, 158, 108, 187, 60, 235, 177, 236, 91, 119, 41, 91, 169, 248, 81, 14, 103, 225, 193, 253, 84, 100, 35, 74, 153, 84, 192, 99, 209, 164]),
    Uint8Array.from([52, 219, 202, 145, 120, 83, 129, 10, 43, 214, 40, 152, 52, 137, 13, 111, 29, 53, 100, 179, 118, 189, 3, 68, 151, 17, 118, 216, 241, 40, 62, 164]),
    Uint8Array.from([3, 108, 186, 33, 251, 235, 204, 9, 215, 241, 212, 103, 5, 127, 9, 119, 207, 230, 42, 192, 21, 66, 41, 224, 255, 53, 248, 103, 1, 247, 171, 138]),
]

for (let i = 0; i < N; i++) {
    // let privKey = bls12_381.utils.randomPrivateKey();
    // let pubkey = bls12_381.getPublicKey(privKey);
    let pubkey = bn256PubKeys[i];
    const paddedPubkey = new Uint8Array(48);
    paddedPubkey.set(pubkey, 0);

    validators.push({
        pubkey: paddedPubkey,
        withdrawalCredentials: Uint8Array.from(crypto.randomBytes(32)),
        effectiveBalance: 32000000,
        slashed: false,
        activationEligibilityEpoch: i,
        activationEpoch: i + 1,
        exitEpoch: 100,
        withdrawableEpoch: 0
    });
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

printTrace(partial_tree, trace);

const target_epoch = 25;

fs.writeFileSync(
    `../test_data/validators.json`,
    serialize(Array.from(validators.entries()).map(([i, validator]) => ({
        id: i,
        committee: 0,
        isActive: !validator.slashed && validator.activationEpoch <= target_epoch && target_epoch < validator.exitEpoch,
        isAttested: true,
        pubkey: Array.from(validator.pubkey),
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
