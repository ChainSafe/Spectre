import fs from "fs";
import path from "path";

import {
    ContainerType,
    ListCompositeType,
    ValueOf
  } from "@chainsafe/ssz";
import {
    ssz,
} from "@lodestar/types"
import {
    Validator as BeaconValidator,
} from "@lodestar/types/phase0"
import {createProof, ProofType, MultiProof, Node} from "@chainsafe/persistent-merkle-tree";
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
    {typeName: "Validator", jsonCase: "eth2"}
  );

type Validator = ValueOf<typeof ValidatorContainer>;

export const ValidatorsSsz = new ListCompositeType(ValidatorContainer, 10);

const N = 5;
let validators: Validator[] = [];
let gindices: bigint[] = [];
let validatorBaseGindices: bigint[] = [];

console.log("validators[0].gindex:", ValidatorsSsz.getPathInfo([0]).gindex);

for (let i = 0; i < N; i++) {
    validators.push({
        pubkey: Uint8Array.from(crypto.randomBytes(48)),
        withdrawalCredentials: Uint8Array.from(crypto.randomBytes(32)),
        effectiveBalance: 32000000,
        slashed: false,
        activationEligibilityEpoch: i,
        activationEpoch: i + 1,
        exitEpoch: 100,
        withdrawableEpoch: 0
    });
    validatorBaseGindices.push(ValidatorsSsz.getPathInfo([i]).gindex);
    console.log([
        [
            ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n, 
            "pubkey1"
        ],
        [
            ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n + 1n, 
            "pubkey2"
        ],
        [
            ValidatorsSsz.getPathInfo([i, 'effectiveBalance']).gindex, 
            "effectiveBalance"
        ],
        [
            ValidatorsSsz.getPathInfo([i, 'slashed']).gindex, 
            "slashed"
        ],
        [
            ValidatorsSsz.getPathInfo([i, 'activationEpoch']).gindex, 
            "activationEpoch"            
        ],
        [
            ValidatorsSsz.getPathInfo([i, 'exitEpoch']).gindex, 
            "exitEpoch"
        ],
    ]);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n + 1n);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'effectiveBalance']).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'slashed']).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'activationEpoch']).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'exitEpoch']).gindex);
}

let view = ValidatorsSsz.toView(validators);

let proof = createProof(view.node, {type: ProofType.multi, gindices: gindices}) as MultiProof; 

const areEqual = (first: Uint8Array, second: Uint8Array) =>
    first.length === second.length && first.every((value, index) => value === second[index]);

let [partial_tree, trace] = createNodeFromMultiProofWithTrace(proof.leaves, proof.witnesses, proof.gindices);

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
