import fs from "fs";
import { bls12_381 } from '@noble/curves/bls12-381'
import {
    BitArray,
    ContainerType,
    ListCompositeType,
    ValueOf,
} from "@chainsafe/ssz";
import {
    ssz,
} from "@lodestar/types"
import { createProof, ProofType, MultiProof, Node } from "@chainsafe/persistent-merkle-tree";
import { chunkArray, g1PointToLeBytes as g1PointToBytesLE, g2PointToLeBytes, serialize } from "./util";
import { createNodeFromMultiProofWithTrace, printTrace } from "./merkleTrace";
import { hexToBytes, bytesToHex, numberToBytesBE } from "@noble/curves/abstract/utils";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { createNodeFromCompactMultiProof } from "@chainsafe/persistent-merkle-tree/lib/proof/compactMulti";
import { ValidatorsSsz, Validator, BeaconStateSsz } from "./types";

const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

console.log("VALIDATOR_0_GINDEX:", BeaconStateSsz.getPathInfo(['validators', 0]).gindex);

const N_validators = parseInt(process.argv[2]) || 5;
const N_committees = parseInt(process.argv[3]) || 1;
let gindices: bigint[] = [];
let validatorBaseGindices: bigint[] = [];

let nonRlcGindices: bigint[] = [];

let privKeyHexes: string[] = JSON.parse(fs.readFileSync("../test_data/private_keys.json").toString());

const targetEpoch = 25;

//----------------- Beacon state -----------------//

let beaconState = ssz.capella.BeaconState.deserialize(new Uint8Array(fs.readFileSync("../test_data/beacon_state_2915750")));
beaconState.validators = [];

//----------------- Validators -----------------//

let pubKeyPoints: ProjPointType<bigint>[] = [];

for (let i = 0; i < N_validators * N_committees; i++) {
    // use 5 pregenerated private keys to avoid changing JSON files.
    let privKey = i < privKeyHexes.length ? hexToBytes(privKeyHexes[i]) : bls12_381.utils.randomPrivateKey();
    let p = bls12_381.G1.ProjectivePoint.fromPrivateKey(privKey);
    let pubkey = g1PointToBytesLE(p, true);

    beaconState.validators.push({
        pubkey: pubkey,
        withdrawalCredentials: Uint8Array.from(Array(32).fill(0)),
        effectiveBalance: 32000000,
        slashed: false,
        activationEligibilityEpoch: i,
        activationEpoch: i + 1,
        exitEpoch: 100,
        withdrawableEpoch: 0
    });
    privKeyHexes[i] = bytesToHex(privKey);
    pubKeyPoints.push(p);
    validatorBaseGindices.push(BeaconStateSsz.getPathInfo(['validators', i]).gindex);
    gindices.push(BeaconStateSsz.getPathInfo(['validators', i, 'pubkey']).gindex * 2n);
    gindices.push(BeaconStateSsz.getPathInfo(['validators', i, 'pubkey']).gindex * 2n + 1n);
    gindices.push(BeaconStateSsz.getPathInfo(['validators', i, 'effectiveBalance']).gindex);
    gindices.push(BeaconStateSsz.getPathInfo(['validators', i, 'slashed']).gindex);
    gindices.push(BeaconStateSsz.getPathInfo(['validators', i, 'activationEpoch']).gindex);
    gindices.push(BeaconStateSsz.getPathInfo(['validators', i, 'exitEpoch']).gindex);

    nonRlcGindices.push(BeaconStateSsz.getPathInfo(['validators', i, 'effectiveBalance']).gindex);
    nonRlcGindices.push(BeaconStateSsz.getPathInfo(['validators', i, 'slashed']).gindex);
    nonRlcGindices.push(BeaconStateSsz.getPathInfo(['validators', i, 'activationEpoch']).gindex);
    nonRlcGindices.push(BeaconStateSsz.getPathInfo(['validators', i, 'exitEpoch']).gindex);
}

fs.writeFileSync(
    `../test_data/validators.json`,
    serialize(Array.from(beaconState.validators.entries()).map(([i, validator]) => ({
        id: i,
        shufflePos: i,
        committee: Math.floor(i / N_validators),
        isActive: !validator.slashed && validator.activationEpoch <= targetEpoch && targetEpoch < validator.exitEpoch,
        isAttested: true,
        pubkey: Array.from(validator.pubkey),
        pubkeyUncompressed: Array.from(g1PointToBytesLE(pubKeyPoints[i], false)),
        effectiveBalance: validator.effectiveBalance,
        slashed: validator.slashed,
        activationEpoch: validator.activationEpoch,
        exitEpoch: validator.exitEpoch,
        gindex: validatorBaseGindices[i]
    })))
);

fs.writeFileSync(
    `../test_data/private_keys.json`,
    serialize(privKeyHexes)
);


//----------------- Committees -----------------//
const committeePubkeys = chunkArray(pubKeyPoints, N_validators);
const aggregatedPubKeys = committeePubkeys.map((pubKeys) => bls12_381.aggregatePublicKeys(pubKeys));
let bytesPubkeys = aggregatedPubKeys.map((aggPubkey) => Array.from(g1PointToBytesLE(aggPubkey, false)));

fs.writeFileSync(
    `../test_data/aggregated_pubkeys.json`,
    serialize(bytesPubkeys)
);

// //-----------------Attestations ----------------//

type Attestations = ValueOf<typeof ssz.phase0.BeaconBlockBody.fields.attestations>;
let attestations: Attestations = [];

const beaconStateRoot = BeaconStateSsz.hashTreeRoot(beaconState);
const committeePrivKeys = chunkArray(privKeyHexes, N_validators);

for (let i = 0; i < N_committees; i++) {
    let data = {
        slot: 32,
        index: i,
        beaconBlockRoot: Uint8Array.from(Array(32).fill(0)),
        source: {
            epoch: targetEpoch - 1,
            root: Uint8Array.from(Array(32).fill(0))
        },
        target: {
            epoch: targetEpoch,
            root: beaconStateRoot,
        }
    };
    
    let dataRoot = ssz.phase0.AttestationData.hashTreeRoot(data);
    
    let msgPoint = bls12_381.G2.ProjectivePoint.fromAffine(bls12_381.G2.hashToCurve(dataRoot, {
        DST: DST,
    }).toAffine());
    
    let signatures = committeePrivKeys[i].map((privKey) => msgPoint.multiply(BigInt('0x' + privKey)));
    let aggSignature = bls12_381.aggregateSignatures(signatures);

    // assert signature is valid
    bls12_381.verify(aggSignature, msgPoint, aggregatedPubKeys[i]);
    
    let sigBytes = g2PointToLeBytes(aggSignature, true);
    
    attestations.push({
        aggregationBits: BitArray.fromBoolArray(Array(N_validators).fill(1)),
        data: data,
        signature: sigBytes
    });
}


let attestationJson = ssz.phase0.BeaconBlockBody.fields.attestations.toJson(attestations);

fs.writeFileSync(
    `../test_data/attestations.json`,
    JSON.stringify(attestationJson)
);


//----------------- State tree -----------------//

let view = BeaconStateSsz.toView(beaconState);


let proof = createProof(view.node, { type: ProofType.multi, gindices: gindices }) as MultiProof;

let [partial_tree, trace] = createNodeFromMultiProofWithTrace(proof.leaves, proof.witnesses, proof.gindices, nonRlcGindices);
// printTrace(partial_tree, trace);
console.log("state_root:", bytesToHex(view.hashTreeRoot()));

fs.writeFileSync(
    `../test_data/merkle_trace.json`,
    serialize(trace)
);
