import fs from "fs";
import { bls12_381 } from '@noble/curves/bls12-381';
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
import { g1PointToLeBytes as g1PointToBytesLE, g2PointToLeBytes, serialize } from "./util";
import { createNodeFromMultiProofWithTrace, printTrace } from "./merkleTrace";
import { hexToBytes, bytesToHex } from "@noble/curves/abstract/utils";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";

const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

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

let nonRlcGindices = [];

let privKeyHexes = [
    "5644920314564b11404384380c1d677871ada2ec9470d5f43f03aa931ecef54b",
    "4314d9849e5cb4add3579426ba8833621dcfeba8f8b33ec8779e76c8facf6b6a",
    "6d973b68057d1b01425eb705d9951cf725aa4f138ded6d56fca23d03b7200575",
    "3ae65153efe6e1103561cc672aa0044784df0244bf9cae8489fe9ab93120ee70",
    "078384584ee0800afb493de39a95955be2132f21fdbf82d2c35a603846cb4cc8"
];

const target_epoch = 25;

//----------------- State tree -----------------//

let pubKeyPoints: ProjPointType<bigint>[] = [];

for (let i = 0; i < N; i++) {
    // use 5 pregenerated private keys to avoid changing JSON files.
    let privKey = i < 5 ? hexToBytes(privKeyHexes[i]) : bls12_381.utils.randomPrivateKey();
    let p = bls12_381.G1.ProjectivePoint.fromPrivateKey(privKey);
    let pubkey = g1PointToBytesLE(p, true);

    validators.push({
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

fs.writeFileSync(
    `../test_data/validators.json`,
    serialize(Array.from(validators.entries()).map(([i, validator]) => ({
        id: i,
        shufflePos: i,
        committee: 0,
        isActive: !validator.slashed && validator.activationEpoch <= target_epoch && target_epoch < validator.exitEpoch,
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

//----------------- Committees -----------------//

const aggregatedPubKey = bls12_381.aggregatePublicKeys(pubKeyPoints);
const aggPubkeyBytes = g1PointToBytesLE(aggregatedPubKey, false);

let bytesPubkeys = [
    Array.from(aggPubkeyBytes),
];

fs.writeFileSync(
    `../test_data/aggregated_pubkeys.json`,
    serialize(bytesPubkeys)
);

// //-----------------Attestations ----------------//

type Attestations = ValueOf<typeof ssz.phase0.BeaconBlockBody.fields.attestations>;
let attestations: Attestations = [];

let data = {
    slot: 0,
    index: 0,
    beaconBlockRoot: Uint8Array.from(Array(32).fill(0)),
    source: {
        epoch: target_epoch - 1,
        root: Uint8Array.from(Array(32).fill(0))
    },
    target: {
        epoch: target_epoch,
        root: Uint8Array.from(Array(32).fill(0))
    }
};

let dataRoot = ssz.phase0.AttestationData.hashTreeRoot(data);

let msgPoint = bls12_381.G2.ProjectivePoint.fromAffine(bls12_381.G2.hashToCurve(dataRoot, {
    DST: DST,
}).toAffine());

let signatures = [];
for (const privKey of privKeyHexes) {
    const sigPoint = msgPoint.multiply(BigInt('0x' + privKey));
    signatures.push(sigPoint);
}

let signature = bls12_381.aggregateSignatures(signatures)

// assert signature is valid
bls12_381.verify(signature, msgPoint, aggregatedPubKey);

let sigBytes = g2PointToLeBytes(signature, true);

attestations.push({
    aggregationBits: BitArray.fromBoolArray(Array(N).fill(1)),
    data: data,
    signature: sigBytes
});

let attestationJson = ssz.phase0.BeaconBlockBody.fields.attestations.toJson(attestations);

fs.writeFileSync(
    `../test_data/attestations.json`,
    JSON.stringify(attestationJson)
);


//----------------- State tree -----------------//
let view = ValidatorsSsz.toView(validators);

let proof = createProof(view.node, { type: ProofType.multi, gindices: gindices }) as MultiProof;

const areEqual = (first: Uint8Array, second: Uint8Array) =>
    first.length === second.length && first.every((value, index) => value === second[index]);

let [partial_tree, trace] = createNodeFromMultiProofWithTrace(proof.leaves, proof.witnesses, proof.gindices, nonRlcGindices);

// printTrace(partial_tree, trace);

fs.writeFileSync(
    `../test_data/merkle_trace.json`,
    serialize(trace)
);
