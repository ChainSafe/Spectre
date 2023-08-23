import fs from "fs";
import { bls12_381 } from '@noble/curves/bls12-381'
import {
    ssz,
} from "@lodestar/types"
import { createProof, ProofType, MultiProof, Node } from "@chainsafe/persistent-merkle-tree";
import { chunkArray, g1PointToLeBytes as g1PointToBytesLE, g2PointToLeBytes, serialize } from "./util";
import { createNodeFromMultiProofWithTrace, printTrace } from "./merkleTrace";
import { hexToBytes, bytesToHex, numberToBytesBE } from "@noble/curves/abstract/utils";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { createNodeFromCompactMultiProof } from "@chainsafe/persistent-merkle-tree/lib/proof/compactMulti";
import { BeaconStateCache, computeSigningRoot } from "@lodestar/state-transition";
import { createBeaconConfig, BeaconConfig } from "@lodestar/config";
import { config as chainConfig } from "@lodestar/config/default";
import { DOMAIN_SYNC_COMMITTEE } from "@lodestar/params";

const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const N_validators = parseInt(process.argv[2]) || 512;

let privKeyHexes: string[] = JSON.parse(fs.readFileSync("../test_data/private_keys.json").toString());

const targetEpoch = 25;

//----------------- Beacon state -----------------//

let beaconState = ssz.capella.BeaconState.deserialize(new Uint8Array(fs.readFileSync("../test_data/beacon_state_2915750")));
beaconState.validators = [];
beaconState.currentSyncCommittee.pubkeys = [];
const config = createBeaconConfig(chainConfig, beaconState.genesisValidatorsRoot);


//----------------- Validators -----------------//

let pubKeyPoints: ProjPointType<bigint>[] = [];

for (let i = 0; i < N_validators; i++) {
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
    beaconState.currentSyncCommittee.pubkeys.push(pubkey);
}


fs.writeFileSync(
    `../test_data/private_keys.json`,
    serialize(privKeyHexes)
);


//----------------- Sync Committee -----------------//

const aggregatedPubKey = bls12_381.aggregatePublicKeys(pubKeyPoints);
beaconState.currentSyncCommittee.aggregatePubkey = g1PointToBytesLE(aggregatedPubKey, true);

//--------------------- Sync ---------------------//

const beaconStateRoot = ssz.capella.BeaconState.hashTreeRoot(beaconState);

let attestedBlock = {
    slot: 32,
    proposerIndex: 0,
    parentRoot: Uint8Array.from(Array(32).fill(0)),
    stateRoot: beaconStateRoot,
    bodyRoot: beaconState.blockRoots[beaconState.blockRoots.length - 1],
};

let domain = config.getDomain(32, DOMAIN_SYNC_COMMITTEE, 32)

const dataRoot = computeSigningRoot(ssz.phase0.BeaconBlockHeader, attestedBlock, domain)

let msgPoint = bls12_381.G2.ProjectivePoint.fromAffine(bls12_381.G2.hashToCurve(dataRoot, {
    DST: DST,
}).toAffine());

let signatures = privKeyHexes.slice(0, N_validators).map((privKey) => msgPoint.multiply(BigInt('0x' + privKey)));
let aggSignature = bls12_381.aggregateSignatures(signatures);

// assert signature is valid
// console.log("sig:", aggSignature.toAffine());
// console.log("msg:", msgPoint.toAffine());
// console.log("pk:", aggregatedPubKey.toAffine());
console.assert(bls12_381.verify(aggSignature, msgPoint, aggregatedPubKey));

const syncSigBytes = g2PointToLeBytes(aggSignature, true);
const attestedBlockJson = ssz.phase0.BeaconBlockHeader.toJson(attestedBlock);

//----------------- State tree -----------------//

let view = ssz.altair.SyncCommittee.fields.pubkeys.toView(beaconState.currentSyncCommittee.pubkeys);

let gindices = Array.from({ length: N_validators }, (_, i) => ssz.altair.SyncCommittee.fields.pubkeys.getPathInfo([i]).gindex);

let proof = createProof(view.node, { type: ProofType.multi, gindices: gindices }) as MultiProof;

let [partial_tree, trace] = createNodeFromMultiProofWithTrace(proof.leaves, proof.witnesses, proof.gindices, []);
printTrace(partial_tree, trace);

// fs.writeFileSync(
//     `../test_data/merkle_trace.json`,
//     serialize(trace)
// );


let input = {
    targetEpoch: targetEpoch,
    syncCommittee: Array.from(beaconState.validators.entries()).map(([i, validator]) => ({
        id: i,
        isAttested: true,
        pubkey: Array.from(validator.pubkey),
        pubkeyUncompressed: Array.from(g1PointToBytesLE(pubKeyPoints[i], false)),
    })),
    domain: Array.from(domain),
    attestedBlock: attestedBlockJson,
    syncSignature: syncSigBytes,
    merkleTrace: trace,
}

fs.writeFileSync(
    `../test_data/sync_state.json`,
    serialize(input)
);
