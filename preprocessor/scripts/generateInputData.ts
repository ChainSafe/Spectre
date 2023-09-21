import fs from "fs";
import { bls12_381 } from '@noble/curves/bls12-381'
import {
    ssz,
} from "@lodestar/types"
import { createProof, ProofType, MultiProof, Node, SingleProof, TreeOffsetProof, LeafNode, BranchNode, Gindex, gindexIterator, createNodeFromProof } from "@chainsafe/persistent-merkle-tree";
import { chunkArray, g1PointToLeBytes as g1PointToBytesLE, g2PointToLeBytes, serialize } from "./util";
import { createNodeFromMultiProofWithTrace, printTrace } from "./merkleTrace";
import { hexToBytes, bytesToHex, numberToBytesBE } from "@noble/curves/abstract/utils";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { createNodeFromCompactMultiProof } from "@chainsafe/persistent-merkle-tree/lib/proof/compactMulti";
import { BeaconStateCache, computeSigningRoot } from "@lodestar/state-transition";
import { createBeaconConfig, BeaconConfig } from "@lodestar/config";
import { config as chainConfig } from "@lodestar/config/default";
import { DOMAIN_SYNC_COMMITTEE } from "@lodestar/params";
import { BitArray } from "@chainsafe/ssz";
import assert from "assert";

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


//-------------- Beacon block body --------------//

let beaconBlockBody = {
    executionPayload: {
        withdrawals: [],
        transactions: [
        ],
        blockHash: Uint8Array.from(Array(32).fill(0)),
        parentHash: Uint8Array.from(Array(32).fill(0)),
        feeRecipient: Uint8Array.from(Array(20).fill(0)),
        stateRoot: Uint8Array.from(Array(32).fill(0)),
        receiptsRoot: Uint8Array.from(Array(32).fill(0)),
        logsBloom: Uint8Array.from(Array(256).fill(0)),
        prevRandao: Uint8Array.from(Array(32).fill(0)),
        blockNumber: 0,
        gasLimit: 0,
        gasUsed: 0,
        timestamp: 0,
        extraData: Uint8Array.from(Array(32).fill(0)),
        baseFeePerGas: 0n,
    },
    blsToExecutionChanges: [],
    randaoReveal: Uint8Array.from(Array(96).fill(0)), //beaconState.randaoMixes[0],
    eth1Data: beaconState.eth1Data,
    graffiti: Uint8Array.from(Array(32).fill(0)),
    proposerSlashings: [],
    attesterSlashings: [],
    attestations: [],
    deposits: [],
    voluntaryExits: [],
    syncAggregate: {
        syncCommitteeBits: BitArray.fromBitLen(512),
        syncCommitteeSignature: Uint8Array.from(Array(96).fill(0)),
    },
};

let beaconBlockTree = ssz.capella.BeaconBlockBody.toView(beaconBlockBody);

let execRootGindex = ssz.capella.BeaconBlockBody.getPathInfo(["executionPayload"]).gindex;

let execMerkleProof = createProof(beaconBlockTree.node, { type: ProofType.single, gindex: execRootGindex }) as SingleProof;

let finalizedBlock = {
    slot: 0,
    proposerIndex: 0,
    parentRoot: Uint8Array.from(Array(32).fill(0)),
    stateRoot: Uint8Array.from(Array(32).fill(0)),
    bodyRoot: beaconBlockTree.node.root,
};

beaconState.finalizedCheckpoint.root = ssz.phase0.BeaconBlockHeader.hashTreeRoot(finalizedBlock);

const finilizedBlockJson = ssz.phase0.BeaconBlockHeader.toJson(finalizedBlock);

assert.deepStrictEqual(createNodeFromProof(execMerkleProof).root, beaconBlockTree.node.root)

//--------------------- Sync ---------------------//

const beaconStateRoot = ssz.capella.BeaconState.hashTreeRoot(beaconState);

let attestedBlock = {
    slot: 32,
    proposerIndex: 0,
    parentRoot: Uint8Array.from(Array(32).fill(0)),
    stateRoot: beaconStateRoot,
    bodyRoot: beaconState.finalizedCheckpoint.root,
};

let domain = config.getDomain(32, DOMAIN_SYNC_COMMITTEE, 32)

const dataRoot = computeSigningRoot(ssz.phase0.BeaconBlockHeader, attestedBlock, domain)

let msgPoint = bls12_381.G2.ProjectivePoint.fromAffine(bls12_381.G2.hashToCurve(dataRoot, {
    DST: DST,
}).toAffine());

let signatures = privKeyHexes.slice(0, N_validators).map((privKey) => msgPoint.multiply(BigInt('0x' + privKey)));
let aggSignature = bls12_381.aggregateSignatures(signatures);

// assert signature is valid
console.assert(bls12_381.verify(aggSignature, msgPoint, aggregatedPubKey));

const syncSigBytes = g2PointToLeBytes(aggSignature, true);
const attestedBlockJson = ssz.phase0.BeaconBlockHeader.toJson(attestedBlock);


//----------------- State tree  -----------------//

let beaconStateTree = ssz.capella.BeaconState.toView(beaconState);

let finilizedBlockRootGindex = ssz.capella.BeaconState.getPathInfo(["finalizedCheckpoint", "root"]).gindex;

let finilizedBlockMerkleProof = createProof(beaconStateTree.node, { type: ProofType.single, gindex: finilizedBlockRootGindex }) as SingleProof;

assert.deepStrictEqual(createNodeFromProof(finilizedBlockMerkleProof).root, beaconStateTree.node.root)

let input = {
    targetEpoch: targetEpoch,
    pubkeysUncompressed: Array.from(beaconState.validators.entries()).map(([i, _]) => Array.from(g1PointToBytesLE(pubKeyPoints[i], false))),
    pariticipationBits: Array.from(beaconState.validators.entries()).map((_) => true),
    domain: Array.from(domain),
    attestedHeader: attestedBlockJson,
    finalizedHeader: finilizedBlockJson,
    signatureCompressed: syncSigBytes,
    executionPayloadBranch: execMerkleProof.witnesses.map((w) => Array.from(w)),
    executionStateRoot: beaconBlockBody.executionPayload.stateRoot,
    finalityBranch: finilizedBlockMerkleProof.witnesses.map((w) => Array.from(w)),
    beaconStateRoot: Array.from(beaconStateRoot),
};

fs.writeFileSync(
    `../test_data/sync_step.json`,
    serialize(input)
);

fs.writeFileSync(
    `../test_data/committee_pubkeys.json`,
    serialize(Array.from(beaconState.validators.entries()).map(([i, _]) => Array.from(g1PointToBytesLE(pubKeyPoints[i], true))))
);
