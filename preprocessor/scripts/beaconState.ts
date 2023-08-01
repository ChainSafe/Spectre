import fs from "fs";
import {getClient, HttpError} from "@lodestar/api";
import {config} from "@lodestar/config/default";
import {ssz} from "@lodestar/types";
import {
    ContainerType,
    ContainerNodeStructType,
    ListCompositeType,
    ValueOf
} from "@chainsafe/ssz";
import { serialize } from "./util";
import { createProof, ProofType, MultiProof, Node, Gindex} from "@chainsafe/persistent-merkle-tree";
import { createNodeFromMultiProofWithTrace, printTrace } from "./merkleTrace";
import {fromHex} from "@lodestar/utils"


// Testing Constants
    // commenting out in favor of a flexible validators count ==> set to beaconstate.validators.length
const N_VALIDATORS_COUNT = 100;
const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const VALIDATOR_LIMIT = 1099511627776;
const TARGET_EPOCH = 90625;
const SLOTS_IN_EPOCH = [2900001, 2900032]

// sepolia endpoint
// const api = getClient({baseUrl: "https://lodestar-sepolia.chainsafe.io"}, {config});
// sepolia beacon node endpoint
const api = getClient({baseUrl: "http://3.133.148.86:80"}, {config});

const beaconstateApi = await 
    api.debug
    .getStateV2(
        "head",
        "ssz")
    .then((res) => {
        if (res.ok) {
            return res.response;
        } else {
            console.error(res.status, res.error.code, res.error.message);
            return new Uint8Array;
        }
    });

let beaconstateSsz = beaconstateApi;
let beaconstateJson = ssz.capella.BeaconState.toJson(ssz.capella.BeaconState.deserialize(beaconstateSsz));
let beaconstateDeserialized = ssz.capella.BeaconState.deserializeToViewDU(beaconstateSsz);

// ------------ Validators Data ------------ // 

type Validator = ValueOf<typeof ValidatorContainer>;
let validators: Validator[] = [];
let validatorBaseGindices: bigint[] = [];
let gindices: bigint[] = [];
// the gindices of the fields that are <= 31 bytes
let nonRlcGindices = [];

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
    { 
        typeName: "Validator",
        jsonCase: "eth2" 
    }
);

// mainnet beacon state validator limit = 1099511627776
// must use this value to have the proper tree depth and and chunk depth
// treeDepth == 41
// chunkDepth == 40
// let n_validators_count = beaconstateJson.validators.length;
export const ValidatorsSsz = new ListCompositeType(ValidatorContainer, VALIDATOR_LIMIT);

// mainnet validators length: 853056
// sepolia validators length:   1973
// console.log("beaconstate ssz validators length: ", beaconstateJson.validators.length);

// for loop in which the constant set for N_VALIDATORS_COUNT
// size of this array will be set by constant
for (let i=0; i<N_VALIDATORS_COUNT-1;i++) {
    let pubkey = fromHex(beaconstateJson.validators[i].pubkey);
    const paddedPubkey = new Uint8Array(48);
    paddedPubkey.set(pubkey, 0);

    validators.push({
        pubkey: paddedPubkey,
        withdrawalCredentials: fromHex(beaconstateJson.validators[i].withdrawal_credentials),
        effectiveBalance: beaconstateJson.validators[i].effective_balance,
        slashed: beaconstateJson.validators[i].slashed,
        activationEligibilityEpoch: beaconstateJson.validators[i].activation_eligibility_epoch,
        activationEpoch: beaconstateJson.validators[i].activation_epoch,
        exitEpoch: beaconstateJson.validators[i].exit_epoch,
        withdrawableEpoch: beaconstateJson.validators[i].withdrawable_epoch
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


//----------------- State tree -----------------//

let proof = createProof(view.node, { type: ProofType.multi, gindices: gindices }) as MultiProof;

const areEqual = (first: Uint8Array, second: Uint8Array) =>
    first.length === second.length && first.every((value, index) => value === second[index]);

let [partial_tree, trace] = createNodeFromMultiProofWithTrace(proof.leaves, proof.witnesses, proof.gindices, nonRlcGindices);

printTrace(partial_tree, trace);

// console.log("proof: ", proof)
// console.log("trace: ", serialize(trace))

fs.writeFileSync(
    `../test_data/sepolia_beacon_state.json`,
    serialize(trace)
)


// ------------ Attestations ------------ //

type Attestations = ValueOf<typeof ssz.phase0.BeaconBlockBody.fields.attestations>;
let attestations: Attestations = [];

async function getBlockAttestationApi(slot: number) {
    return await api.beacon
    .getBlockAttestations(
            slot
        )
    .then((res) => {
        if (res.ok) {
            return res.response;
        } else {
            // console.error(res.status, res.error.code, res.error.message);
            return undefined;
        }
    });
}

// get all blocks within a target epoch
for (var i=SLOTS_IN_EPOCH[0]; i<=SLOTS_IN_EPOCH[1]; i++) {
    let blockAttestation = await getBlockAttestationApi(i);
    if (blockAttestation == undefined) {
        // console.log("empty slot");
        continue;
    };
    if (blockAttestation.data[0].data.target.epoch == TARGET_EPOCH) {
        let data = {
            slot: blockAttestation.data[0].data.slot,
            index: blockAttestation.data[0].data.index,
            beaconBlockRoot: blockAttestation.data[0].data.beaconBlockRoot,
            source: {
                epoch: blockAttestation.data[0].data.source.epoch,
                root: blockAttestation.data[0].data.source.root
            },
            target: {
                epoch: blockAttestation.data[0].data.target.epoch,
                root: blockAttestation.data[0].data.target.root
            }
        };

        attestations.push({
            aggregationBits: blockAttestation.data[0].aggregationBits,
            data: data,
            signature: blockAttestation.data[0].signature
        });

    }

};

let attestationJson = ssz.phase0.BeaconBlockBody.fields.attestations.toJson(attestations);

// console.log(attestationJson);

fs.writeFileSync(
    `../test_data/sepolia_attestations.json`,
    JSON.stringify(attestationJson)
);





