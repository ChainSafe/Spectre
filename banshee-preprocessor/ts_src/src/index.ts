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
import { createNodeFromMultiProofWithTrace, printTrace } from "./merkleTrace";
import crypto from "crypto";


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
let gindeces: bigint[] = [];

for (let i = 0; i < N; i++) {
    validators.push({
        pubkey: crypto.randomBytes(48),
        activationEpoch: i + 1,
        effectiveBalance: 32000000,
        withdrawalCredentials: crypto.randomBytes(32),
        slashed: false,
        activationEligibilityEpoch: i,
        exitEpoch: 100,
        withdrawableEpoch: 0
    });
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n + 1n);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'effectiveBalance']).gindex);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'slashed']).gindex);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'activationEpoch']).gindex);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'exitEpoch']).gindex);
}
let view = ValidatorsSsz.toView(validators);

function printTree(tree: Node, depth: number = 0) {
    console.log(" ".repeat(depth), depth, "0x" + Buffer.from(tree.root).toString("hex"), tree.isLeaf() ? "leaf" : "");
    if (tree.isLeaf())
        return;
    if (tree.left) {
        printTree(tree.left, depth + 1,);
    }
    if (tree.right) {
        printTree(tree.right, depth + 1);
    }
}
// printTree(view.node);


console.log('gindeces:', gindeces);

let proof = createProof(view.node, {type: ProofType.multi, gindices: gindeces}) as MultiProof; 

const areEqual = (first: Uint8Array, second: Uint8Array) =>
    first.length === second.length && first.every((value, index) => value === second[index]);


let [partial_tree, trace] = createNodeFromMultiProofWithTrace(proof.leaves, proof.witnesses, proof.gindices);

printTrace(partial_tree, trace);

console.log("\nisValid?", areEqual(partial_tree.root, view.node.root));
