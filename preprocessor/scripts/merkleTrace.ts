import {Node, BranchNode, LeafNode, Gindex} from "@chainsafe/persistent-merkle-tree";
import { SortOrder, computeMultiProofBitstrings, } from "./util";

type TraceRow = {
    node: Uint8Array;
    index: Gindex;
    sibling: Uint8Array;
    siblingIndex: Gindex;
    intoLeft: boolean;
    isLeft: boolean;
    isRight: boolean;
    parent: Uint8Array;
    parentIndex: Gindex;
    depth: number;
};

export function createNodeFromMultiProofWithTrace(leaves: Uint8Array[], witnesses: Uint8Array[], gindices: Gindex[]): [Node, TraceRow[]] {
    if (leaves.length !== gindices.length) {
      throw new Error("Leaves length should equal gindices length");
    }
  
    const leafBitstrings = gindices.map((gindex) => gindex.toString(2));
    const witnessBitstrings = computeMultiProofBitstrings(leafBitstrings, false, SortOrder.Decreasing);
  
    if (witnessBitstrings.length !== witnesses.length) {
      throw new Error("Witnesses length should equal witnesses gindices length");
    }
  
    // Algorithm:
    // create an object which tracks key-values for each level
    // pre-load leaves and witnesses into the level object
    // level by level, starting from the bottom,
    // find the sibling, create the parent, store it in the next level up
    // the root is in level 1
    const maxLevel = Math.max(leafBitstrings[0]?.length ?? 0, witnessBitstrings[0]?.length ?? 0);
  
    const levels: Record<number, Record<string, Node>> = Object.fromEntries(
      Array.from({length: maxLevel}, (_, i) => [i + 1, {}])
    );
  
    // preload leaves and witnesses
    for (let i = 0; i < leafBitstrings.length; i++) {
      const leafBitstring = leafBitstrings[i];
      const leaf = leaves[i];
      levels[leafBitstring.length][leafBitstring] = LeafNode.fromRoot(leaf);
    }
    for (let i = 0; i < witnessBitstrings.length; i++) {
      const witnessBitstring = witnessBitstrings[i];
      const witness = witnesses[i];
      levels[witnessBitstring.length][witnessBitstring] = LeafNode.fromRoot(witness);
    }

    let trace: TraceRow[] = [];
  
    for (let i = maxLevel; i > 1; i--) {
      const level = levels[i];
      const parentLevel = levels[i - 1];
      for (const bitstring of Object.keys(level)) {
        const nodeGindex = BigInt(parseInt(bitstring, 2));
        const node = level[bitstring];
        // if the node doesn't exist, we've already processed its sibling
        if (!node) {
          continue;
        }
  
        const isLeft = bitstring[bitstring.length - 1] === "0";
        const parentBitstring = bitstring.substring(0, bitstring.length - 1);
        const parentGindex = BigInt(parseInt(parentBitstring, 2));

        const siblingBitstring = parentBitstring + (isLeft ? "1" : "0");
        const siblingGindex = BigInt(parseInt(siblingBitstring, 2));
  
        const siblingNode = level[siblingBitstring];
        if (!siblingNode) {
          throw new Error(`Sibling not found: ${siblingBitstring}`);
        }
  
        // store the parent node
        const parentNode = isLeft ? new BranchNode(node, siblingNode) : new BranchNode(siblingNode, node);
        trace.push({
            node: node.root,
            index: nodeGindex,
            sibling: siblingNode.root,
            siblingIndex: siblingGindex,
            intoLeft: parentBitstring[parentBitstring.length - 1] === "0",
            isLeft: gindices.includes(isLeft ? nodeGindex : siblingGindex),
            isRight: gindices.includes(isLeft ? siblingGindex : nodeGindex),
            parent: parentNode.root,
            parentIndex: parentGindex,
            depth: i,
        });
        
        parentLevel[parentBitstring] = parentNode;
  
        // delete the used nodes
        delete level[bitstring];
        delete level[siblingBitstring];
      }
    }

    const root = levels[1]["1"];

    trace.push({
      node: root.root,
      index: 1n,
      sibling: Uint8Array.from([]),
      siblingIndex: 0n,
      intoLeft: false,
      isLeft: false,
      isRight: false,
      parent: Uint8Array.from([]),
      parentIndex: 0n,
      depth: 1,
    });
    if (!root) {
      throw new Error("Internal consistency error: no root found");
    }
    return [root, trace];
  }

export function printTrace(node: Node, trace: TraceRow[]) {
  let current_level = trace[0].depth;
  let row_index = 0;

  function draw_separator() {
      console.log('|-----||-------|---------|--------|---------|-------|----------|--------|---------|---------|--------|')
  }

  console.log();
  draw_separator();
  console.log('| Row || Depth | Sibling | sIndex |  Node   | Index | IntoLeft | IsLeft | IsRight | Parent  | pIndex |')
  draw_separator();
  for (let t of trace.slice(0, trace.length - 1)) {
      if (t.depth != current_level) {
          draw_separator()
          current_level = t.depth;
      }
      let node = Buffer.from(t.node).toString("hex").substring(0, 7);
      let sibling = Buffer.from(t.sibling).toString("hex").substring(0, 7);
      let parent = Buffer.from(t.parent).toString("hex").substring(0, 7);
      console.log(`| ${(row_index++).toString().padEnd(3, ' ')} ||  ${t.depth.toString().padEnd(3, ' ')}  | ${sibling} |  ${t.siblingIndex.toString().padEnd(4, ' ')}  | ${node} | ${t.index.toString().padEnd(4, ' ')}  |    ${t.intoLeft ? 1 : 0}     |   ${t.isLeft ? 1 : 0}    |    ${t.isRight ? 1 : 0}    | ${parent} |  ${t.parentIndex.toString().padEnd(4, ' ')}  |`)
  }

  let root = Buffer.from(node.root).toString("hex").substring(0, 7);
  draw_separator();
  console.log(`| ${(++row_index).toString().padEnd(3, ' ')} ||  1    |         |        | ${root} | 1     |          |        |         |         |        |`)
  draw_separator();
}
