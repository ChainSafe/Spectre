import { GindexBitstring } from "@chainsafe/persistent-merkle-tree";


function toSnakeCase(str: string): string {
  return str.replace(/\.?([A-Z]+)/g, (x, y) => "_" + y.toLowerCase()).replace(/^_/, "");
}

function toRustFormat(obj: any, keysToSkip: string[] = [], replacer: (value: any) => any = (value) => value): any {
  if (Array.isArray(obj)) {
    return obj.map(v => toRustFormat(v, keysToSkip, replacer));
  } else if (obj !== null && typeof obj === 'object') {
    return Object.keys(obj).reduce(
      (result, key) => ({
        ...result,
        ...(keysToSkip.includes(key) ? {} : { 
          [toSnakeCase(key)]: toRustFormat(replacer(obj[key]), keysToSkip, replacer)
        })
      }),
      {}
    );
  }
  return replacer(obj);
}

export function serialize(obj: any, keysToSkip: string[] = []): string {
  const processed = toRustFormat(obj, keysToSkip, (value) => {
    if (value instanceof Uint8Array) {
      return Array.from(value);
    }
    if (typeof value === 'bigint') {
      return Number(value);
    }
    return value;
  });
  return JSON.stringify(processed);
}

export enum SortOrder {
    InOrder,
    Decreasing,
    Unsorted,
}

/**
 * Return the set of generalized indices required for a multiproof
 * This may include all leaves and any necessary witnesses
 * @param gindices leaves to include in proof
 * @returns all generalized indices required for a multiproof (leaves and witnesses), deduplicated and sorted
 */
export function computeMultiProofBitstrings(
    gindices: GindexBitstring[],
    includeLeaves = true,
    sortOrder = SortOrder.InOrder
  ): GindexBitstring[] {
    const leaves = filterParentBitstrings(gindices);
    // Maybe initialize the proof indices with the leaves
    const proof = new Set<GindexBitstring>(includeLeaves ? leaves : []);
    const paths = new Set<GindexBitstring>();
    const branches = new Set<GindexBitstring>();
  
    // Collect all path indices and all branch indices
    let maxBitLength = 1;
    for (const gindex of leaves) {
      if (gindex.length > maxBitLength) maxBitLength = gindex.length;
      const {path, branch} = computeProofBitstrings(gindex);
      path.forEach((g) => paths.add(g));
      branch.forEach((g) => branches.add(g));
    }
  
    // Remove all branches that are included in the paths
    paths.forEach((g) => branches.delete(g));
    // Add all remaining branches to the leaves
    branches.forEach((g) => proof.add(g));
  
    switch (sortOrder) {
      case SortOrder.InOrder:
        return sortInOrderBitstrings(Array.from(proof), maxBitLength);
      case SortOrder.Decreasing:
        return sortDecreasingBitstrings(Array.from(proof));
      case SortOrder.Unsorted:
        return Array.from(proof);
    }
  }

  /**
 * Sort generalized indices in decreasing order
 */
export function sortDecreasingBitstrings(gindices: GindexBitstring[]): GindexBitstring[] {
    if (!gindices.length) {
      return [];
    }
    return gindices.sort((a, b) => {
      if (a.length < b.length) {
        return 1;
      } else if (b.length < a.length) {
        return -1;
      }
      let aPos0 = a.indexOf("0");
      let bPos0 = b.indexOf("0");
      // eslint-disable-next-line no-constant-condition
      while (true) {
        if (aPos0 === -1) {
          return -1;
        } else if (bPos0 === -1) {
          return 1;
        }
  
        if (aPos0 < bPos0) {
          return 1;
        } else if (bPos0 < aPos0) {
          return -1;
        }
  
        aPos0 = a.indexOf("0", aPos0 + 1);
        bPos0 = b.indexOf("0", bPos0 + 1);
      }
    });
  }
  
/**
 * Filter out parent generalized indices
 */
export function filterParentBitstrings(gindices: GindexBitstring[]): GindexBitstring[] {
    const sortedBitstrings = gindices.slice().sort((a, b) => a.length - b.length);
    const filtered: GindexBitstring[] = [];
    outer: for (let i = 0; i < sortedBitstrings.length; i++) {
      const bsA = sortedBitstrings[i];
      for (let j = i + 1; j < sortedBitstrings.length; j++) {
        const bsB = sortedBitstrings[j];
        if (bsB.startsWith(bsA)) {
          continue outer;
        }
      }
      filtered.push(bsA);
    }
    return filtered;
  }


/**
 * Compute both the path and branch indices
 *
 * Path indices are parent indices upwards toward the root
 * Branch indices are witnesses required for a merkle proof
 */
export function computeProofBitstrings(gindex: GindexBitstring): {
    path: Set<GindexBitstring>;
    branch: Set<GindexBitstring>;
  } {
    const path = new Set<GindexBitstring>();
    const branch = new Set<GindexBitstring>();
    let g = gindex;
    while (g.length > 1) {
      path.add(g);
      const lastBit = g[g.length - 1];
      const parent = g.substring(0, g.length - 1);
      branch.add(parent + (Number(lastBit) ^ 1));
      g = parent;
    }
    return {path, branch};
  }

  /**
 * Sort generalized indices in-order
 * @param bitLength maximum bit length of generalized indices to sort
 */
export function sortInOrderBitstrings(gindices: GindexBitstring[], bitLength: number): GindexBitstring[] {
    if (!gindices.length) {
      return [];
    }
    return gindices
      .map((g) => g.padEnd(bitLength))
      .sort()
      .map((g) => g.trim());
  }
