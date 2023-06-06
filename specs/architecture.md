---
tags: [zk-casper]
---

# ZK-CASPER Architecture

The key component in `BansheeZK` architecture are lookup tables. When a circuit encounters an expensive operation (e.g. hashing) instead of doing the computation, the precomputed result is checked for consistency with a dedicated table via lookup argument in a simple input-output relationship.

![](https://hackmd.io/_uploads/r15f4ChH2.png)

The content of each table is computed off-circuit and supplied during proof generation. Each table has one or more circuits to enforce constraints on its content, unless it's a fixed table such as for logical operations (e.g. AND, OR).

> **Note:** lookup arguments can usually only allowed to access tables containing public values that both verifier and prover knows which are fixed during circuit compilation. In `halo2-ce` fork this limitation is removed (see [PR](https://github.com/privacy-scaling-explorations/halo2/pull/8)) allowing lookups to private `Advice` columns.

The sub-circuits can either be placed within a super-circuit or proved separately. In the second scenario resulted proofs must later be aggregated into a single final proof to ensure succinct verification.

The multiple-circuits/multiple-proofs approach has a few noteworthy benefits:
- Placing everything in one circuit will creat a significant overhead during proof generation due to a large number of rows. Splitting the logic avoids that, allowing individual circuits to remain at a manageable size.
- Proofs for some circuits can be generated in parallel, further reducing latency.
- Optimization can be achieved by applying specialized prove system for individual circuits, as long as their verifiers can be expressed in the primary system arithmetization more efficiently than just doing the outsourced computation.

The last point is particularly intriguing because certain prove systems are inherently better suited for certain types of computation. This avenue is explored in [this](/gLyD0yyOQFCmB6oetW_48w) document.

## Diagram

![](https://hackmd.io/_uploads/Bk0k9dwIh.png)
