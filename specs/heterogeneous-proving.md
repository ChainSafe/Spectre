# Heterogeneous Proofs Composition

The motivation for this optimization comes from the fact that certain prove systems are inherently better suited for certain types of computation. For the purpose of this document prove systems are defined by arithmetization (R1CS, PLONKish, AIR) and cryptographic compiler (KZG, IPA, FRI).

The primary application of interest is SHA256 that mainly consists of bitwise operations where wire values are either 0 or 1. With R1CS, this reduces most of the computations from elliptic curve scalar multiplication to elliptic curve point addition. However, wire values are not directly used in Plonk’s computations, so the special wire structure in SHA-256 does not reduce the amount of computation needed in Plonk frameworks. 


[![](https://ethresear.ch/uploads/default/optimized/2X/b/b896f5f8076c06d25e49a81753efb557a9802705_2_555x371.png)](https://ethresear.ch/t/benchmarking-zkp-development-frameworks-the-pantheon-of-zkp/14943)


AIR-based systems, such as STARK, incur the least overhead, which combined with a much smaller field (64-bit Goldilocks) used by the cryptographic compiler (FRI) makes them superior in proving efficiency (time + peak memory consumption). The tradeoff is that STARK proofs are significantly larger than any SNARK-system.

The proposed optimization is, therefore, to leverage the efficient prover of AIR+FRI system (eg. [Starky](https://github.com/mir-protocol/plonky2/tree/main/starky)) to generate a proof $\pi_{sha}$ for a large number SHA256 hashes. The aggregation circuit for the main SNARK-system (eg. Halo 2) would implement Starky verifier for the proof $\pi_{sha}$. This way, verified hashes can be used in Halo 2 via lookup arguments securely and trustlessly without the overhead of verifying them in PlonK.

## Starky `SHA256` circuit

### Circuit layout
- `preimages`: 512-bit padded sequence of bytes.
- `hashes`: 256-bit hashes.
- `prev_proof`: optional recursive proof.
- `starky_verifier_chip`

### Circuit constraint
1. Takes $N$ `preimages` and $N$ `hashes` as public input and optional proof $\pi_{sha}$ as private input. $N$ is a variable number between 1 and $M$ where $M$ is a constant enforced by circuit.
2. Re-calculates hashes for inputs and enforces equality constraint between results and `hashes` inputs. 
3. Verifies proof $\pi_{sha}$ if supplied

### References
- https://github.com/celer-network/plonky2-bench/tree/merkle-stark/merkle-stark/src/sha256_stark

## Halo2 `StarkyVerifier` circuit

> To be specified...

## References
- FRI gadget for Halo2 https://github.com/maxgillett/halo2-fri-gadget
- `Plonky2Verifier` for Halo2 https://github.com/DoHoonKim8/stark-verifier/tree/main/semaphore_aggregation/src/snark/chip
- STARK verifier in Circom https://github.com/0xPolygonHermez/pil-stark/blob/main/circuits.bn128/stark_verifier.circom.ejs
- Winterfell STARK verifier in Circom https://github.com/VictorColomb/stark-snark-recursive-proofs