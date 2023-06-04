# Heterogeneous proving

The motivation for this optimization comes from the fact that certain prove systems are inherently better suited for certain types of computation. For the purpose of this document prove systems are defined by arithmetization (R1CS, PLONKish, AIR) and cryptographic compiler (KZG, IPA, FRI).

The primary application of interest is SHA256 that mainly consists of bitwise operations where wire values are either 0 or 1. With R1CS, this reduces most of the computations from elliptic curve scalar multiplication to elliptic curve point addition. However, wire values are not directly used in Plonk’s computations, so the special wire structure in SHA-256 does not reduce the amount of computation needed in Plonk frameworks. 

AIR-based systems, such as STARK, incur least overhead, which combined with a much smaller field used by cryptographic compiler (Goldilocks, 64-bit) makes them superior in proving efficiency (time + peak memory consumption).

[![](https://ethresear.ch/uploads/default/optimized/2X/b/b896f5f8076c06d25e49a81753efb557a9802705_2_555x371.png)](https://ethresear.ch/t/benchmarking-zkp-development-frameworks-the-pantheon-of-zkp/14943)

> Benchmarks source - [the Pantheon of ZKP](https://ethresear.ch/t/benchmarking-zkp-development-frameworks-the-pantheon-of-zkp/14943).
