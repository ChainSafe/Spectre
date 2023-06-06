# SHA256 Circuit

The SHA256 circuit constraints SHA2 hashes used elsewhere in the protocol. These hashes are accessed through lookups to `SHA256Table`. 

Since doing SHA hashing is expensive in arithmetic form and we don't want to repeat previous work, we structure this circuit as recursive proof-of-knowledge system. On each step only the new hashes are being computed. All the remaining hashes are trusted after verifying previous instance of the recursive proof. The result is that a nearly constant size proof verifies a steadily growing number of hashes.

## Circuit layout

The attestations circuit consists of the following columns:
1. `sha256_table`: The columns from `SHA256Table`.
2. [`Table16Chip`](https://github.com/privacy-scaling-explorations/halo2/blob/main/halo2_gadgets/src/sha256/table16.rs#L240) chip
3. `State`

## Circuit behaviour
1. Circuit takes `inputs: Vec<Vec<u8>>` for hashes that must be verified.
2. On each input circuit calculates random linear combination using public randomness
	> Note: In order to preserve ability to use hashes between proof generations we cannot use plain Fiat-Shamir since it changes based on other public inputs.
	> TODO: would it be secure enough to use randomness baked into prover/verifier key?
3. Check that RLC calculated is equal to `input_rlc` and `lens(input[i) == input_len`.
4. Compute SHA2 hash for input bytes and get RLC of the output.
5. Check that result is equal to `output_rlc`.

References:
- https://github.com/ChainSafe/recursive-zk-bridge/blob/main/halo2/src/sha256.rs
- github.com/sorasuegami/halo2-dynamic-sha256
- https://github.com/duguorong009/zk-mooc-halo2
- https://github.com/scroll-tech/zkevm-circuits/pull/398
- https://github.com/privacy-scaling-explorations/zkevm-circuits/pull/268
- alternative poseidon table & circuit https://youtu.be/HhHTho2QZa4?t=2466

