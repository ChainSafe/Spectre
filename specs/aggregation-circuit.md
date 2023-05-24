# Aggregation circuit

The aggregation constraints the committees and aggregated public keys in the `RegistryTable` based on participation in current epoch.

Recall that each validator record in table contains `attested` flag that signals that validator took part in attestation. For the purposes of this circuit, `attested` flag is used to check that accumulated effective balance for committee and the aggregated public key is consistent with rest of the table.

> Depending on the proof generation approach and infrastructure at hand logic in this circuit can be combined together with `validators` circuit. If generated on one machine it is advised to do so. However, if distributed proof generation is considered it may be fruitful to separate these circuits.

## Circuit layout
1. `q_enabled`: A selector to indicate whether or not the current row will be used in the circuit's layout.
2. `vreg_table`: The columns from [Validator registry table](#Validator-registry-table).
3. [`range_chip`](https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-base/src/gates/range.rs#L33): Lookup table for range constraints on numbers.
4. [`ec_chip`](https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-ecc/src/bn254/tests/ec_add.rs#L63): Custom gates and API for EC points addition.

## Circuit behaviour

