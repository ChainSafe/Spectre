# Attestations circuit

The attestations circuit verifies attestations that finalize/justify `target_epoch`.

## Circuit layout

The attestations circuit consists of the following columns:
1. `q_enabled`: A selector to indicate whether or not the current row will be used in the circuit's layout.
2. `fork_version`: `BeaconState.fork.current_version`
3. `genesis_validators_root`: `BeaconState.genesis_validators_root` (can be constant)
4. `attest_table`: The columns from [AttestationsTable](/6B5be79aQni9TeRlxb0yIA#AttestationsTable).
5. `attestations`: List of attestations.
6. `aggregated_pubkeys`: List of aggregated public keys for attestations.
7. [`hash_to_curve`](https://github.com/ChainSafe/recursive-zk-bridge/blob/main/halo2/src/hash2curve.rs#L69) chip.
8. [`ecc_chip`](https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-ecc/src/ecc/mod.rs#L555): Custom gates and API for EC points addition.

## Circuit behaviour

For each [`Attestation`](https://eth2book.info/capella/annotated-spec/#indexedattestation) defined as `(aggregation_bits, data, signature)`, the circuit computes:
1. `domain: bytes = DOMAIN_BEACON_ATTESTER + lookup(SHA256Table, fork_version + genesis_validators_root)`
2. [`message: bytes = compute_signing_root(data, DOMAIN)`](https://eth2book.info/capella/annotated-spec/#compute_signing_root).
3. `hash_point: G2Affine = hash_to_g2(HASH_DOMAIN, signing_root)` where `HASH_DOMAIN = b'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_'` ([source](https://github.com/ethereum/annotated-spec/blob/master/phase0/beacon-chain.md#bls-signatures)).
4. `aggregated_pubkey: G1Affine = aggregated_pubkeys[data.index]`.

And validates that:
1. `signature.(x/y).(c0/c1) mod q*2`
2. `signature` is a valid point on $\mathbb{G}_2$
3. `len(aggregation_bits) <= 2048`

As a final constraint, the circuit performs BLS signatures verification in the following steps:
1. Initialize the signature point:
	- The circuit picks the 7 rows where `slot == data.slot && committee == data.index && field_tag = 'PubKey.*.*'` for each tag $\in$ `['PubKey.X.C0', 'PubKey.X.C1', 'PubKey.Y.C0', 'PubKey.Y.C1']`,
	- Initializes `signature` of type [`EcPoint<Fp2, G2Affine>`](https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-ecc/src/ecc/mod.rs#L24) using selected values.
2. Assign $\mathbb{G}_1$ generator to constant `g1_gen` of type [`EcPoint<Fp, G1Affine>`](https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-ecc/src/ecc/mod.rs#L24).
3. Enforce `pairing(g1_gen, signature) == pairing(aggregated_pubkey, hash_point)` constraint.

> Notice how `aggregated_pubkeys` input here is trusted. While we can enforce these keys to by constructed from the public keys of legitimate validators here, that would require supplying the entire `state_table` table, which increases size of the circuit. Instead, the simple consistancy constraint is placed in Casper circuit which needs both lookup tables anyway.

From this inputs and computed value the circuit builds the `AttestationsTable` where:
- `TargetEpoch`: `data.target_checkpoint.epoch`
- `PubKey.*`: `aggregated_pubkey.*`
- `AggregationBit`: `aggregation_bits`

> Each row with `field_tag = 'AggregationBit'` must proceed with 4 rows with `is_padding = 1`. Such padding ensures that relevant rows in `StateTable` and `AttestationTable` are properly aligned and makes for more lookups in Casper circuit.

| 0 *Slot* | 1 *Committee* | 2 *IsPadding* | 3 *FieldTag*      | 3 *Index* | 4 *Value* |
| -------- | ------------- | --- |----------------- | --------- | --------- |
| $slot    | $c_idx        | 0 |`TargetEpoch`     | 0         | $value: raw    |
| $slot    | $c_idx        |  0 |`PubKey.X`  | $chunkIdx | $value: `hash_point.y.c0`    |
| $slot    | $c_idx        |  0 |`PubKey.Y`  | $chunkIdx | $value: `hash_point.y.c1`    |
| $slot    | $c_idx        |  0 |`AggregationBit` | $bitIdx   | $value: raw    |
| $slot    | $c_idx        |  1 | | $padIdx   |    |

There are some constraints on the shape of the table:
- `Slot` must start at 0 and increase sequentially for each attestation.
- For every attestation, each tag `TargetEpoch` must appear exactly once.
- When `field_tag == PubKey.*`, value of `index` must be exactly between 0 and 7.
- There must be exactly 5 rows with `is_padding == 1` after row with `field_tag = 'AggregationBit'`.

### Batched pairing

The *batched pairing* technique offers a more efficient alternative to sequential pairing operations in BLS signature verification due to the shared computations in the Miller loop, reducing total computational cost. The final result is the product of individual pairings.

However, to correctly use it for BLS signature verification, the `g1_gen` in the first pairing must be negated so that the product of the pairings will be reduced to target group's identity element (denoted as 1). This property is used for signature verification: `multi_pairing([(g1_neg, sigma), (pk, h(m))] == 1`.

### Multi-message aggregation

If not for the `data.index` then all aggregate attestations per slot could have been further aggregated into a single aggregate attestation, combining the votes from all the validators voting at that slot. This would've saved up to 14.4 KB per block and greatly reduced the overhead of verifying it in circuit, but at the expanse of making [committee aggregation process](https://eth2book.info/capella/part2/building_blocks/aggregator/) more complex, which apparently is unfeasible currently.

So, with how things are right now the verification takes $2*N$ pairings:

$$
\sum^{N}_{i=0} e(G_1,\sigma_i) - e(PK_i,H_i) = 0
$$

However, BLS still allows to aggregate signatures for different messages. It's not as efficient as single-message aggregation goes, which takes two pairings, and requires to know who signed which messages during verification.

To aggregate many signatures, we simply sum them $\sigma=\sigma_1​+\sigma_2​+\sigma_3​ +\;...$ Then to verify, we compute all the hashes for the messages $H$ and check:
$$
e(G_1,\sigma) = \sum^{N}_{i=0} e(PK_i,H_i​)
$$

This takes $N + 1$ pairings and $N$ $\mathbb{G}_2$ additions, which in theory should by slightly more efficient.