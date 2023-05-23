## Validators circuit

The validators circuit constraints changes to the `validator registry table` that applied at the start of each epoch.

The rate at which actors can enter/exit active validator set is limited (see ["churn"](https://eth2book.info/capella/annotated-spec/#min_per_epoch_churn_limit)). This number is calculated as `max(MIN_PER_EPOCH_CHURN_LIMIT, n / CHURN_LIMIT_QUOTIENT)`. This limit applies for both exits and activations separately. Today this translates to 9 validators per epoch. The [hysteresis](https://eth2book.info/capella/annotated-spec/#hysteresis-parameters) is another mechanism that ensures that the effective balance does not change often too.

### Circuit layout

The validators circuit consists of the following columns:
1. `q_enabled`: A selector to indicate whether or not the current row will be used in the circuit's layout.
2. `v_table`: The columns from [Validator registry table](#Validator-registry-table).
3. > additional columns will be specified closer/during the implementation

### Circuit constrains
- For every row where `v_table.activation_epoch == target_epoch`, validate that:
	- `v_table.balance >= 32 ETH`
	- `v_table.slashed != 1`;
- For every row where `v_table.exit_epoch == target_epoch`, validate that:
	- `v_table.reason == 'ejection' && v_table.balance < 16 ETH`
	- `v_table.reason == 'slashed' && v_table.slashed`

### State trie

For each validator, the validator circuit also must prepare keys and values to build the state trie. These keys and values are used in lookups to the MPT/SHA256 table in order to verify that a tree built with the key-values corresponding to the validators and their balances has the root value `stateRoot`.

> By doing lookups to the MPT table, we prove that when we start with an empty MPT, and do a chain of key-value insertions corresponding to each validator and their balance, we reach a Trie with root value `stateRoot`.

This is needed because we need to prove that exactly all changes to validator registry (activations, deactivation, balances) that happened at the start of `target_epoch` are applied. 

> Only checking Merkle multi-proof of changed values won't be enough because malicious prover could hide certain changes (slashes, balance decreases) and pass the check anyway.

However, the overhead of building a SHA2-based Merkle Trie with current (and growing) number of validators is too big. Fortunately, current architecture prover does not need to compute all the hashes that lead to the `stateRoot` --- most of them already present in SHA256 table and verified by the previous proof. This reduces hashing overhead significantly because as stated above the activations, exists, and balances changes are limited considerably.

### On shuffling constraints

Since validator registry table contains `s_index` and `committee` columns it's only natural to constraint these corresponding values based on [validator shuffling](https://eth2book.info/capella/part2/building_blocks/shuffling/#swap-or-not-specification) and [committees assignment](https://eth2book.info/capella/part2/building_blocks/committees/#committee-assignments) rules.

The issue, however, is that doing this explicitly and for reach validator row would be too expensive: with `SHUFFLE_ROUND_COUNT = 90` doing [`compute_shuffled_index`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#compute_shuffled_index) for each validator row would require computing `n*90*2` SHA256 hashes that unlike previously described [State trie](#State-trie) won't benefit from caching.

And while not ideal, we are argue that this expensive check can be skipped. This is justified by the fact that signed attestation, verified later in `zkCasper` circuit, ultimately attest for correctness of shuffling and committee assignment too.

> Since each attestation is signed by the set of validators who are assigned to committee after shuffling, we can assume that network participants individually performed this check before attesting.
