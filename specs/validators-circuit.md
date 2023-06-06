# Validators circuit

The validators circuit constraints changes to the `StateTable` that applied at the start of each epoch.

The rate at which actors can enter/exit active validator set is limited (see ["churn"](https://eth2book.info/capella/annotated-spec/#min_per_epoch_churn_limit)). This number is calculated as `max(MIN_PER_EPOCH_CHURN_LIMIT, n / CHURN_LIMIT_QUOTIENT)`. This limit applies for both exits and activations separately. Today this translates to 9 validators per epoch. The [hysteresis](https://eth2book.info/capella/annotated-spec/#hysteresis-parameters) is another mechanism that ensures that the effective balance does not change often too.

## Circuit layout

The validators circuit consists of the following columns:
1. `q_enabled`: A selector to indicate whether or not the current row will be used in the circuit's layout.
2. `state_table`: The columns from [Validator state table](/6B5be79aQni9TeRlxb0yIA#StateTable).

## Circuit constrains
1. for every row where `tag == 'validator' && field_tag == 'ActivationEpoch' && value == target_epoch`, validate that:
	- exists a row with same *$validatorIdx* where `field_tag == 'Balance' value >= 32 ETH`
	- exists a row with same *$validatorIdx* where `field_tag == 'Slashed' && value != 1`
2. for every row where `tag == 'validator' && field_tag == 'Balance' && value < 16 ETH`, validate that:
	- exists a row with same *$validatorIdx* where `field_tag == 'ExitEpoch' value <= target_epoch`
3. for every row where `tag == 'validator' && field_tag == 'Slashed' && value == 1`, validate that:
	- exists a row with same *$validatorIdx* where `field_tag == 'ExitEpoch' value <= target_epoch`
4. for every row where `tag == 'validator' && is_active == 1`, validate that: 
	- exists a row with same *$validatorIdx* where `field_tag == 'ActivationEpoch' value <= target_epoch`
	- exists a row with same *$validatorIdx* where `field_tag == 'ExitEpoch' value < target_epoch`
5. for every row where `tag == 'validator' && field_tag == 'Balance'`, validate that `value <= MAX_BALANCE` where `MAX_BALANCE` is a constant to prevent overflowing on projective field.
6. for every row where `tag == 'committee'`, validate that `order == 1 && attested == 1`
7. `id` and `order` $\leq$ [`VALIDATOR_REGISTRY_LIMIT`](https://eth2book.info/capella/annotated-spec/#state-list-lengths)
8. for every row where `tag == 'validator' && field_tag == 'Slashed'`, validate that `value` is bool
9. `is_attested` and `is_active` are bool
10. if `is_attested == 1` then `is_active == 1` too.
- constraints (1), (2), (3), (4), (10) are done with custom gates, for example: $(A_3(x)-1)\cdot(A_5(x)-4)\cdot(A_7(x) - 1)\cdot(A_7(\omega^{-1}x) - I_1(x)) = 0$
	> - $A_3(x)-1$ checks that `tag == 'validator'` (enum val = 1)
	> - $A_5(x)-4$ checks that `field_tag == 'slashed'` (enum val = 4)
	> - $A_7(x) - 1$ checks that `value = 1` for current row (slashed)
	> - $A_7(\omega^{-1}x) - I_1(x)(x)$ checks that `value` for previous row (ExitEpoch) is equal to value of instance column $I_1$ (`target_epoch`)
	> 
	> the result is a simplified custom gate for constraint (3)
- constraints (6) is done with range lookup table that contains all possible values

![](https://hackmd.io/_uploads/ByLjo88Un.png)

There are some constraints on the shape of the table:
- number of unique rows with `tag == 'validator' && field_tag == 'Balance'` is $\leq$ [`VALIDATOR_REGISTRY_LIMIT`](https://eth2book.info/capella/annotated-spec/#state-list-lengths)
- `order` must start at 0 and  increase sequentially for each validator
- number of unique rows with `tag == 'validator' && field_tag == 'Balance'` that appear in between rows with `tag == 'committee'` is $\leq$ [`MAX_VALIDATORS_PER_COMMITTEE`](https://eth2book.info/capella/annotated-spec/#misc)

## State tree 

For each validator, the validator circuit also must prepare keys and values to build the state tree. These keys and values are used in lookups to the SHA256 table in order to verify that a tree built with the key-values corresponding to the validators and their balances has the root value `state_root`.

This is needed because we need to prove that exactly all changes to validator registry (activations, deactivation, balances) that happened at the start of `target_epoch` are applied. 

> Only checking Merkle multi-proof of changed values won't be enough because malicious prover could hide certain changes (slashes, balance decreases) and pass the check anyway.

However, the overhead of building a SHA2-based Merkle Tree with current (and growing) number of validators is too big. Fortunately, with current architecture, prover does not need to compute all the hashes that lead to the `state_root` --- most of them already present in SHA256 table and verified by the previous proof. This reduces hashing overhead significantly because as stated above the activations, exists, and balances changes are limited considerably.

## On shuffling constraints

Since validator state table contains `s_index` and `committee` columns it's only natural to constraint these corresponding values based on [validator shuffling](https://eth2book.info/capella/part2/building_blocks/shuffling/#swap-or-not-specification) and [committees assignment](https://eth2book.info/capella/part2/building_blocks/committees/#committee-assignments) rules.

The issue, however, is that doing this explicitly and for reach validator row would be too expensive: with `SHUFFLE_ROUND_COUNT = 90` doing [`compute_shuffled_index`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#compute_shuffled_index) for each validator row would require computing `n*90*2` SHA256 hashes that unlike previously described [State trie](#State-trie) won't benefit from caching.

And while not ideal, we are argue that this expensive check can be skipped. This is justified by the fact that signed attestation, verified later in Casper circuit, ultimately attest for correctness of shuffling and committee assignment too.

> Since each attestation is signed by the set of validators who are assigned to committee after shuffling, we can assume that network participants individually performed this check before attesting.

> TODO: consider attack were validators collude together with provers to create bogus attestations that are not consistent with shuffling.
