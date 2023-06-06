# Casper circuit

The Casper circuit checks that:
- the total accumulated balance from all the committees whose attestations are verified is more than 2/3 of the total stake.
- all the variables used by accessed by all circuits including this are part of state tree that has its root equal to the `state_root` public input.

For modularity, these constraints are enforced by two separate chips: `FinalityCalculationChip` and `StateVerifierChip` respectively. Current document specifies the former one and the latter is covered in [State Verifier Chip](/MM_04SbgR42f053XEqcs9w).

### Finality calculation

The `source_checkpoint` is *justified* when the `total_effective_balance` of all validators whose have attested to it is more than 2/3 of total stake - referred to as supermajority link to `target_checkpoint`. The same checkpoint is *finalized* when another supermajority link is created from the `target_checkpoint` to the next epoch's checkpoint.

> Other edge cases exist but for the proposes of current draft they are currently omitted.

## Chip layout
- `state_table`: The columns from [`StateTable`](/6B5be79aQni9TeRlxb0yIA#StateTable).
- `attest_table`: The columns from [`AttestationsTable`](/6B5be79aQni9TeRlxb0yIA#StateTable).
- `total_active_balance`: Accumulator variable for all the balances of all active validators.
- `total_effective_balance`: Accumulator variable for all the balances of all attested validators.

![](https://hackmd.io/_uploads/ByctSNDLh.png)

> Recall that padding in `attest_table` is used to align its rows with `state_table`. Notice how `tag == 'committee'` rows of `state_table` match corresponding rows `attest_table`. Similarly `field_tag == 'AggregationBit'` rows in `attest_table` match corresponding rows in `state_table`.

## Chip constraints

From the perspective of this circuit:
- legitimacy of validators is already enforced in [`validators`](/rgNEXSR4T--WGypp02n1rw) circuit;
- aggregated public keys and balances are calculated in [`aggregation`](/IkcCzb_vSTuUiiLFavLqRw) circuit;
- attestations are verified in [`attestations`](/6pIqAv1jQE6zz4MMTSM57Q) circuits.

What remains is to check the consistency of `state_table` and `attest_table`:
1. For each `state_table` row where `tag == 'validator' && field_tag == 'Balance'` there exits `attest_table` row where `field_tag == 'AggregationBit'` such that `state_table.is_attested == attest_table.value`.
2. For each `state_table` row where `tag == 'committee' && field_tag == 'PubKey.*'` there exits `attest_table` row with same `field_tag`, `index`, and `value` cells values.
- These checks are done using [permutation arguments](https://zcash.github.io/halo2/design/proving-system/permutation.html), which enforces that multiple cells contain the same value. See colored cells in the picture above.

> **Note:** In current draft corresponding cells from both tables are conveniently placed on the same rows of global table using padding. However, since permutation checks are enforced globally there might be a little performance benefit from that. At the same time such design choice prevents layouter to use space reserved for padding. Ie. Experiments must be conducted to determine if such a padding is worthwhile.

Now that all attestations are trusted to be collected from correctly assigned committees we can proceed to finality calculations:
1. For each row in `state_table` where `tag == 'validator' && field_tag == 'Balance' && is_active == 1` do `total_active_balance += state_table.value`.
2. For each row in `state_table` where `tag == 'committee' && field_tag == 'balance'` do `total_effective_balance += state_table.value`.
3. Check that `total_effective_balance >= 2/3 * total_active_balance`

And with that `target_epoch` is considered justified/finalized.

> TODO: constraint `current_justified_checkpoint` and `finalized_checkpoint`
