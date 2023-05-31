# Casper circuit

The Casper circuit checks that:
- the total accumulated balance from all the committees whose attestations are verified is more than 2/3 of the total stake.
- all the variables used by accessed by all circuits including this are part of state tree that has its root equal to the `state_root` public input.

For modularity, these constraints are enforced by two separate chips: `FinalityCalculationChip` and `StateVerifierChip` respectively. Current document specifies the former one and the latter is covered in [State Verifier Chip](/MM_04SbgR42f053XEqcs9w).

### Finality calculation

The `source_checkpoint` is *justified* when the `total_effective_balance` of all validators whose have attested to it is more than 2/3 of total stake - referred to as supermajority link to `target_checkpoint`. The same checkpoint is *finalized* when a supermajority link is created from the `target_checkpoint` to the next epoch's checkpoint.

> Other edge cases exist but for the proposes of current draft, chance of their occurrence is assumed to be negligent.


## Chip layout
- `registry_table`: The columns from [Validator registry table](/6B5be79aQni9TeRlxb0yIA#RegistryTable).
- `attest_table`: The columns from [Attestations table](/6B5be79aQni9TeRlxb0yIA#RegistryTable).
- `total_effective_balance`: Accumulator variable for all the balances of all attested validators.

## Chip constraints