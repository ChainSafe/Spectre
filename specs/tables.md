# Tables

In BansheeZK we use the following dynamic and fixed tables for lookups to the Casper circuit.

## `StateTable`

Proved by the `validators` and `aggregation` circuits.

The validator table consists of 7 columns, described as follows:
- **ID**: when `tag == 'validator'` represents [`ValidatorIndex`](https://eth2book.info/capella/annotated-spec/#validatorindex), [`CommitteeIndex`](https://eth2book.info/capella/annotated-spec/#committeeindex) when `tag == 'committee'`, and empty otherwise.
- **Order**: shuffle index calculated using [`compute_shuffled_index()`](https://eth2book.info/capella/annotated-spec/#compute_shuffled_index).
- **Tag**: the type entity row represents (`self`, `fork`, `eth1_data`, `validator`, `committee`).
- **Attested**: whether validator have attested during this epoch.
- **FieldTag**: the type of field the row represents: `Balance`, `ActivationEpoch`, `ExitEpoch`, `Slashed`, `PubKey.*`.
- **Index**: the number of row associated with given tag: *\$chunkIdx* ranges (0..7) for BLS12-381


| *ID*          | *Order* | *Tag*       | *IsAttested* | *IsActive* | *FieldTag*        | *GIndex* | *Index*   | *Value*   |
| ------------- | ------- | ----------- | ------------ | ---------- | ----------------- | -------- | --------- | --------- |
| -             | -       | `fork`      | -            | -          | `CurrentVersion`  | $gindex  | 0         | $value    |
| -             | -       | `eth1_data` | -            | -          | `BlockHash`       | $gindex  | 0         | $value    |
| $validatorIdx | $index  | `validator` | bool         | bool       | `Balance`         | $gindex  | 0         | $value    |
| $validatorIdx | $index  | `validator` | bool         | bool       | `ActivationEpoch` | $gindex  | 0         | $value    |
| ...           | ...     | ...         | ...          | ...        | `ExitEpoch`       | ...      | 0         | ...       |
| ...           | ...     | ...         | ...          | ...        | `Slashed`         | ...      | 0         | ...       |
| ...           | ...     | ...         | ...          | ...        | `PubKeyRLC`       | ...      | 0         | ...       |
| $committeeIdx | -       | `committee` | -            | -          | `Balance`         | -        | 0         | $accValue |
| $committeeIdx | -       | `committee` | -            | -          | `PubKey.X`        | -        | $chunkIdx | $accValue |
| ...           | ...     | ...         | ...          | ...        | `PubKey.Y`        | ...      | $chunkIdx | ...       |
| -             | -       | `self`      | -            | -          | `BlockHeader`     | $gindex  | 0         | $value    |
| -             | -       | `self`      | -            | -          | `PrevJustifiedCP` | $gindex  | 0         | $value    |
| -             | -       | `self`      | -            | -          | `CurJustifiedCP`  | $gindex  | 0         | $value    |
| -             | -       | `self`      | -            | -          | `FinilizedCP`     | $gindex  | 0         | $value    |


## `AttestationsTable`

Provided by the `attestations` circuits.

The attestations table consists of 5 columns, described as follows:
- **Slot** and **Committee** are used to query individual attestations.
- **IsPadding** flag is used to align rows with `StateTable`.
- **FieldTag**: the type of field the row represents: `TargetEpoch`, `PubKey.*`, `AggregationBits`.
- **Index**: the number of row associated with given tag: *\$chunkIdx* ranges (0..7) for BLS12-381, *\$bitIdx* (0..2048)

| 0 *Slot* | 1 *Committee* | 2 *IsPadding* | 3 *FieldTag*     | 3 *Index* | 4 *Value* |
| -------- | ------------- | ------------- | ---------------- | --------- | --------- |
| $slot    | $c_idx        | 0             | `TargetEpoch`    | 0         | $value    |
| $slot    | $c_idx        | 0             | `PubKey.X`       | $chunkIdx | $value    |
| $slot    | $c_idx        | 0             | `PubKey.Y`       | $chunkIdx | $value    |
| $slot    | $c_idx        | 0             | `AggregationBit` | $bitIdx   | $value    |
| $slot    | $c_idx        | 1             |               | $padIdx   |  0         |


## `SHA256 Table`

SHA256 table can be implemented in two ways: full and compact. The trade-off is between increased memory/computation respectively.

### Full

Full version contains input in bytes as illustrated below with example.

| *InputByte*  | *BytesLeft* | *IsPadding* | *OutputLo/Hi* |
| ---------- | ----------- | ----------- | ------------- |
| $byteVal   | $bytesLeft  | bool        | $hash         |

```text
| input_byte | bytes_left | is_padding | output{Lo,Hi} |
|     e      |     6      |     0      |               |
|     x      |     5      |     0      |               |
|     a      |     4      |     0      |               |
|     m      |     3      |     0      |               |
|     p      |     2      |     0      |               |
|     l      |     1      |     0      |               |
|     e      |     0      |     0      | (0x.., 0x..)  |
```

> **Note:** Lookups based on [Plookup](https://eprint.iacr.org/2020/315) require polynomial divisions which are done with FFT. The BN254 curve allows for FFTs of degree up to 2^28 while proving time roughly doubles with each degree added. So in practice, increased degree due to full table layout is likely to offset the benefits of not doing RLC or be impossible at all.

### Compact (w/ RLC encoding)

Compact version uses random linear combination (RLC) to succinctly encode input so that each (input, output) pair takes a single row in table.

> **Note:** RLC is a one way encoding encoding (commitment).

| *InputRLC* | *InputLen* | *OutputRLC* |
| ---------- | ---------- | ----------- |
| $rlc       | $length    | $hash       |
