# Tables

In zkCasper we use the following dynamic and fixed tables for lookups to the Casper circuit.

## `vreg_table`: validator registry table


| Column             | Type       | Description                                        |
| ------------------ | ---------- | -------------------------------------------------- |
| `v_index`          | `Advice`   | A unique validator index number                    |
| `pubkey`           | `G1Affine` | A public key as BLS12-381 $\mathbb{G}_1$ point     |
| `activation_epoch` | `Advice`   | When criteria for activation were met              |
| `exit_epoch`       | `Advice`   | When criteria for deactivation were met            |
| `balance`          | `Advice`   | Effective balance at stake                         |
| `s_index`          | `Advice`   | Shuffling index based on current epoch random seed |
| committee          | `Advice`   | Assigned committee                                 |

Proved by the `validators` circuits.

## `Attestations Table`

| Column         | Type       | Description                           |
| -------------- | ---------- | ------------------------------------- |
| `slot`         | `Advice`   | Slot number                           |
| `committee`    | `Advice`   | Committee index                       |
| `source_epoch` | `Advice`   | Source checkpoint epoch number        |
| `target_epoch` | `Advice`   | Target checkpoint epoch number        |
| `target_root`  | `Advice`   | Target checkpoint state root          |
| `fork_root`    | `Advice`   | LMD GHOST vote                        |
| `signature`    | `G2Affine` | BLS Signature                         |
| `hash_point`   | `G2Affine` | Message hash as `hash_to_curve(data)` |
| `v_indexes`    | `?`        | Attesting validator indices           |

Proved by the `attestations` circuits.


## `SHA256 Table`

| Column         | Type     | Description                                      |
| -------------- | -------- | ------------------------------------------------ |
| `is_final`     | `Advice` | `1` if contains output, otherwise `0`            |
| `input`        | `Advice` | An input word                                    |
| `input_len`    | `Advice` | The input length, in 32-byte words               |
| `output_hi/lo` | `Advice` | The output hash, encoded into high and low parts |

```text
| is_final | input | input_len | output{Lo,Hi} |
|    0     |  0x01 |     3     |               | 
|    0     |  0x02 |     3     |               |
|    1     |  0x03 |     3     | (0x.., 0x..)  |
```
