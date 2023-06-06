# State Verifier Chip

The verifier chip checks that the modification of the state tree happened correctly and consistent with the `state_root` public input.

In common terms, this chip verifies a Merkle multi-proof for all the variables of the state that were used elsewhere in the protocol. It depends on the `SHA256Table` for providing hashes along the path to `state_root`, which in turn heavily relies on caching to reduce hashing overhead.

By [design](https://eth2book.info/capella/part2/incentives/balances/#engineering-aspects-of-effective-balance), the list of validator records in the state does not change frequently. As a result we can leverage this cache and do not recalculate large areas of the tree every time we compute state root or perform multi-proof verification.

Since the protocol is only concerned with a small subset of data of full beacon state, we can replace everything else with their corresponding hash tree roots. The Merkleization in SSZ guarantees that such substitution wont affect the final result. Another thing to note, Merkleization operates on lists of "chunks" which are 32-byte blobs of data. The process that governs how particular data types are split in chunks is called ["packing and chunking"](https://eth2book.info/capella/part2/building_blocks/merkleization/#packing-and-chunking).

> Full description of Merkleization procedure can be found in official spec [document](https://github.com/ethereum/consensus-specs/blob/v1.3.0/ssz/simple-serialize.md#merkleization) and [Ben Edgington's overview](https://eth2book.info/capella/part2/building_blocks/merkleization/).

The following list contains all the fields in [`BeaconState`](https://eth2book.info/capella/annotated-spec/#beaconstate) that must be constrained:
- `slot: uint64` - 1 chunk
- `fork.current_version: Bytes4` - 1 chunk
- `latest_block_header.body_root: Bytes32` -  1 chunk
- `block_roots[-1..0]: [Bytes32]` - 1 chunk each
- `state_roots[-1..0]: [Bytes32]` - 1 chunk each
- `eth1_data.block_hash: Bytes32` - 1 chunk 
- `validators`
	- `pubkey: Bytes48` - 2 chunks
	- `effective_balance: uint64` - 1 chunk
	- `slashed: bool` - 1 chunk
	- `activation_epoch: uint64` - 1 chunk
	- `exit_epoch: uint64` - 1 chunk
- `randao_mixes[-1..0]: [Bytes32]` - 1 chunk each
- `previous_justified_checkpoint: {uint64, Bytes32}` - 2 chunks total
- `current_justified_checkpoint: {uint64, Bytes32}` - 2 chunks total
- `finalized_checkpoint: {uint64, Bytes32}` - 2 chunks total

Each chunk is associated with a "generalized index" calculated as `2**depth + index`. These indexes mark elements, the membership of which is proved by a Merkle multiproof. Generalized indeces can be deterministically calculated for any variable in the state tree.

## Circuit layout

The state verifier chip consists of the following columns:

1. `leaf`: holds the leaf values that you want to prove membership for.
2. `index`: holds the generalized index values for leaves.
3. `sibling`: holds the sibling values that are used to calculate the nodes in the Node column.
4. `node`: holds the nodes of the partial Merkle tree being constructed.
5. `hash`: holds the hash values that are calculated by hashing together the values in the Node and Sibling columns.
6. `flag`: selector that used to flag rows that correspond to leaf values, as opposed to internal nodes of the Merkle tree.
7. `root`: holds the root of the Merkle tree, which is a public input to the circuit.
8. `state_root`: an instance column that holds the public value of the root of the state.

| *Leaf* | *Index* | *Sibling* | *Node* | *Hash* | *Flag* | *Root* | *StateRoot* |
| ------ | ------- | --------- | ------ | ------ | ------ | ------ | ----------- |
| L1     | G1      | S1        | L1     | H1     | 1      |        | SR          |
| L2     | G2      | S2        | L2     | H2     | 1      |        | SR          |
|        |         | S3        | H1     | H3     | 0      |        | SR          |
|        |         | S4        | H2     | H4     | 0      |        | SR          |
|        |         | S5        | H3     | H5     | 0      |        | SR          |
|        |         |           | H4     |        | 0      | H4     | SR          |


## Circuit behaviour

The `MerkleMultiProof` structure is used to initialize the circuit. Its code is as follows:

```rust
struct MerkleMultiProof {
   leaves: Vec<Bytes32>,
   indices: Vec<GeneralizedIndex>,
   path_nodes: Vec<Bytes32>,
}
```

The `leaves` and `indeces` fields values are uploaded in the rows where the `flag` column is 1 to the `leaf` and `index` columns respectively. For those same rows, the `node` column is also set to the corresponding `leaf` value. The `sibling` column is filled with the corresponding path hashes from the `path_nodes` field.

Once all the leaf nodes have been processed, we start processing the internal nodes of the Merkle tree. For these rows, the `flag` column is set to 0. The `node` column is set to the `hash` value from the previous row, and the `sibling` column is filled with the corresponding path hashes from the `path_hashes` field.

The `root` column is filled with the final hash value, which should match the root of the Merkle tree, and the `state_root` column is set to the given public input value.

### Circuit constraints

The following constraints are enforced in the circuit:

1. For each row where `flag == 1` (indicating a leaf node), enforce that:
	- `node == leaf`
	- `hash == lookup(SHA256Table, node + sibling)`
	- `leaf == 0`
	- `root == 0`
	- `lookup(StateTable, g_index=index, value).is_ok()`
1. For each row with `flag == 0` (indicating an internal node), enforce that:
	- `node == hash_prev`
	- `hash == lookup(SHA256Table, node + sibling)`
	- `leaf == 0`
2. For the last row in the circuit, enforce that `root == state_root`.
- These constraints can be represented as custom gates as follows:
	1. For leaf nodes: `(flag - 1) * (node - leaf) == 0` => $(A_{5}(x) - 1) \cdot (A_{2}(x) - A_{1}(x)) = 0$
	2. For internal nodes: `flag * (leaf - node_prev) == 0` => $A_{5}(x) \cdot (A_{2}(x) - A_{4}(\omega^{-1}x)) = 0$

> In custom gates expressions, $A_{n}(x)$ represents the nth column of the circuit, and $\omega$ is a root of unity, used to access different rows in the table, using so called rotation technique.

And an additional constraint on the shape of the table:
- The `flag` column cells must be 1 at the start of the table but after the first 0, there can only be zeros down to the end of the table. 

Custom gates expressions for implementing this constraint is as follows:
- To ensure `flag` is boolean: `flag * (1 - flag) == 0` => $A_{5}(x) * ( 1 - A_{5}(x)) = 0$
- To ensure that if the current row `flag` is 0, then the next row has to be 0: `(1 - flag)*flag_next` => $(1 - A_{5}(x)) A_{5}(\omega x) = 0$

> **Note:** This last constraint can be seen as state transition system which starts with the 'active' state (represented by 1 in the `flag` column), and transitions to the 'padding' state (represented by 0). This transition is irreversible, meaning that once a row has `flag == 0`, all subsequent rows must also have `flag == 0`. This ensures a one-way flow from the active computation to the padding phase of the circuit, enforcing the correct sequence and padding of the table rows. For a detailed explanation of this technique, refer to [this talk](https://youtu.be/wSfkpJDq8AI?t=1197).