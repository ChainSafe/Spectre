# State Circuit

The state circuit checks that the modification of the state tree happened correctly and consistent with the `state_root` public input.

In common terms, this circuits verifies a Merkle multi-proof for all the variables of the state that were used elsewhere in the protocol. It depends on the `SHA256Table` for providing hashes along the path to `state_root`, which in turn heavily relies on caching to reduce hashing overhead.

[By design](https://eth2book.info/capella/part2/incentives/balances/#engineering-aspects-of-effective-balance) the list of validator records in the state does not change frequently. As a result we can cache the hash tree root of the list and do not need to recalculate it every time we recalculate the entire beacon state root.

Since the protocol is only concerned with a small subset of data of full beacon state, we can replace everything else with their corresponding hash tree roots. The Merkleization procedure for SSZ types ensures that such substitution wont affect the final result. Another thing to note, Merkleization operates on lists of "chunks" which are 32-byte blobs of data.

> Full description of Merkleization procedure can be found in official spec [document](https://github.com/ethereum/consensus-specs/blob/v1.3.0/ssz/simple-serialize.md#merkleization) and [Ben Edgington's overview](https://eth2book.info/capella/part2/building_blocks/merkleization/).

The following list contains all the fields in [`BeaconState`](https://eth2book.info/capella/annotated-spec/#beaconstate) that must be constraint:
- `slot`
- `latest_block_header`
- `block_roots[-1]`
- `state_roots[-1]`
- `eth1_data.block_hash`
- `validators`
	- `pubkey`
	- `effective_balance`
	- `slashed`
	- `activation_epoch`
	- `exit_epoch`
- `balances`
- `randao_mixes`
- `slashings`
- `previous_justified_checkpoint`
- `current_justified_checkpoint`
- `finalized_checkpoint`

## Circuit layout

## Circuit behaviour
