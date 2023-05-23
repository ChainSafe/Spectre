# Public inputs

The following list contains data used by a Beacon chain client to calculate a block and finalize the calculated block.

## BeaconBlock
- `block_root`: 256 bits
- [`BeaconBlockBody`](https://eth2book.info/capella/annotated-spec/#beaconblockbody) fields used in SSZ:
	- `randao_reveal`
	- `eth1_data`
	- `proposer_slashings`
	- `attester_slashings`
	- `attestations`
	- `deposits`
	- `voluntary_exits`
	- `sync_aggregate`
	- other non-relevant fields

### Circuits
- Block Hash verifier
    - All fields
- Attestation circuit
	- `attestations`
- Validators circuit
	- `proposer_slashings`
	- `attester_slashings`
	- `deposits`
	- `voluntary_exits`

## BeaconState
- `state_root`: 256 bits
- [`BeaconState`](https://eth2book.info/capella/annotated-spec/#beaconstate) fields used in SSZ:
	- `genesis_validators_root`
	- `slot`
	- `fork`
	- `latest_block_header`
	- `block_roots`
	- `state_roots`
	- `eth1_data`
	- `validators`
	- `balances`
	- `randao_mixes`
	- `previous_justified_checkpoint`
	- `current_justified_checkpoint`
	- `finalized_checkpoint`
	- other non-relevant fields

### Circuits
- Attestation circuit
	- `fork.current_version`
	- `genesis_validators_root`
- Validators circuit
	- `slot`: 64 bits
	- `validators`
	- `balances`
- zkCasper circuit
	- `slot`: 64 bits
	- `previous_justified_checkpoint`
	- `current_justified_checkpoint`
	- `finalized_checkpoint`
- Block Hash verifier
	- `latest_block_header.block_root`: 256 bits
- Verifier circuit
	- `latest_block_header.parent_root`: 256 bits
	- `block_roots[-1]`: 256 bits
	- `state_roots[-1]`: 256 bits


## Data to verify proof

The following values should be published along with the proof:
- `state_root`
