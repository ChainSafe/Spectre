## Attestations circuit

The attestations circuit constraints attestations to finalize `target_epoch`. This does not include verifying BLS signatures. Instead the purpose of this circuit is to prepare most of the cryptographic materials so simplify BLS verification in `zkCasper` circuit.

### Circuit layout

The attestations circuit consists of the following columns:
1. `q_enabled`: A selector to indicate whether or not the current row will be used in the circuit's layout.
2. `a_table`: The columns from [Attestations table](#Attestations-table).
3. > additional columns will be specified closer/during the implementation

### Circuit behaviour
- For each row, do:
	1. Given `AttestationData` defined as `(slot, committee, fork_root, source_epoch, target_epoch)` the circuit computes [`compute_signing_root`](https://eth2book.info/capella/annotated-spec/#compute_signing_root) with constant `domain`.
	2. Verify that `hash_to_curve(HASH_DOMAIN, signing_root) == hash_point`.
