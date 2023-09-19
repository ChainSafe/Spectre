test:
    cargo test --workspace
fmt:
    cargo fmt --all
check:
    cargo check --all
lint: fmt
    cargo clippy --all-targets --all-features --workspace
setup-circuits:
    cargo run -r -- sync-step -o artifacts -k 22
    cargo run -r -- committee-update -o artifacts -k 18
gen-evm-contracts:
    cargo run -r -- sync-step -c ./lightclient-circuits/config/sync_step.json -o evm-verifier ./contracts/snark-verifiers/sync_step.yul
    # cargo run -r -- sync-step -c ./lightclient-circuits/config/committee_update.json -o evm-verifier ./contracts/snark-verifiers/committee_update.yul
