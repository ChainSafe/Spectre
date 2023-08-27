test:
    cargo test --workspace
fmt:
    cargo fmt --all
check:
    cargo check --all
lint: fmt
    cargo clippy --all-targets --all-features --workspace
setup-circuits:
    cargo run -r -- sync-step -o artifacts
    cargo run -r -- committee-update -o artifacts
gen-evm-contracts:
    cargo run -r -- sync-step -o evm-verifier ./contracts/snark-verifiers/sync_step.yul
    cargo run -r -- committee-update -o evm-verifier ./contracts/snark-verifiers/committee_update.yul
