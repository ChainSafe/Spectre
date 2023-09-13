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
    # cargo run -r -- committee-update -o evm-verifier ./contracts/snark-verifiers/committee_update.yul

# downloads spec tests and copies them to the right locations.
download-spec-tests: clean-spec-tests
    #!/usr/bin/env bash
    if [[ ! -d 'consensus-spec-tests' ]]; then
        echo "Downloading test data."
        scripts/download_consensus_specs.sh
    fi

# deletes all the downloaded spec tests
clean-spec-tests:
    echo "Cleaning up downloaded tests"
    rm -rf *.profraw
    rm -rf *.tar.gz.1
    rm -rf consensus-spec-tests