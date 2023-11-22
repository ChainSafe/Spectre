test:
    cargo test --workspace

fmt:
    cargo fmt --all

check:
    cargo check --all

lint: fmt
    cargo clippy --all-targets --all-features --workspace

setup-step-circuit:
    cargo run -r -- circuit sync-step -c ./lightclient-circuits/config/sync_step.json -o artifacts -k 22

setup-rotation-circuit:
    cargo run -r -- circuit committee-update -c ./lightclient-circuits/config/committee_update.json -o artifacts -k 18
    # TODO: generate committee-update snark
    cargo run -r -- circuit aggregation -c ./lightclient-circuits/config/aggregation.json --app-pk-path \
     ./build/committee_update.pkey --app-config-path ./lightclient-circuits/config/committee_update.json -i ./rotation -o artifacts -k 22

gen-step-evm-verifier:
    cargo run -r -- circuit sync-step -c ./lightclient-circuits/config/sync_step.json -o evm-verifier ./contracts/snark-verifiers/sync_step.yul

gen-rotation-evm-verifier:
    cargo run -r -- circuit aggregation -c ./lightclient-circuits/config/aggregation.json --app-pk-path ./build/committee_update.pkey --app-config-path ./lightclient-circuits/config/committee_update.json -i ./rotation -o evm-verifier ./contracts/snark-verifiers/committee_update_aggregated.yul 

build-contracts:
    cd contracts && forge build

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
