set dotenv-load # automatically loads .env file in the current directory
set positional-arguments

test:
    cargo test --workspace

fmt:
    cargo fmt --all

check:
    cargo check --all

lint: fmt
    cargo clippy --all-targets --all-features --workspace

setup-step network *k='22':
    cargo run -r -- circuit sync-step -p ./build/sync_step_$1.pkey -k $2 setup

setup-step-compressed network *k='23':
    cargo run -r -- circuit sync-step-compressed -k 20 -p ./build/sync_step_$1.pkey  \
         -K $2 -P ./build/sync_step_verifier_$1.pkey -L 19 setup

setup-committee-update network *k='24':
    cargo run -r -- circuit committee-update -k 20 -p ./build/committee_update_$1.pkey  \
         -K $2 -P ./build/committee_update_verifier_$1.pkey setup

gen-verifier-step network:
    cargo run -r -- circuit sync-step -p ./build/sync_step_$1.pkey gen-verifier -o ./contracts/snark-verifiers/sync_step.sol

gen-verifier-step-compressed network:
    cargo run -r -- circuit sync-step-compressed -p ./build/sync_step_$1.pkey -P ./build/sync_step_verifier_$1.pkey \
        gen-verifier -o ./contracts/snark-verifiers/sync_step_verifier.sol

gen-verifier-committee-update network:
    cargo run -r -- circuit committee-update -p ./build/committee_update_$1.pkey -P ./build/committee_update_verifier_$1.pkey \
        gen-verifier -o ./contracts/snark-verifiers/committee_update_verifier.sol

build-contracts:
    cd contracts && forge build

deploy-contracts-local:
    cd contracts && forge script ./script/DeploySpectre.s.sol:DeploySpectre --fork-url $LOCAL_RPC_URL --broadcast

deploy-contracts network: # network one of [MAINNET, GOERLI, SEPOLIA]
    #! /usr/bin/env bash
    RPC_URL="$1_RPC_URL"
    cd contracts && forge script ./script/DeploySpectre.s.sol:DeploySpectre --rpc-url ${!RPC_URL} --broadcast --verify -vvvv

# downloads spec tests and copies them to the right locations.
download-spec-tests: clean-spec-tests
    #!/usr/bin/env bash
    if [[ ! -d 'consensus-spec-tests' ]]; then
        echo "Downloading test data."
        bash test-utils/scripts/download_consensus_specs.sh
    fi

# deletes all the downloaded spec tests
clean-spec-tests:
    echo "Cleaning up downloaded tests"
    rm -rf *.profraw
    rm -rf *.tar.gz.1
    rm -rf consensus-spec-tests
