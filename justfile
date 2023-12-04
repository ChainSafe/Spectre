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

setup-step network:
    cargo run -r -- circuit sync-step -p ./build/sync_step_$1.pkey -k 22 setup

setup-committee-update network:
    cargo run -r -- circuit committee-update  -p ./build/committee_update_$1.pkey -k 18 \
         --verifier-k 25 --verifier-pk-path ./build/committee_update_verifier_$1.pkey setup

gen-step-evm-verifier network:
   cargo run -r -- circuit sync-step --pk-path ./build/sync_step_$1.pkey gen-verifier --solidity-out ./contracts/snark-verifiers/sync_step.yul 

gen-rotation-evm-verifier network:
    cargo run -r -- circuit committee-update --pk-path ./build/committee_update_$1.pkey --verifier-pk-path ./build/committee_update_verifier_$1.pkey  gen-verifier  --solidity-out ./contracts/snark-verifiers/committee_update_aggregated.yul 

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
        scripts/download_consensus_specs.sh
    fi

# deletes all the downloaded spec tests
clean-spec-tests:
    echo "Cleaning up downloaded tests"
    rm -rf *.profraw
    rm -rf *.tar.gz.1
    rm -rf consensus-spec-tests
