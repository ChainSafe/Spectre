# Spectre

Spectre is a Zero-Knowledge (ZK) coprocessor designed to offload intensive computations from the resource-limited execution layer of target chains. Iit offers a trust-minimized method for verifying block headers, adhering to the consensus rules of the originating chain.

The type of outsourced computation is specific to the arithmetic circuits. For Spectre, its primary function is to verify the Ethereum LightClient protocol introduced in the Altair hardfork.

## Requirements
- Rust `1.73.0-nightly`
- Packages `build-essential` `clang` `pkg-config` `libssl-dev`
- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- [Just](https://just.systems/man/en/)

## Technical details

Spectre prover utilizes the Halo2 proving stack ([`privacy-scaling-explorations/halo2`](https://github.com/privacy-scaling-explorations/halo2) fork).

Circuits are implemented with the [`halo2-lib`](https://github.com/axiom-crypto/halo2-lib) circuit development framework. This library contains a number of non-trivial optimization tricks, while its readable SDK prevents most of the soundness bugs and improves auditability. Our team has contributed a number of features back to the halo2-lib repository, containing some foundational cryptographic primitives powering Ethereum consensus.

Verifier contracts for consensus proofs are auto-generated via the [`privacy-scaling-explorations/snark-verifier`](https://github.com/privacy-scaling-explorations/snark-verifier). We aslo support [`privacy-scaling-explorations/halo2-solidity-verifier`](https://github.com/privacy-scaling-explorations/halo2-solidity-verifier) behind `experimental` flag. Supplemental contract logic has been introduced exclusively to manage intermediary states during proof verifications.

## Usage

### Setup circuits

#### Step circuit

```shell
cargo run -r -- circuit sync-step-compressed -k 20 -p ./build/sync_step_20.pkey -K 23 -P ./build/sync_step_verifier_23.pkey -L 19 setup
```
Flags `-k` and `-K` are circuit degrees for first and aggregation (compression) stage respectively. `-L` is the number lookup bits used in aggregation stage.

#### Committee update circuit

```shell
cargo run -r -- circuit committee-update -k 20 -p ./build/committee_update_20.pkey -K 24 -P ./build/committee_update_verifier_20.pkey setup
```

Alternatively, you can use `just` recipes as shown below.

```shell
just setup-step-compressed testnet
just setup-committee-update testnet
```

### Generates verifier contracts

#### Step proof

```shell
cargo run -r -- circuit sync-step-compressed -p ./build/sync_step_20.pkey -P ./build/sync_step_verifier_23.pkey gen-verifier -o ./contracts/snark-verifiers/sync_step_verifier.sol
```

#### Committee update proof

```shell
cargo run -r -- circuit committee-update -p ./build/committee_update_20.pkey -P ./build/committee_update_verifier_24.pkey gen-verifier -o ./contracts/snark-verifiers/committee_update_verifier.sol
```

Or use `just` recipes as shown below.

```shell
just gen-verifier-step-compressed testnet
just gen-verifier-committee-update testnet
```

### Deploying contracts

Just scripts are provided to deploy the contracts either to a local testnet, or public networks.

For either make a copy of the `.env.example` file called `.env`. Set the `INITIAL_SYNC_PERIOD`, `INITIAL_COMMITTEE_POSEIDON` and `SLOTS_PER_PERIOD` variables according to the network you want Spectre to act as a light-client for and the starting point.

To get the `INITIAL_COMMITTEE_POSEIDON` value, run:

```shell
cargo run -r -- utils committee-poseidon --beacon-api https://lodestar-sepolia.chainsafe.io
```

`--beacon-api` is a URL of the RPC of the targeted Beacon chain.

#### Deploying locally

1. Start a local anvil instance with:

```shell
anvil
```

2. Copy one of the private key strings printed into the `DEPLOYER_PRIVATE_KEY` in the `.env` file then run 

```shell
just deploy-contracts-local
```

#### Deploying to a public network

1. Obtain the required gas token and obtain the private key for the deployer account. Set the `DEPLOYER_PRIVATE_KEY` in the `.env` file.
2. Obtain a public RPC URL for the network and set the variable `<NETWORK>_RPC_URL` in the `.env` file (If using Infura this will require an API key)
3. Run

```shell
just deploy-contracts <NETWORK>
```

where `<NETWORK>` is one of `["GOERLI", "SEPOLIA", "MAINNET"]`.

### Running the prover

Prover is accessible via JSON RPC interface. To start it, run:

```shell
cargo run -r -- rpc --port 3000
```
