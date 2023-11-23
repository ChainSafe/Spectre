# Spectre
Spectre is a ZK-based block header oracle protocol based on Altair fork light-client sync protocol.

## Deploying contracts

Just scripts are provided to deploy the contracts either to a local testnet, or public networks.

For either make a copy of the `.env.example` file called `.env`. Set the `INITIAL_SYNC_PERIOD`, `INITIAL_COMMITTEE_POSEIDON` and `SLOTS_PER_PERIOD` variables according to the network you want Spectre to act as a light-client for and the starting point.

### Deploying locally

1. Start a local anvil instance with:

```shell
anvil
```

2. Copy one of the private key strings printed into the `DEPLOYER_PRIVATE_KEY` in the `.env` file then run 

```shell
just deploy-contracts-local
```

### Deploying to a public network

1. Obtain the required gas token and obtain the private key for the deployer account. Set the `DEPLOYER_PRIVATE_KEY` in the `.env` file.
2. Obtain a public RPC URL for the network and set the variable `<NETWORK>_RPC_URL` in the `.env` file (If using Infura this will require an API key)
3. Run

```shell
just deploy-contracts <NETWORK>
```

where `<NETWORK>` is one of `["GOERLI", "SEPOLIA", "MAINNET"]`.
