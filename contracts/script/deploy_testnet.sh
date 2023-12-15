#!/bin/sh
cd $(git rev-parse --show-toplevel)
source .env
SEPOLIA_RPC_URL="https://rpc.sepolia.org/"

forge script script/DeploySpectreTestnet.s.sol:DeploySpectre --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $SEPOLIA_RPC_URL --broadcast -vvvv
