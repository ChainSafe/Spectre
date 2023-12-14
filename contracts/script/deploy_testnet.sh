# The Licensed Work is (c) 2023 ChainSafe
# Code: https://github.com/ChainSafe/Spectre
# SPDX-License-Identifier: LGPL-3.0-only

#!/bin/sh
cd $(git rev-parse --show-toplevel)
source .env
SEPOLIA_RPC_URL="https://rpc.sepolia.org/"

forge script script/DeploySpectreTestnet.s.sol:DeploySpectre --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $SEPOLIA_RPC_URL --broadcast -vvvv
