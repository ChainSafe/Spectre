# The Licensed Work is (c) 2023 ChainSafe
# Code: https://github.com/ChainSafe/Spectre
# SPDX-License-Identifier: LGPL-3.0-only

#!/bin/sh
cd $(git rev-parse --show-toplevel)
source .env
LOCAL_RPC_URL="http://localhost:8545"

forge script script/DeploySpectre.s.sol:DeploySpectre --private-key $ANVIL_PRIVATE_KEY --rpc-url $LOCAL_RPC_URL --broadcast -vvvv
