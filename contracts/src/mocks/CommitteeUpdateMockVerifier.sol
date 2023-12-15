
// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

pragma solidity ^0.8.0;

import { CommitteeUpdateVerifier } from "../interfaces/CommitteeUpdateVerifier.sol";

contract CommitteeUpdateMockVerifier is CommitteeUpdateVerifier {
    function verify(uint256[77] calldata _input, bytes calldata _proof) external override returns (bool) {
        return true;
    }
}
