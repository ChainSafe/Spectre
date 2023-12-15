
// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

pragma solidity ^0.8.0;

import { SyncStepVerifier, SyncStepCompressedVerifier } from "../interfaces/SyncStepVerifier.sol";

contract SyncStepMockVerifier is SyncStepVerifier {
    function verify(uint256[2] calldata _input, bytes calldata _proof) external override returns (bool) {
        return true;
    }
}

contract SyncStepCompressedMockVerifier is SyncStepCompressedVerifier {
    function verify(uint256[14] calldata _input, bytes calldata _proof) external override returns (bool) {
        return true;
    }
}
