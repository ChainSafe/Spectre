
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { SyncStepVerifier } from "../interfaces/SyncStepVerifier.sol";

contract SyncStepMockVerifier is SyncStepVerifier {
    function verify(uint256[2] calldata _input, bytes calldata _proof) external override returns (bool) {
        return true;
    }
}
