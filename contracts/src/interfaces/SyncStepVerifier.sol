// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface SyncStepVerifier {
    function verify(uint256[2] calldata input, bytes calldata proof) external returns (bool);
}
