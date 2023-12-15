// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

pragma solidity ^0.8.0;

interface SyncStepVerifier {
    function verify(uint256[2] calldata input, bytes calldata proof) external returns (bool);
}

interface SyncStepCompressedVerifier {
    function verify(uint256[14] calldata pubInputs, bytes calldata proof) external returns (bool);
}
