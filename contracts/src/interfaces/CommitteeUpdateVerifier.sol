// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

pragma solidity ^0.8.0;

interface CommitteeUpdateVerifier {
    function verify(uint256[77] calldata pubInputs, bytes calldata proof) external returns (bool);
}
