// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface CommitteeUpdateVerifier {
    function verify(uint256[65] calldata input, bytes calldata proof) external returns (bool);
}
