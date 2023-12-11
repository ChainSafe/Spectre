// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface CommitteeUpdateVerifier {
    function verify(uint256[77] calldata pubInputs, bytes calldata proof) external returns (bool);
}
