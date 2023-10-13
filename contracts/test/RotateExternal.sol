// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import { RotateLib } from "../src/RotateLib.sol";

/**
* @title SyncStepLibTest
* @dev This contract exists solely for the purpose of exposing the RotateLib functions
*      so they can be used in the Rust test suite. It should not be part of a production deployment
*/
contract RotateExternal {
    using RotateLib for RotateLib.RotateInput;

    function toInputCommitment(RotateLib.RotateInput calldata args, bytes32 finalizedHeaderRoot) public pure returns (uint256[] memory) {
        uint256[65] memory commitment = args.toInputCommitment(finalizedHeaderRoot);
        // copy all elements into a dynamic array. We need to do this because ethers-rs has a bug that can't support uint256[65] return types
        uint256[] memory result = new uint256[](65);
        for (uint256 i = 0; i < commitment.length; i++) {
            result[i] = commitment[i];
        }
        return result;
    }
}
