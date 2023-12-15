// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

pragma solidity 0.8.19;

import { RotateLib } from "../src/RotateLib.sol";

/**
* @title RotateExternal
* @dev This contract exists solely for the purpose of exposing the RotateLib functions
*      so they can be used in the Rust test suite. It should not be part of a production deployment
*/
contract RotateExternal {
    using RotateLib for RotateLib.RotateInput;

    function toPublicInputs(RotateLib.RotateInput calldata args, bytes32 finalizedHeaderRoot) public pure returns (uint256[] memory) {
        uint256[77] memory commitment = args.toPublicInputs(finalizedHeaderRoot);
        // copy all elements into a dynamic array. We need to do this because ethers-rs has a bug that can't support uint256[65] return types
        uint256[] memory result = new uint256[](77);
        for (uint256 i = 0; i < commitment.length; i++) {
            result[i] = commitment[i];
        }
        return result;
    }
}
