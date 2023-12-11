// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {RotateLib} from "../src/RotateLib.sol";

/**
 * @title RotateExternal
 * @dev This contract exists solely for the purpose of exposing the RotateLib functions
 *      so they can be used in the Rust test suite. It should not be part of a production deployment
 */
contract RotateExternal {
    using RotateLib for RotateLib.RotateInput;

    function toPublicInputs(
        RotateLib.RotateInput calldata args,
        bytes32 justifiedHeaderRoot,
        uint256[12] memory accumulator
    ) public pure returns (uint256[] memory) {
        uint256[77] memory commitment = args.toPublicInputs(
            justifiedHeaderRoot,
            accumulator
        );
        // copy all elements into a dynamic array. We need to do this because ethers-rs has a bug that can't support uint256[65] return types
        uint256[] memory result = new uint256[](77);
        for (uint256 i = 0; i < commitment.length; i++) {
            result[i] = commitment[i];
        }
        return result;
    }
}
