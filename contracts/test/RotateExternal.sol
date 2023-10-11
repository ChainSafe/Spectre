// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import { RotateLib } from "../src/RotateLib.sol";

/**
* @title SyncStepLibTest
* @dev This contract exists solely for the purpose of exposing the SyncStepLib functions
*      so they can be used in the Rust test suite. It should not be part of a production deployment
*/
contract RotateExternal {
    using RotateLib for RotateLib.RotateInput;

    function toInputCommitment(RotateLib.RotateInput calldata args, bytes32 finalizedHeaderRoot) public pure returns (uint256[] memory) {
        return args.toInputCommitment(finalizedHeaderRoot);
    }
}
