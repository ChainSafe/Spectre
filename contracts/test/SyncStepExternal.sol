// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {SyncStepLib} from "../src/SyncStepLib.sol";

/**
 * @title SyncStepExternal
 * @dev This contract exists solely for the purpose of exposing the SyncStepLib functions
 *      so they can be used in the Rust test suite. It should not be part of a production deployment
 */
contract SyncStepExternal {
    using SyncStepLib for SyncStepLib.SyncStepInput;

    function toInputCommitment(
        SyncStepLib.SyncStepInput calldata args
    ) public pure returns (uint256) {
        return args.toInputCommitment();
    }
}
