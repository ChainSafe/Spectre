// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { SyncStepLib } from "./SyncStepLib.sol";

contract Spectre {
    using SyncStepLib for SyncStepLib.SyncStepInput;

    address public verifierContract;

    constructor(address _verifierContract) {
        verifierContract = _verifierContract;
    }

    function postHeader(bytes calldata proof) external {
        (bool success,) = verifierContract.call(proof);

        if (!success) {
            revert("Proof verification failed");
        }
    }
}
