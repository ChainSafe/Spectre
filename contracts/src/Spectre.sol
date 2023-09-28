// SPDX-License-Identifier: MIT
pragma solidity 0.8.16;

import { SyncStep } from "./SyncStep.sol";

contract Spectre {
    using SyncStep for SyncStep.SyncStepArgs;

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
