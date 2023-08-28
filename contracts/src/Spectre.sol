// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Spectre {
    
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
