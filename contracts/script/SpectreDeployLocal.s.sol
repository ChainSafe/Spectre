// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import "forge-std/safeconsole.sol";
import {Spectre} from "../src/Spectre.sol";
import {Verifier} from "../snark-verifiers/sync_step.sol"; 

contract SpectreDeployLocal is Script {
    bytes proof;
    address syncStepVerifierAddress;

    function run() external {
        vm.startBroadcast();

        Verifier verifier = new Verifier();

        vm.stopBroadcast();
    }
}
