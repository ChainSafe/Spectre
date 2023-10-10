// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import "forge-std/safeconsole.sol";
import {Spectre} from "../src/Spectre.sol";
import {Verifier as SyncStepVerifier} from "../snark-verifiers/sync_step.sol"; 
import {Verifier as CommitteeUpdateVerifier} from "../snark-verifiers/committee_update_aggregated.sol"; 

contract SpectreDeployLocal is Script {
    bytes proof;
    address syncStepVerifierAddress;

    function run() external {
        vm.startBroadcast();

        new SyncStepVerifier();
        new CommitteeUpdateVerifier();
        

        vm.stopBroadcast();
    }
}
