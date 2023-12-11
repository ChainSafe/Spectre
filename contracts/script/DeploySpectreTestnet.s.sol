// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

import {Spectre} from "../src/Spectre.sol";
import {Verifier as CommitteeUpdateVerifier} from "../snark-verifiers/committee_update_verifier.sol"; 
import {Verifier as SyncStepVerifier} from "../snark-verifiers/sync_step.sol";

contract DeploySpectre is Script {

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        uint256 initialSyncPeriod = vm.envUint("INITIAL_SYNC_PERIOD");
        uint256 initialCommitteePoseidon = vm.envUint("INITIAL_COMMITTEE_POSEIDON");
        uint256 slotsPerPeriod = vm.envUint("SLOTS_PER_PERIOD");

        vm.startBroadcast(deployerPrivateKey);

        SyncStepVerifier stepVerifier = new SyncStepVerifier();
        CommitteeUpdateVerifier updateVerifier = new CommitteeUpdateVerifier();

        Spectre spectre = new Spectre(address(stepVerifier), address(updateVerifier), initialSyncPeriod, initialCommitteePoseidon, slotsPerPeriod);
        
        vm.stopBroadcast();
    }
}
