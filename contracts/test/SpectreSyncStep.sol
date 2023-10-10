// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import "forge-std/safeconsole.sol";
import "forge-std/Test.sol";
import "../lib/YulDeployer.sol";
import {Spectre} from "../src/Spectre.sol";

contract SpectreSyncStep is Test {
    YulDeployer yulDeployer;
    address verifierAddress;
    bytes proof;

    function setUp() public virtual {
        
        yulDeployer = new YulDeployer();
        // `mainnet_10_7.v1` is a Yul verifier for a SNARK constraining a chain of up to 1024 block headers
        // and Merkle-ization of their block hashes as specified in `updateRecent`.
        verifierAddress = address(yulDeployer.deployContract("sync_step_k21"));
        proof = vm.parseBytes(vm.readFile("test/data/sync_step_21.calldata"));
    }

    function testPostHeader() public {
        vm.pauseGasMetering();

        Spectre spectre = new Spectre(verifierAddress);
        vm.resumeGasMetering();

        spectre.postHeader(proof);
        // verifierAddress.call(proof);
    }
}
