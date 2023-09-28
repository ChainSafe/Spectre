// SPDX-License-Identifier: MIT
pragma solidity 0.8.16;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {SSZ} from "telepathy-libs/SimpleSerialize.sol";
import {SyncStep} from "../src/SyncStep.sol";

contract SyncStepInputEncoding is Test {
    using SyncStep for SyncStep.SyncStepArgs;

    function testToInputCommitment() public {
        // test data obtained from minimal spec test. 
        // TODO: read these from file fixtures
        SyncStep.SyncStepArgs memory args = SyncStep.SyncStepArgs({
            attestedSlot: 40,
            finalizedSlot: 24,
            participation: 32,
            executionPayloadRoot: 0xd11151b7c53e3ed79401bcdbb74845bc99ed0de99d32ebee241fc58c1e8c68cb
        });
        bytes32 keysPoseidonCommitment = 0x02b0a3b579953718463ac4baa9987225c5d74b0a7b4193e51ae091f5a0aa1c11;

        uint256 comm = args.toInputCommitment(keysPoseidonCommitment);

        // expected commitment as a little endian bit integer expressed as hex
        bytes32 expected = 0x8d387254c3f6a8074f1f4d78f99eec52a2a93104494d69ac6f52884780426019;

        assertEq(SSZ.toLittleEndian(comm), expected, "Input commitment does not match");
    }
}
