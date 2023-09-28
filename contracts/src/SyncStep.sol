// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library SyncStep {
    bytes32 constant DOMAIN = keccak256("sync-step"); // TODO: Fix this to the actual domain used for the given network

    struct SyncStepArgs {
        uint256 attestedSlot;
        uint256 finalizedSlot;
        uint256 participation;
        // bytes32 executionPayloadRoot; // not sure why this is skipped right now
        bytes32 finalizedHeaderRoot;
    }

    /**
    * @notice Compute the public input commitment for the sync step given this input
    * @param args The arguments for the sync step
    * @param keysPoseidonCommitment The commitment to the keys used in the sync step
     */
    function toInputCommitment(SyncStepArgs memory args, bytes32 keysPoseidonCommitment) internal pure returns (bytes32) {
        return bytes32(0x0);
    }
}