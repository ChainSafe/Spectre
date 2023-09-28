// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library SyncStep {
    bytes32 constant DOMAIN = keccak256("sync-step"); // TODO: Fix this to the actual domain used for the given network

    struct SyncStepArgs {
        uint256 attestedSlot;
        uint256 finalizedSlot;
        // bytes32 finalizedHeaderRoot;  // not sure why this is skipped right now
        uint256 participation;
        bytes32 executionPayloadRoot;
    }

    /**
    * @notice Compute the public input commitment for the sync step given this input.
    *         This must always match the prodecure used in lightclient-circuits/src/sync_step_circuit.rs - SyncStepCircuit::instance()
    * @param args The arguments for the sync step
    * @param keysPoseidonCommitment The commitment to the keys used in the sync step
     */
    function toInputCommitment(SyncStepArgs memory args, bytes32 keysPoseidonCommitment) internal pure returns (uint256 comm) {
        // May need to convert to LE
        bytes32 attestedSlotBytes = bytes32(args.attestedSlot);
        bytes32 finalizedSlotBytes = bytes32(args.finalizedSlot);
        bytes32 participationBytes = bytes32(args.participation);

        bytes32 h = sha256(bytes.concat(attestedSlotBytes, finalizedSlotBytes));
        h = sha256(bytes.concat(participationBytes, h));
        h = sha256(bytes.concat(args.executionPayloadRoot, h));
        h = sha256(bytes.concat(keysPoseidonCommitment, h));
        comm = uint256(h) & ((uint256(1) << 253) - 1); // truncate to 253 bits
    }
}
