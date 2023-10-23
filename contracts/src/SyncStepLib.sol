// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { EndianConversions } from "./EndianConversions.sol";

library SyncStepLib {
    struct SyncStepInput {
        uint64 attestedSlot;
        uint64 finalizedSlot;
        uint64 participation;
        bytes32 finalizedHeaderRoot;
        bytes32 executionPayloadRoot;
    }

    /**
    * @notice Compute the public input commitment for the sync step given this input.
    *         This must always match the prodecure used in lightclient-circuits/src/sync_step_circuit.rs - SyncStepCircuit::instance()
    * @param args The arguments for the sync step
    * @param keysPoseidonCommitment The commitment to the keys used in the sync step
    * @return The public input commitment that can be sent to the verifier contract.
     */
    function toInputCommitment(SyncStepInput memory args, bytes32 keysPoseidonCommitment) internal pure returns (uint256) {
        bytes32 h = sha256(abi.encodePacked(
            EndianConversions.toLittleEndian64(args.attestedSlot),
            EndianConversions.toLittleEndian64(args.finalizedSlot),
            EndianConversions.toLittleEndian64(args.participation),
            args.finalizedHeaderRoot,
            args.executionPayloadRoot,
            keysPoseidonCommitment
        ));
        uint256 commitment = uint256(EndianConversions.toLittleEndian(uint256(h)));
        return commitment & ((uint256(1) << 253) - 1); // truncated to 253 bits
    }
}
