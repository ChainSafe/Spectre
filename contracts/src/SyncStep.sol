// SPDX-License-Identifier: MIT
pragma solidity 0.8.16;

import {SSZ} from "telepathy-libs/SimpleSerialize.sol";
import "forge-std/console.sol";


library SyncStep {
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
    * @return comm The public input commitment that can be sent to the verifier contract.
     */
    function toInputCommitment(SyncStepArgs memory args, bytes32 keysPoseidonCommitment) internal view returns (uint256) {
        bytes32 attestedSlotBytes = SSZ.toLittleEndian(args.attestedSlot);
        bytes32 finalizedSlotBytes = SSZ.toLittleEndian(args.finalizedSlot);
        bytes32 participationBytes = SSZ.toLittleEndian(args.participation);

        bytes32 h = sha256(bytes.concat(attestedSlotBytes, finalizedSlotBytes));
        h = sha256(bytes.concat(h, participationBytes));
        h = sha256(bytes.concat(h, args.executionPayloadRoot));
        h = sha256(bytes.concat(h, keysPoseidonCommitment));

        uint256 commitment = uint256(SSZ.toLittleEndian(uint256(h)));
        return commitment & ((uint256(1) << 253) - 1); // truncated to 253 bits
    }
}
