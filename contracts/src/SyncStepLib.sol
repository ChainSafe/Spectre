// The Licensed Work is (c) 2023 ChainSafe
// Code: https://github.com/ChainSafe/Spectre
// SPDX-License-Identifier: LGPL-3.0-only

pragma solidity ^0.8.0;

import { EndianConversions } from "./EndianConversions.sol";

library SyncStepLib {
    struct SyncStepInput {
        uint64 attestedSlot;
        uint64 finalizedSlot;
        uint64 participation;
        bytes32 finalizedHeaderRoot;
        bytes32 executionPayloadRoot;
        uint256[12] accumulator;
    }

    /**
    * @notice Compute the public input commitment for the sync step given this input.
    *         This must always match the prodecure used in lightclient-circuits/src/sync_step_circuit.rs - SyncStepCircuit::instance()
    * @param args The arguments for the sync step
    * @return The public input commitment that can be sent to the verifier contract.
     */
    function toPublicInputs(SyncStepInput memory args, uint256 syncCommitteePoseidon) internal pure returns (uint256[14] memory) {
        uint256[14] memory inputs;

        for (uint256 i = 0; i < args.accumulator.length; i++) {
            inputs[i] = args.accumulator[i];
        }

        bytes32 h = sha256(abi.encodePacked(
            EndianConversions.toLittleEndian64(args.attestedSlot),
            EndianConversions.toLittleEndian64(args.finalizedSlot),
            EndianConversions.toLittleEndian64(args.participation),
            args.finalizedHeaderRoot,
            args.executionPayloadRoot
        ));
        uint256 commitment = uint256(EndianConversions.toLittleEndian(uint256(h)));

        

        inputs[args.accumulator.length] = commitment & ((uint256(1) << 253) - 1); // truncated to 253 bits
        inputs[args.accumulator.length + 1] = syncCommitteePoseidon;

        return inputs;
    }
}
