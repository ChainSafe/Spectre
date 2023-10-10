// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/console.sol";


library SyncStepLib {
    struct SyncStepInput {
        uint64 attestedSlot;
        uint64 finalizedSlot;
        uint64 participation;
        bytes32 finalizedHeaderRoot;
        bytes32 executionPayloadRoot;
    }

    function toLittleEndian64(uint64 v) internal pure returns (bytes8) {
        v = ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000) >> 32) | ((v & 0x00000000FFFFFFFF) << 32);
        return bytes8(v);
    }

    function toLittleEndian(uint256 v) internal pure returns (bytes32) {
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
            | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
            | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
            | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
            | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        v = (v >> 128) | (v << 128);
        return bytes32(v);
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
            toLittleEndian64(args.attestedSlot),
            toLittleEndian64(args.finalizedSlot),
            toLittleEndian64(args.participation),
            args.finalizedHeaderRoot,
            args.executionPayloadRoot,
            keysPoseidonCommitment
        ));
        uint256 commitment = uint256(toLittleEndian(uint256(h)));
        return commitment & ((uint256(1) << 253) - 1); // truncated to 253 bits
    }
}
