// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


library RotateLib {

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

    struct RotateInput {
        bytes32 syncCommitteeSSZ;
        bytes32 syncCommitteePoseidon;
    }

    /**
    * @notice Compute the public input commitment for the rotation
    *           This must always match the method used in  lightclient-circuits/src/committee_udate_circuit.rs - CommitteeUpdateCircuit::instance()
    * @param args The arguments for the sync step
    * @return The public input commitment that can be sent to the verifier contract.
     */
    function toInputCommitment(RotateInput memory args, bytes32 finalizedHeaderRoot) internal pure returns (uint256[65] memory) {
        uint256[65] memory inputs;

        inputs[0] = uint256(toLittleEndian(uint256(args.syncCommitteePoseidon)));

        uint256 syncCommitteeSSZNumeric = uint256(args.syncCommitteeSSZ);
        for (uint256 i = 0; i < 32; i++) {
            inputs[32 - i] = syncCommitteeSSZNumeric % 2 ** 8;
            syncCommitteeSSZNumeric = syncCommitteeSSZNumeric / 2 ** 8;
        }

        uint256 finalizedHeaderRootNumeric = uint256(finalizedHeaderRoot);
        for (uint256 j = 0; j < 32; j++) {
            inputs[64 - j] = finalizedHeaderRootNumeric % 2 ** 8;
            finalizedHeaderRootNumeric = finalizedHeaderRootNumeric / 2 ** 8;
        }

        return inputs;
    }
}
