// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { EndianConversions } from "./EndianConversions.sol";

library RotateLib {

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

        inputs[0] = uint256(EndianConversions.toLittleEndian(uint256(args.syncCommitteePoseidon)));

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
