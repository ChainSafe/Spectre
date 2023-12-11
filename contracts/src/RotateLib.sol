// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { EndianConversions } from "./EndianConversions.sol";

library RotateLib {

    struct RotateInput {
        bytes32 syncCommitteeSSZ;
        uint256 syncCommitteePoseidon;
        uint256[12] accumulator;
    }

    /**
    * @notice Compute the public input commitment for the rotation
    *           This must always match the method used in  lightclient-circuits/src/committee_udate_circuit.rs - CommitteeUpdateCircuit::instance()
    * @param args The arguments for the sync step
    * @return The public input commitment that can be sent to the verifier contract.
     */
    function toPublicInputs(RotateInput memory args, bytes32 finalizedHeaderRoot) internal pure returns (uint256[77] memory) {
        uint256[77] memory inputs;

        for (uint256 i = 0; i < args.accumulator.length; i++) {
            inputs[i] = args.accumulator[i];
        }

        inputs[args.accumulator.length] = args.syncCommitteePoseidon;

        uint256 syncCommitteeSSZNumeric = uint256(args.syncCommitteeSSZ);
        for (uint256 i = 0; i < 32; i++) {
            inputs[args.accumulator.length + 32 - i] = syncCommitteeSSZNumeric % 2 ** 8;
            syncCommitteeSSZNumeric = syncCommitteeSSZNumeric / 2 ** 8;
        }

        uint256 finalizedHeaderRootNumeric = uint256(finalizedHeaderRoot);
        for (uint256 j = 0; j < 32; j++) {
            inputs[args.accumulator.length + 64 - j] = finalizedHeaderRootNumeric % 2 ** 8;
            finalizedHeaderRootNumeric = finalizedHeaderRootNumeric / 2 ** 8;
        }

        return inputs;
    }
}
