// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


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
    function toInputCommitment(RotateInput memory args, bytes32 finalizedHeaderRoot) internal pure returns (uint256[] memory) {
        // TODO: Impment this
        return new uint256[](0);
    }
}
