// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { SyncStepLib } from "./SyncStepLib.sol";
import { RotateLib } from "./RotateLib.sol";

import { Verifier as SyncStepVerifier } from "../snark-verifiers/sync_step.sol";
import { Verifier as CommitteeUpdateVerifier } from "../snark-verifiers/committee_update_aggregated.sol";

contract Spectre {
    using SyncStepLib for SyncStepLib.SyncStepInput;
    using RotateLib for RotateLib.RotateInput;

    uint256 internal immutable SLOTS_PER_PERIOD;

    /// Maps from a sync period to the poseidon commitment for the sync committee.
    mapping(uint256 => bytes32) public syncCommitteePoseidons;

    /// Maps from a slot to a beacon block header root.
    mapping(uint256 => bytes32) public blockHeaderRoots;

    /// Maps from a slot to the current finalized ethereum1 execution state root.
    mapping(uint256 => bytes32) public executionStateRoots;

    /// The highest slot that has been verified
    uint256 public head = 0;

    SyncStepVerifier public immutable stepVerifier;
    CommitteeUpdateVerifier public immutable committeeUpdateVerifier;

    constructor(
        address _stepVerifierAddress,
        address _committeeUpdateVerifierAddress,
        uint256 _initialSyncPeriod,
        bytes32 _initialSyncCommitteePoseidon,
        uint256 _slotsPerPeriod
    ) {
        stepVerifier = SyncStepVerifier(_stepVerifierAddress);
        committeeUpdateVerifier = CommitteeUpdateVerifier(_committeeUpdateVerifierAddress);
        syncCommitteePoseidons[_initialSyncPeriod] = _initialSyncCommitteePoseidon;
        SLOTS_PER_PERIOD = _slotsPerPeriod;
    }

    /// @notice Verify that a sync committee has attested to a block that finalizes the given header root and execution payload
    /// @param input The input to the sync step. Defines the slot and attestation to verify
    /// @param proof The proof for the sync step
    function step(SyncStepLib.SyncStepInput calldata input, bytes calldata proof) external {
        uint256 currentPeriod = getSyncCommitteePeriod(input.attestedSlot);

        if (syncCommitteePoseidons[currentPeriod] == 0) {
            revert("Sync committee not yet set for this period");
        }
        uint256 instanceCommitment = input.toInputCommitment(syncCommitteePoseidons[currentPeriod]);

        bool success = stepVerifier.verify([instanceCommitment], proof);
        if (!success) {
            revert("Proof verification failed");
        }

        // update the contract state
        executionStateRoots[input.finalizedSlot] = input.executionPayloadRoot;
        blockHeaderRoots[input.finalizedSlot] = input.finalizedHeaderRoot;
        head = input.finalizedSlot;
    }

    /// @notice Use the current sync committee to verify the transition to a new sync committee
    /// @param rotateInput The input to the sync step.
    /// @param rotateProof The proof for the rotation
    /// @param stepInput The input to the sync step.
    /// @param stepProof The proof for the sync step
    function rotate(RotateLib.RotateInput calldata rotateInput, bytes calldata rotateProof, SyncStepLib.SyncStepInput calldata stepInput, bytes calldata stepProof) external {
        // *step phase*
        // This allows trusting that the current sync committee has signed off on the finalizedHeaderRoot which is used as the base of the SSZ proof
        // that checks the new committee is in the beacon state 'next_sync_committee' field. It also allows trusting the finalizedSlot which is
        // used to calculate the sync period that the new committee belongs to.
        uint256 attestingPeriod = getSyncCommitteePeriod(stepInput.attestedSlot);
        uint256 instanceCommitment = stepInput.toInputCommitment(syncCommitteePoseidons[attestingPeriod]);
        bool stepSuccess = stepVerifier.verify([instanceCommitment], stepProof);
        if (!stepSuccess) {
            revert("Step proof verification failed");
        }

        // *rotation phase*
        // This proof checks that the given poseidon commitment and SSZ commitment to the sync committee are equivalent and that 
        // that there exists an SSZ proof that can verify this SSZ commitment to the committee is in the state
        uint256 currentPeriod = getSyncCommitteePeriod(stepInput.finalizedSlot);
        uint256 nextPeriod = currentPeriod + 1;
        uint256[65] memory verifierInput = rotateInput.toInputCommitment(stepInput.finalizedHeaderRoot);
        bool rotateSuccess = committeeUpdateVerifier.verify(verifierInput, rotateProof);
        if (!rotateSuccess) {
            revert("Rotation proof verification failed");
        }

        // update the contract state
        syncCommitteePoseidons[nextPeriod] = rotateInput.syncCommitteePoseidon;
    }

    function getSyncCommitteePeriod(uint256 slot) internal view returns (uint256) {
        return slot / SLOTS_PER_PERIOD;
    }
}
