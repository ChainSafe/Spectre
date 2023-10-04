// SPDX-License-Identifier: MIT
pragma solidity 0.8.16;

import { SyncStepLib } from "./SyncStepLib.sol";
import { Verifier as SyncStepVerifier } from "../snark-verifiers/sync_step.sol";
import { Verifier as CommitteeUpdateVerifier } from "../snark-verifiers/committee_update_aggregated.sol";

contract Spectre {
    using SyncStepLib for SyncStepLib.SyncStepInput;

    uint256 internal immutable SLOTS_PER_PERIOD;

    /// @notice Maps from a sync period to the poseidon commitment for the sync committee.
    mapping(uint256 => bytes32) public syncCommitteePoseidons;

    /// @notice Maps from a slot to a beacon block header root.
    mapping(uint256 => bytes32) public blockHeaderRoots;

    /// @notice Maps from a slot to the current finalized ethereum1 execution state root.
    mapping(uint256 => bytes32) public executionStateRoots;

    /// @notice The contract used to verify the sync step proofs
    SyncStepVerifier public immutable stepVerifier;
    
    /// @notice The contract used to verify the committee update / rotation proofs
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

    /// @notice Verify attestations for a given slot and update the contract state.
    ///         The sync committee rotation must already have been posted for the period which the update belongs to.
    /// @param input The input to the sync step. Defines the slot and attestation to verify
    /// @param proof The proof for the sync step
    function step(SyncStepLib.SyncStepInput calldata input, bytes calldata proof) external {
        uint256 currentPeriod = getSyncCommitteePeriod(input.finalizedSlot);

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
    }

    function getSyncCommitteePeriod(uint256 slot) internal view returns (uint256) {
        return slot / SLOTS_PER_PERIOD;
    }
}
