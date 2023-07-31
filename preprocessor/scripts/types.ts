import {
    BitArray,
    ByteVectorType,
    ContainerType,
    ListCompositeType,
    ValueOf,
} from "@chainsafe/ssz";
import {
    ssz,
} from "@lodestar/types"

import {
    HISTORICAL_ROOTS_LIMIT,
} from "@lodestar/params";

const primitiveSsz = ssz;
const phase0Ssz = ssz.phase0;
const altairSsz = ssz.altair;

const {
    UintNum64,
    Slot,
    ValidatorIndex,
    WithdrawalIndex,
    Root,
    BLSSignature,
    BLSPubkey,
    ExecutionAddress,
    Gwei,
    UintBn256,
    Bytes32,
} = primitiveSsz;

const ValidatorContainer = new ContainerType(
    {
        pubkey: ssz.Bytes48,
        withdrawalCredentials: ssz.Bytes32,
        effectiveBalance: ssz.UintNum64,
        slashed: ssz.Boolean,
        activationEligibilityEpoch: ssz.EpochInf,
        activationEpoch: ssz.EpochInf,
        exitEpoch: ssz.EpochInf,
        withdrawableEpoch: ssz.EpochInf,
    },
    { typeName: "Validator", jsonCase: "eth2" }
);

export type Validator = ValueOf<typeof ValidatorContainer>;

export const ValidatorsSsz = new ListCompositeType(ValidatorContainer, 1099511627776);

const HistoricalSummary = new ContainerType(
    {
        blockSummaryRoot: Root,
        stateSummaryRoot: Root,
    },
    { typeName: "HistoricalSummary", jsonCase: "eth2" }
);

export const BeaconStateSsz = new ContainerType(
    {
        genesisTime: UintNum64,
        genesisValidatorsRoot: Root,
        slot: primitiveSsz.Slot,
        fork: phase0Ssz.Fork,
        // History
        latestBlockHeader: phase0Ssz.BeaconBlockHeader,
        blockRoots: phase0Ssz.HistoricalBlockRoots,
        stateRoots: phase0Ssz.HistoricalStateRoots,
        // historical_roots Frozen in Capella, replaced by historical_summaries
        historicalRoots: new ListCompositeType(new ByteVectorType(32), HISTORICAL_ROOTS_LIMIT),
        // Eth1
        eth1Data: phase0Ssz.Eth1Data,
        eth1DataVotes: phase0Ssz.Eth1DataVotes,
        eth1DepositIndex: UintNum64,
        // Registry
        validators: ValidatorsSsz,
        balances: phase0Ssz.Balances,
        randaoMixes: phase0Ssz.RandaoMixes,
        // Slashings
        slashings: phase0Ssz.Slashings,
        // Participation
        previousEpochParticipation: altairSsz.EpochParticipation,
        currentEpochParticipation: altairSsz.EpochParticipation,
        // Finality
        justificationBits: phase0Ssz.JustificationBits,
        previousJustifiedCheckpoint: phase0Ssz.Checkpoint,
        currentJustifiedCheckpoint: phase0Ssz.Checkpoint,
        finalizedCheckpoint: phase0Ssz.Checkpoint,
        // Inactivity
        inactivityScores: altairSsz.InactivityScores,
        // Sync
        currentSyncCommittee: altairSsz.SyncCommittee,
        nextSyncCommittee: altairSsz.SyncCommittee,
        // Execution
        latestExecutionPayloadHeader: ssz.capella.ExecutionPayloadHeader, // [Modified in Capella]
        // Withdrawals
        nextWithdrawalIndex: WithdrawalIndex, // [New in Capella]
        nextWithdrawalValidatorIndex: ValidatorIndex, // [New in Capella]
        // Deep history valid from Capella onwards
        historicalSummaries: new ListCompositeType(HistoricalSummary, HISTORICAL_ROOTS_LIMIT), // [New in Capella]
    },
    { typeName: "BeaconState", jsonCase: "eth2" }
);

export type BeaconState = ValueOf<typeof BeaconStateSsz>;
