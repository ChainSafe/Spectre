use ethers::contract::abigen;

abigen!(Spectre, "./out/Spectre.sol/Spectre.json");

abigen!(StepVerifier, "./out/sync_step.sol/Verifier.json");

abigen!(
    CommitteeUpdateVerifier,
    "./out/committee_update_aggregated.sol/Verifier.json"
);

abigen!(
    StepMockVerifier,
    "./out/SyncStepMockVerifier.sol/SyncStepMockVerifier.json"
);

abigen!(
    CommitteeUpdateMockVerifier,
    "./out/CommitteeUpdateMockVerifier.sol/CommitteeUpdateMockVerifier.json"
);
