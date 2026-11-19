//! Shared Ed25519, trust-provisioning and distributed-lane helpers for Safe GC integration tests (#122).

use std::path::Path;

use rootyard::ref_store::core::state_machine::{
    AppliedLogId, InitializeGateCommand, NoopCommand, RefCasCommand, RefCasSnapshot, RefCasStateMachine,
    RepositoryLane, SmPackMode, WireGateInit,
};
use rootyard::ref_store::core::types::GitObjectFormat;
use rootyard::storage_lifecycle::safe_gc::{
    BackupRootEvidence, HoldBridgeEvidence, QuorumCommitEvidence, SafeGcEd25519Signer, SafeGcError,
    SafeGcRepoTrustConfig, TrustedConsensusVoter, VoterCutpointClaims,
    dist_auth::{QuorumCommitSeal, sign_single_voter_cutpoint_attestation},
    model::GlobalHoldEntry,
    model::SafeGcObjectFormat,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const TEST_ARM_SEED: [u8; 32] = [0x41; 32];
pub const TEST_VOTER_SEEDS: [[u8; 32]; 3] = [[0x71; 32], [0x72; 32], [0x73; 32]];

pub fn test_arm_signer() -> SafeGcEd25519Signer {
    SafeGcEd25519Signer::from_seed(TEST_ARM_SEED).unwrap()
}

fn test_hold_bridge_signer() -> SafeGcEd25519Signer {
    SafeGcEd25519Signer::from_seed([0x42; 32]).unwrap()
}

fn test_backup_signer() -> SafeGcEd25519Signer {
    SafeGcEd25519Signer::from_seed([0x43; 32]).unwrap()
}

fn voter_signer(voter_id: u64) -> SafeGcEd25519Signer {
    SafeGcEd25519Signer::from_seed(TEST_VOTER_SEEDS[(voter_id - 1) as usize]).unwrap()
}

pub fn test_trusted_voters() -> Vec<TrustedConsensusVoter> {
    (1..=3_u64)
        .map(|voter_id| TrustedConsensusVoter {
            voter_id,
            key_id: 1,
            ed25519_pubkey_hex: voter_signer(voter_id).pubkey_hex().to_owned(),
            endpoint_url: format!("http://127.0.0.1:{}/", 18_100 + voter_id),
        })
        .collect()
}

fn sha(tag: &str) -> String {
    hex::encode(Sha256::digest(tag.as_bytes()))
}

pub fn seeded_snapshot(
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
    group_epoch: i64,
    committed_log_index: u64,
) -> RefCasSnapshot {
    assert!(committed_log_index >= 1);
    let mut sm = RefCasStateMachine::new();
    let gate = WireGateInit {
        repository_id: repo_id,
        tenant_id,
        object_format: GitObjectFormat::Sha1,
        history_incarnation: history_id,
        authority_epoch: 1,
        group_epoch,
        head_ref: "refs/heads/main".into(),
    };
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate,
            lane: RepositoryLane::ServingRefStore,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 1,
        }),
    )
    .unwrap();
    for index in 2..=committed_log_index {
        sm.apply(AppliedLogId { term: 1, index }, RefCasCommand::Noop(NoopCommand { logical_tick: None })).unwrap();
    }
    sm.snapshot().unwrap()
}

pub fn test_dist_lane(
    tenant_id: Uuid,
    ref_cas_authority_id: Uuid,
    history_id: Uuid,
    quorum_epoch: u64,
    raft_commit_index: u64,
    holds: &[GlobalHoldEntry],
    format: SafeGcObjectFormat,
) -> rootyard::storage_lifecycle::safe_gc::model::AuthorityLane {
    let snapshot = seeded_snapshot(
        tenant_id,
        ref_cas_authority_id,
        history_id,
        i64::try_from(quorum_epoch).unwrap(),
        raft_commit_index,
    );
    let mut signatures = Vec::new();
    let mut snapshot_sha256 = String::new();
    for voter_id in [1_u64, 2] {
        let claims = VoterCutpointClaims {
            voter_id,
            key_id: 1,
            group_id: 0,
            history_incarnation: history_id,
            group_epoch: i64::try_from(quorum_epoch).unwrap(),
            authority_epoch: 1,
            raft_term: 1,
            committed_log_index: raft_commit_index,
            raft_commit_digest_hex: sha("raft-commit"),
        };
        let attested = sign_single_voter_cutpoint_attestation(&voter_signer(voter_id), &claims, &snapshot).unwrap();
        snapshot_sha256 = attested.snapshot_sha256.clone();
        signatures.push(attested.signature);
    }
    let quorum = QuorumCommitEvidence::from_verified_voters(
        ref_cas_authority_id,
        quorum_epoch,
        QuorumCommitSeal {
            group_id: 0,
            history_incarnation: history_id,
            authority_epoch: 1,
            raft_term: 1,
            committed_log_index: raft_commit_index,
            raft_commit_digest_hex: sha("raft-commit"),
            snapshot_sha256,
            snapshot_checksum: sha("s3-it-sm-snap"),
            quorum_threshold: 2,
            voter_signatures: signatures,
        },
    )
    .unwrap();
    let bridge = HoldBridgeEvidence::sign(
        &test_hold_bridge_signer(),
        ref_cas_authority_id,
        quorum_epoch,
        raft_commit_index.max(1),
        holds,
    )
    .unwrap();
    let backup = BackupRootEvidence::sign(
        &test_backup_signer(),
        ref_cas_authority_id,
        quorum_epoch,
        1,
        hex::encode([0x44_u8; 32]),
        vec!["a".repeat(format.oid_hex_len())],
    )
    .unwrap();
    rootyard::storage_lifecycle::safe_gc::model::AuthorityLane::DistributedRefCas {
        ref_cas_authority_id,
        quorum_epoch,
        raft_commit_index,
        quorum_evidence: Box::new(quorum),
        hold_bridge_evidence: Box::new(bridge),
        backup_root_evidence: Box::new(backup),
        async_projection_only: false,
    }
}

/// Seal an arm with the shared test signer so repository trust matches the acceptance key.
pub fn seal_test_lane_arm(
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
    incarnation_id: Uuid,
    incarnation_epoch: u64,
    lane: rootyard::storage_lifecycle::safe_gc::model::AuthorityLane,
) -> Result<rootyard::storage_lifecycle::safe_gc::model::SafeGcArmReceipt, SafeGcError> {
    rootyard::storage_lifecycle::safe_gc::model::SafeGcArmReceipt::seal(
        &test_arm_signer(),
        tenant_id,
        repo_id,
        history_id,
        incarnation_id,
        incarnation_epoch,
        true,
        lane,
    )
}

pub fn provision_single_node_trust(
    storage_root: &Path,
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
) -> Result<SafeGcRepoTrustConfig, SafeGcError> {
    SafeGcRepoTrustConfig::provision_single_node(storage_root, tenant_id, repo_id, history_id, &test_arm_signer())
}

pub fn provision_distributed_trust(
    storage_root: &Path,
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
    quorum_threshold: usize,
    trusted_voters: Vec<TrustedConsensusVoter>,
) -> Result<SafeGcRepoTrustConfig, SafeGcError> {
    let bridge = test_hold_bridge_signer();
    let backup = test_backup_signer();
    SafeGcRepoTrustConfig::provision_distributed(
        storage_root,
        tenant_id,
        repo_id,
        history_id,
        &test_arm_signer(),
        quorum_threshold,
        trusted_voters,
        (bridge.pubkey_hex(), backup.pubkey_hex()),
    )
}

/// Prove the worker volume holds no external voter/quorum/bridge/backup private material.
pub fn assert_worker_volume_has_no_external_signing_keys(storage_root: &Path, repo_id: Uuid) {
    let dir = SafeGcRepoTrustConfig::trust_dir(storage_root);
    let config = format!("{repo_id}.json");
    let arm_seed = format!("{repo_id}.arm.seed");
    let prefix = format!("{repo_id}.");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("worker trust directory must exist")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(&prefix))
        .collect();
    names.sort();
    for name in &names {
        assert!(name == &config || name == &arm_seed, "worker volume unexpectedly holds trust artifact {name}");
        for forbidden in ["quorum", "bridge", "backup", "voter"] {
            assert!(!name.contains(forbidden), "worker volume holds external signing material: {name}");
        }
    }
    assert!(names.contains(&config), "worker trust config missing");
    assert!(names.contains(&arm_seed), "worker arm seed missing");
    assert!(!dir.join(format!("{repo_id}.quorum.seed")).exists());
    assert!(!dir.join(format!("{repo_id}.bridge.seed")).exists());
    assert!(!dir.join(format!("{repo_id}.backup.seed")).exists());
}
