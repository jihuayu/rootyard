//! Independent multi-voter Ed25519 quorum cutpoint fail-closed tests (#122).

use tempfile::tempdir;
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, InitializeGateCommand, NoopCommand, RefCasCommand, RefCasSnapshot, RefCasStateMachine,
    RepositoryLane, SmPackMode, WireGateInit,
};
use crate::ref_store::core::types::GitObjectFormat;

use super::super::domain::AuthorityRecord;
use super::super::model::{AuthorityLane, GlobalHoldEntry, GlobalHoldState, SafeGcArmReceipt, SafeGcObjectFormat};
use super::{
    BackupRootEvidence, HoldBridgeEvidence, QuorumCommitEvidence, QuorumCommitSeal, SafeGcEd25519Signer,
    SafeGcRepoTrustConfig, TrustedConsensusVoter, VoterCutpointAttestation, VoterCutpointClaims, compute_holds_digest,
    sign_single_voter_cutpoint_attestation, verify_quorum_voter_attestations, verify_single_voter_cutpoint_attestation,
};

pub(crate) const TEST_VOTER_SEEDS: [[u8; 32]; 3] = [[0x71; 32], [0x72; 32], [0x73; 32]];

pub(crate) fn test_arm_signer() -> SafeGcEd25519Signer {
    SafeGcEd25519Signer::from_seed([0x41; 32]).unwrap()
}

fn test_hold_bridge_signer() -> SafeGcEd25519Signer {
    SafeGcEd25519Signer::from_seed([0x42; 32]).unwrap()
}

fn test_backup_signer() -> SafeGcEd25519Signer {
    SafeGcEd25519Signer::from_seed([0x43; 32]).unwrap()
}

fn sha(tag: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(tag.as_bytes()))
}

fn voter_signer(voter_id: u64) -> SafeGcEd25519Signer {
    SafeGcEd25519Signer::from_seed(TEST_VOTER_SEEDS[(voter_id - 1) as usize]).unwrap()
}

pub(crate) fn test_trusted_voters() -> Vec<TrustedConsensusVoter> {
    (1..=3_u64)
        .map(|voter_id| TrustedConsensusVoter {
            voter_id,
            key_id: 1,
            ed25519_pubkey_hex: voter_signer(voter_id).pubkey_hex().to_owned(),
            endpoint_url: format!("http://127.0.0.1:{}/", 18_100 + voter_id),
        })
        .collect()
}

pub(crate) fn test_trust_config(auth: &AuthorityRecord) -> SafeGcRepoTrustConfig {
    SafeGcRepoTrustConfig {
        repo_id: auth.repo_id,
        tenant_id: auth.tenant_id,
        history_id: auth.history_id,
        trusted_arm_pubkey_hex: test_arm_signer().pubkey_hex().to_owned(),
        quorum_threshold: Some(2),
        trusted_hold_bridge_pubkey_hex: Some(test_hold_bridge_signer().pubkey_hex().to_owned()),
        trusted_backup_pubkey_hex: Some(test_backup_signer().pubkey_hex().to_owned()),
        trusted_consensus_voters: test_trusted_voters(),
    }
}

fn seeded_snapshot(auth: &AuthorityRecord, committed_log_index: u64, logical_tick: Option<u64>) -> RefCasSnapshot {
    assert!(committed_log_index >= 1);
    let mut sm = RefCasStateMachine::new();
    let gate = WireGateInit {
        repository_id: auth.repo_id,
        tenant_id: auth.tenant_id,
        object_format: GitObjectFormat::Sha1,
        history_incarnation: auth.history_id,
        authority_epoch: 1,
        group_epoch: 1,
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
        let tick = (index == committed_log_index).then_some(logical_tick).flatten();
        sm.apply(AppliedLogId { term: 1, index }, RefCasCommand::Noop(NoopCommand { logical_tick: tick })).unwrap();
    }
    sm.snapshot().unwrap()
}

fn voter_claims(voter_id: u64, auth: &AuthorityRecord, committed_log_index: u64) -> VoterCutpointClaims {
    VoterCutpointClaims {
        voter_id,
        key_id: 1,
        group_id: 0,
        history_incarnation: auth.history_id,
        group_epoch: 1,
        authority_epoch: 1,
        raft_term: 1,
        committed_log_index,
        raft_commit_digest_hex: sha("raft-commit"),
    }
}

fn attestation(
    voter_id: u64,
    auth: &AuthorityRecord,
    committed_log_index: u64,
    snapshot: &RefCasSnapshot,
) -> VoterCutpointAttestation {
    sign_single_voter_cutpoint_attestation(
        &voter_signer(voter_id),
        &voter_claims(voter_id, auth, committed_log_index),
        snapshot,
    )
    .unwrap()
}

fn quorum_seal(snapshot: &RefCasSnapshot, auth: &AuthorityRecord, committed_log_index: u64) -> QuorumCommitSeal {
    let one = attestation(1, auth, committed_log_index, snapshot);
    let two = attestation(2, auth, committed_log_index, snapshot);
    QuorumCommitSeal {
        group_id: 0,
        history_incarnation: auth.history_id,
        authority_epoch: 1,
        raft_term: 1,
        committed_log_index,
        raft_commit_digest_hex: sha("raft-commit"),
        snapshot_sha256: one.snapshot_sha256.clone(),
        snapshot_checksum: sha("sm-snapshot"),
        quorum_threshold: 2,
        voter_signatures: vec![one.signature, two.signature],
    }
}

pub(crate) fn make_test_dist_lane(
    auth: &AuthorityRecord,
    raft_commit_index: u64,
    holds: &[GlobalHoldEntry],
    format: SafeGcObjectFormat,
) -> AuthorityLane {
    let snapshot = seeded_snapshot(auth, raft_commit_index, None);
    let quorum =
        QuorumCommitEvidence::from_verified_voters(auth.repo_id, 1, quorum_seal(&snapshot, auth, raft_commit_index))
            .unwrap();
    let bridge =
        HoldBridgeEvidence::sign(&test_hold_bridge_signer(), auth.repo_id, 1, raft_commit_index.max(1), holds).unwrap();
    let backup = BackupRootEvidence::sign(
        &test_backup_signer(),
        auth.repo_id,
        1,
        1,
        hex::encode([0x44_u8; 32]),
        vec!["a".repeat(format.oid_hex_len())],
    )
    .unwrap();
    AuthorityLane::DistributedRefCas {
        ref_cas_authority_id: auth.repo_id,
        quorum_epoch: 1,
        raft_commit_index,
        quorum_evidence: Box::new(quorum),
        hold_bridge_evidence: Box::new(bridge),
        backup_root_evidence: Box::new(backup),
        async_projection_only: false,
    }
}

fn authority_record() -> AuthorityRecord {
    AuthorityRecord {
        tenant_id: Uuid::new_v4(),
        repo_id: Uuid::new_v4(),
        history_id: Uuid::new_v4(),
        trusted_arm_pubkey_hex: test_arm_signer().pubkey_hex().to_owned(),
        incarnation_id: Uuid::new_v4(),
        incarnation_epoch: 1,
        membership_generation: 1,
        live_ref_seq: 1,
        lease_epoch: 1,
    }
}

fn sample_holds() -> Vec<GlobalHoldEntry> {
    vec![GlobalHoldEntry {
        hold_id: Uuid::from_u128(0x5afe_6c00_0151_0001),
        tenant_id: Uuid::new_v4(),
        repo_id: Uuid::new_v4(),
        incarnation_epoch: 1,
        registered_seq: 1,
        state: GlobalHoldState::Active,
        protected_pack_ids: vec![Uuid::new_v4()],
        protected_oids: vec!["b".repeat(40)],
        protected_physical_keys: vec!["safe-gc/pack".into()],
    }]
}

#[test]
fn arm_receipt_signature_and_ttl_arming_fail_closed() {
    let auth = authority_record();
    let lane = make_test_dist_lane(&auth, 10, &[], SafeGcObjectFormat::Sha1);
    lane.validate_for_destructive_gc().unwrap();
    let arm = SafeGcArmReceipt::seal(
        &test_arm_signer(),
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        auth.incarnation_id,
        auth.incarnation_epoch,
        true,
        lane,
    )
    .unwrap();
    arm.validate().unwrap();
    assert_eq!(arm.arm_pubkey_hex, test_arm_signer().pubkey_hex());

    let mut tampered = arm.clone();
    tampered.arm_signature_hex = hex::encode([0x55_u8; 64]);
    assert!(matches!(tampered.validate(), Err(super::super::SafeGcError::ArmingRejected(_))));

    let mut ttl = arm;
    ttl.armed_from_cache_or_ttl_only = true;
    assert!(matches!(ttl.validate(), Err(super::super::SafeGcError::ArmingRejected(_))));
}

#[test]
fn independent_voters_reject_minority_tampering_and_forged_signatures() {
    let auth = authority_record();
    let snapshot = seeded_snapshot(&auth, 10, None);
    let one = attestation(1, &auth, 10, &snapshot);
    let two = attestation(2, &auth, 10, &snapshot);
    let trust = test_trust_config(&auth);

    let mut minority = two.clone();
    minority.signature = one.signature.clone();
    assert!(verify_quorum_voter_attestations(&trust, auth.repo_id, &[minority]).is_err());

    let mut forged = two.clone();
    forged.signature.signature_hex = hex::encode([0x66_u8; 64]);
    assert!(verify_quorum_voter_attestations(&trust, auth.repo_id, &[one.clone(), forged]).is_err());

    let mut duplicate_voter = two.clone();
    duplicate_voter.signature.voter_id = 1;
    assert!(verify_quorum_voter_attestations(&trust, auth.repo_id, &[one.clone(), duplicate_voter]).is_err());

    let mut duplicate_key = two;
    duplicate_key.signature.voter_pubkey_hex = one.signature.voter_pubkey_hex.clone();
    assert!(verify_quorum_voter_attestations(&trust, auth.repo_id, &[one, duplicate_key]).is_err());
}

#[test]
fn conflicting_snapshots_cannot_reach_a_quorum() {
    let auth = authority_record();
    let a = seeded_snapshot(&auth, 10, None);
    let b = seeded_snapshot(&auth, 10, Some(7));
    assert_ne!(a.checksum, b.checksum);
    let trust = test_trust_config(&auth);
    let split = [attestation(1, &auth, 10, &a), attestation(2, &auth, 10, &b)];
    assert!(verify_quorum_voter_attestations(&trust, auth.repo_id, &split).is_err());
    let consistent = [attestation(1, &auth, 10, &a), attestation(2, &auth, 10, &a)];
    let (group_id, sm, quorum) = verify_quorum_voter_attestations(&trust, auth.repo_id, &consistent).unwrap();
    assert_eq!(group_id, 0);
    assert_eq!(sm.last_applied(), Some(AppliedLogId { term: 1, index: 10 }));
    assert_eq!(quorum.quorum_threshold, 2);
    assert_eq!(quorum.snapshot_checksum, a.checksum);
    quorum.verify(auth.repo_id, 1).unwrap();
}

#[test]
fn untrusted_voters_and_history_mismatch_are_rejected() {
    let auth = authority_record();
    let snapshot = seeded_snapshot(&auth, 10, None);
    let mut trust = test_trust_config(&auth);
    let good = [attestation(1, &auth, 10, &snapshot), attestation(2, &auth, 10, &snapshot)];
    let (_, _, quorum) = verify_quorum_voter_attestations(&trust, auth.repo_id, &good).unwrap();
    quorum.verify_against_trusted_voters(auth.repo_id, 1, auth.history_id, &trust.trusted_consensus_voters, 2).unwrap();

    trust.trusted_consensus_voters[1].ed25519_pubkey_hex = voter_signer(3).pubkey_hex().to_owned();
    assert!(
        quorum
            .verify_against_trusted_voters(auth.repo_id, 1, auth.history_id, &trust.trusted_consensus_voters, 2)
            .is_err()
    );
    trust.trusted_consensus_voters = test_trusted_voters();
    assert!(
        quorum
            .verify_against_trusted_voters(auth.repo_id, 1, Uuid::new_v4(), &trust.trusted_consensus_voters, 2)
            .is_err()
    );
    assert!(
        quorum
            .verify_against_trusted_voters(auth.repo_id, 1, auth.history_id, &trust.trusted_consensus_voters, 3)
            .is_err()
    );

    let stranger = SafeGcEd25519Signer::from_seed([0x74; 32]).unwrap();
    let foreign = sign_single_voter_cutpoint_attestation(
        &stranger,
        &VoterCutpointClaims {
            voter_id: 2,
            key_id: 1,
            group_id: 0,
            history_incarnation: auth.history_id,
            group_epoch: 1,
            authority_epoch: 1,
            raft_term: 1,
            committed_log_index: 10,
            raft_commit_digest_hex: sha("raft-commit"),
        },
        &snapshot,
    )
    .unwrap();
    assert!(
        verify_single_voter_cutpoint_attestation(
            &trust.trusted_consensus_voters[1],
            auth.repo_id,
            auth.tenant_id,
            auth.history_id,
            &foreign
        )
        .is_err()
    );
}

#[test]
fn trust_bundle_provisioning_keeps_only_the_arm_seed_on_the_worker_volume() {
    let dir = tempdir().unwrap();
    let auth = authority_record();
    let trust = SafeGcRepoTrustConfig::provision_distributed(
        dir.path(),
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        &test_arm_signer(),
        2,
        test_trusted_voters(),
        (test_hold_bridge_signer().pubkey_hex(), test_backup_signer().pubkey_hex()),
    )
    .unwrap();
    assert_eq!(SafeGcRepoTrustConfig::load(dir.path(), auth.repo_id).unwrap(), trust);
    assert!(SafeGcRepoTrustConfig::seed_path(dir.path(), auth.repo_id, "arm").is_file());
    for kind in ["quorum", "bridge", "backup", "voter"] {
        assert!(!SafeGcRepoTrustConfig::seed_path(dir.path(), auth.repo_id, kind).exists());
    }

    let lane = make_test_dist_lane(&auth, 10, &sample_holds(), SafeGcObjectFormat::Sha1);
    let arm = SafeGcArmReceipt::seal(
        &test_arm_signer(),
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        auth.incarnation_id,
        1,
        true,
        lane,
    )
    .unwrap();
    trust.verify_arm_against_trust(&arm).unwrap();

    let mut wrong_repo = arm;
    wrong_repo.repo_id = Uuid::new_v4();
    assert!(trust.verify_arm_against_trust(&wrong_repo).is_err());

    let bad_threshold = SafeGcRepoTrustConfig::provision_distributed(
        dir.path(),
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        &test_arm_signer(),
        1,
        test_trusted_voters(),
        (test_hold_bridge_signer().pubkey_hex(), test_backup_signer().pubkey_hex()),
    );
    assert!(matches!(bad_threshold, Err(super::super::SafeGcError::ArmingRejected(_))));

    let mut duplicate = test_trusted_voters();
    duplicate[1].voter_id = duplicate[0].voter_id;
    let dup = SafeGcRepoTrustConfig::provision_distributed(
        dir.path(),
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        &test_arm_signer(),
        2,
        duplicate,
        (test_hold_bridge_signer().pubkey_hex(), test_backup_signer().pubkey_hex()),
    );
    assert!(matches!(dup, Err(super::super::SafeGcError::ArmingRejected(_))));

    let reuse_arm_key = SafeGcRepoTrustConfig::provision_distributed(
        dir.path(),
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        &test_arm_signer(),
        2,
        test_trusted_voters(),
        (test_arm_signer().pubkey_hex(), test_backup_signer().pubkey_hex()),
    );
    assert!(matches!(reuse_arm_key, Err(super::super::SafeGcError::ArmingRejected(_))));
}

#[test]
fn hold_bridge_evidence_rejects_wrong_holds_and_zero_sequence() {
    let signer = test_hold_bridge_signer();
    let authority_id = Uuid::new_v4();
    let holds = sample_holds();
    let bridge = HoldBridgeEvidence::sign(&signer, authority_id, 1, 10, &holds).unwrap();
    bridge.verify(authority_id, 1).unwrap();
    let mut different_holds = holds.clone();
    different_holds[0].registered_seq = 2;
    assert_ne!(compute_holds_digest(&holds), compute_holds_digest(&different_holds));
    assert!(matches!(
        HoldBridgeEvidence::sign(&signer, authority_id, 1, 0, &holds),
        Err(super::super::SafeGcError::DistributedPrereqsMissing(_))
    ));
}

#[test]
fn backup_root_evidence_rejects_forged_oids_and_epochs() {
    let signer = test_backup_signer();
    let authority_id = Uuid::new_v4();
    let evidence =
        BackupRootEvidence::sign(&signer, authority_id, 1, 1, sha("backup"), vec!["a".repeat(40), "b".repeat(40)])
            .unwrap();
    evidence.verify(authority_id, 1).unwrap();

    let mut no_roots = evidence.clone();
    no_roots.protected_root_oids.clear();
    assert!(no_roots.verify(authority_id, 1).is_err());

    let mut wrong_epoch = evidence;
    wrong_epoch.backup_root_epoch = 2;
    assert!(wrong_epoch.verify(authority_id, 1).is_err());
}

#[tokio::test]
async fn install_to_commit_abort_leaves_pending_decision_and_publishes_cutpoint() {
    use crate::pulls::remote_merge_finalizer::unit_tests::{build_spec_and_pull, setup_fixture};
    use crate::pulls::remote_merge_finalizer::{
        AuthorityCommitOutcome, MergeAuthorityBackend, verify_pull_remote_authz_grant,
    };
    use crate::ref_store::core::state_machine::SmDecisionState;
    use crate::storage_lifecycle::safe_gc::safe_gc_refcas_cutpoint_path;

    let dir = tempdir().unwrap();
    let f = setup_fixture(GitObjectFormat::Sha256);
    let backend = f.backend.clone().with_safe_gc_cutpoint_publisher(dir.path(), 0).unwrap();
    let (spec, pull) = build_spec_and_pull(&f, 1, 1, 5);
    let validated = verify_pull_remote_authz_grant(&spec, &pull, &f.keyring).unwrap();
    backend.set_abort_after_install_once(true);
    let outcome = backend
        .install_and_commit_scoped(f.repo_id, &spec.base_ref, validated.install_cmd, validated.commit_cmd)
        .await
        .unwrap();
    assert!(matches!(outcome, AuthorityCommitOutcome::UnknownPending { .. }));
    assert!(safe_gc_refcas_cutpoint_path(dir.path(), f.repo_id).is_file());
    let sm = backend.state_machine();
    assert_eq!(sm.read_decision(spec.decision_id).unwrap().state, SmDecisionState::Open);
    assert_eq!(backend.read_ref_oid(f.repo_id, "refs/heads/main").await.unwrap(), Some(f.base_oid.clone()));
}
