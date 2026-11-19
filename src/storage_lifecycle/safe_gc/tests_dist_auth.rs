//! Distributed-authority Ed25519, #151 quorum and keyring fail-closed tests (#122).

use tempfile::tempdir;
use uuid::Uuid;

use crate::ref_store::core::artifact_hold::reconcile_proof::GroupVoterSignatureDto;

use super::super::model::{
    AuthorityLane, AuthorityRecord, GlobalHoldEntry, GlobalHoldState, SafeGcArmReceipt, SafeGcObjectFormat,
};
use super::{
    BackupRootEvidence, HoldBridgeEvidence, QuorumCommitEvidence, SafeGcEd25519Signer, SafeGcRepoTrustConfig,
    write_refcas_group_keyring_dir,
};

pub(crate) fn test_arm_signer() -> SafeGcEd25519Signer {
    SafeGcEd25519Signer::from_seed([0x41; 32]).unwrap()
}

fn sha(tag: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(tag.as_bytes()))
}

pub(crate) fn make_test_dist_lane(
    ref_cas_authority_id: Uuid,
    quorum_epoch: u64,
    raft_commit_index: u64,
    holds: &[GlobalHoldEntry],
    format: SafeGcObjectFormat,
) -> AuthorityLane {
    let signer = test_arm_signer();
    let quorum = QuorumCommitEvidence::sign(
        &signer,
        ref_cas_authority_id,
        quorum_epoch,
        0,
        1,
        raft_commit_index,
        sha("sm-snapshot"),
        vec![GroupVoterSignatureDto { voter_id: 1, key_id: 0, mac_hex: hex::encode([0x33_u8; 32]) }],
    )
    .unwrap();
    let bridge =
        HoldBridgeEvidence::sign(&signer, ref_cas_authority_id, quorum_epoch, raft_commit_index.max(1), holds).unwrap();
    let backup = BackupRootEvidence::sign(
        &signer,
        ref_cas_authority_id,
        quorum_epoch,
        1,
        hex::encode([0x44_u8; 32]),
        vec!["a".repeat(format.oid_hex_len())],
    )
    .unwrap();
    AuthorityLane::DistributedRefCas {
        ref_cas_authority_id,
        quorum_epoch,
        raft_commit_index,
        quorum_evidence: quorum,
        hold_bridge_evidence: bridge,
        backup_root_evidence: backup,
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
    let lane = make_test_dist_lane(Uuid::new_v4(), 1, 10, &[], SafeGcObjectFormat::Sha1);
    let arm = SafeGcArmReceipt::seal(
        &test_arm_signer(),
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        auth.incarnation_id,
        auth.incarnation_epoch,
        true,
        lane.clone(),
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
fn quorum_and_hold_bridge_evidence_reject_tampering_and_wrong_holds() {
    let signer = test_arm_signer();
    let authority_id = Uuid::new_v4();
    let holds = sample_holds();
    let voter = GroupVoterSignatureDto { voter_id: 1, key_id: 0, mac_hex: sha("voter") };
    let quorum =
        QuorumCommitEvidence::sign(&signer, authority_id, 1, 0, 1, 10, sha("snapshot"), vec![voter.clone()]).unwrap();
    quorum.verify(authority_id, 1).unwrap();

    let mut bad_sig = quorum.clone();
    bad_sig.quorum_signature_hex = hex::encode([0x66_u8; 64]);
    assert!(bad_sig.verify(authority_id, 1).is_err());

    assert!(
        QuorumCommitEvidence::sign(&signer, authority_id, 1, 0, 1, 10, sha("snapshot"), vec![voter.clone(), voter])
            .is_err()
    );

    let bridge = HoldBridgeEvidence::sign(&signer, authority_id, 1, 10, &holds).unwrap();
    bridge.verify(authority_id, 1).unwrap();
    let mut different_holds = holds.clone();
    different_holds[0].registered_seq = 2;
    assert_ne!(super::compute_holds_digest(&holds), super::compute_holds_digest(&different_holds));
    assert!(matches!(
        HoldBridgeEvidence::sign(&signer, authority_id, 1, 0, &holds),
        Err(super::super::SafeGcError::DistributedPrereqsMissing(_))
    ));
}

#[test]
fn backup_root_evidence_rejects_forged_oids_and_epochs() {
    let signer = test_arm_signer();
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

#[test]
fn distributed_lane_rejects_async_projection_and_missing_evidence() {
    let authority_id = Uuid::new_v4();
    let lane = make_test_dist_lane(authority_id, 1, 10, &[], SafeGcObjectFormat::Sha1);
    lane.validate_for_destructive_gc().unwrap();

    let AuthorityLane::DistributedRefCas {
        ref_cas_authority_id,
        quorum_epoch,
        quorum_evidence,
        hold_bridge_evidence,
        backup_root_evidence,
        ..
    } = lane
    else {
        unreachable!()
    };
    let mut no_backup = backup_root_evidence;
    no_backup.protected_root_oids.clear();
    let bad = AuthorityLane::DistributedRefCas {
        ref_cas_authority_id,
        quorum_epoch,
        raft_commit_index: 10,
        quorum_evidence: quorum_evidence.clone(),
        hold_bridge_evidence: hold_bridge_evidence.clone(),
        backup_root_evidence: no_backup,
        async_projection_only: false,
    };
    assert!(matches!(bad.validate_for_destructive_gc(), Err(super::super::SafeGcError::DistributedPrereqsMissing(_))));
    let async_only = AuthorityLane::DistributedRefCas {
        ref_cas_authority_id,
        quorum_epoch,
        raft_commit_index: 10,
        quorum_evidence,
        hold_bridge_evidence,
        backup_root_evidence: BackupRootEvidence::sign(
            &test_arm_signer(),
            authority_id,
            1,
            1,
            sha("backup"),
            vec!["a".repeat(40)],
        )
        .unwrap(),
        async_projection_only: true,
    };
    assert!(async_only.validate_for_destructive_gc().is_err());
}

#[test]
fn trust_bundle_and_keyring_provisioning_reject_mismatched_identity() {
    let dir = tempdir().unwrap();
    let auth = authority_record();
    let trust = SafeGcRepoTrustConfig::provision_single_node(
        dir.path(),
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        &test_arm_signer(),
    )
    .unwrap();
    assert_eq!(SafeGcRepoTrustConfig::load(dir.path(), auth.repo_id).unwrap(), trust);

    let lane = AuthorityLane::SingleNodePg {
        pg_authority_id: auth.repo_id,
        pg_tx_seq: 1,
        pg_gc_fence_epoch: 1,
        reader_barrier_epoch: 1,
    };
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

    let keyring = dir.path().join("keyring");
    std::fs::create_dir_all(&keyring).unwrap();
    write_refcas_group_keyring_dir(
        &keyring,
        1,
        auth.history_id,
        2,
        &[(1, 0, [0x11; 32]), (2, 0, [0x12; 32]), (3, 0, [0x13; 32])],
    )
    .unwrap();
    let verifier =
        crate::ref_store::core::artifact_hold::reconcile_proof::GroupConsensusVerifier::from_keyring_dir(&keyring)
            .unwrap();
    assert_eq!(verifier.group_count(), 1);
}

#[tokio::test]
async fn install_to_commit_abort_leaves_pending_decision_and_publishes_cutpoint() {
    use crate::pulls::remote_merge_finalizer::unit_tests::{build_spec_and_pull, setup_fixture};
    use crate::pulls::remote_merge_finalizer::{
        AuthorityCommitOutcome, MergeAuthorityBackend, verify_pull_remote_authz_grant,
    };
    use crate::ref_store::core::state_machine::SmDecisionState;
    use crate::ref_store::core::types::GitObjectFormat;
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
