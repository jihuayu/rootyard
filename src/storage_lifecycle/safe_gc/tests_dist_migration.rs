//! Fail-closed legacy safe-gc trust and DistributedRefCas journal migration tests (#122).

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde_json::{Value, json};
use tempfile::tempdir;
use uuid::Uuid;

use crate::ref_store::core::state_machine::RefCasStateMachine;

use super::super::{
    SafeGcError,
    model::{AuthorityLane, GcMode},
    pg_maintenance_dist::{
        ProductionRefCasAuthoritySource, RefCasCutpointSource, persist_refcas_cutpoint_snapshot,
        register_live_sm_cutpoint_source,
    },
    store::DurableSafeGcAuthority,
    voter_service::SafeGcVoterServiceConfig,
};
use super::{
    SafeGcEd25519Signer, SafeGcRepoTrustConfig,
    migration_fixtures::{
        BACKUP, BRIDGE, authority, current_quorum, dist_lane, hold, journal_path, legacy_document,
        snapshot_with_pending, voters, write_legacy_fixture, write_legacy_trust,
    },
};

#[test]
fn unmigrated_legacy_distributed_bundle_fails_closed() {
    let root = tempdir().unwrap();
    let (repo_id, tenant_id, history_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let arm = SafeGcEd25519Signer::from_seed([0x41; 32]).unwrap();
    write_legacy_fixture(root.path(), repo_id, tenant_id, history_id, arm.pubkey_hex());
    let quorum_seed = SafeGcRepoTrustConfig::seed_path(root.path(), repo_id, "quorum");
    assert!(quorum_seed.is_file(), "legacy quorum seed must exist before migration");
    let err = SafeGcRepoTrustConfig::load(root.path(), repo_id).unwrap_err();
    assert!(matches!(
        err,
        SafeGcError::ArmingRejected(
            "legacy safe-gc trust bundle requires explicit migration to independent consensus voters"
        )
    ));
    assert!(quorum_seed.is_file(), "a rejected load must not mutate legacy seeds");
}

#[test]
fn migrate_legacy_trust_file_preserves_identity_and_is_idempotent() {
    let root = tempdir().unwrap();
    let (repo_id, tenant_id, history_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let arm = SafeGcEd25519Signer::from_seed([0x41; 32]).unwrap();
    write_legacy_fixture(root.path(), repo_id, tenant_id, history_id, arm.pubkey_hex());
    let arm_seed = SafeGcRepoTrustConfig::seed_path(root.path(), repo_id, "arm");
    arm.write_seed_file(&arm_seed).unwrap();
    let arm_seed_bytes = std::fs::read(&arm_seed).unwrap();

    let migrated = SafeGcRepoTrustConfig::migrate_legacy_trust_file(root.path(), repo_id, 2, voters()).unwrap();
    assert_eq!(migrated.repo_id, repo_id);
    assert_eq!(migrated.tenant_id, tenant_id);
    assert_eq!(migrated.history_id, history_id);
    assert_eq!(migrated.trusted_arm_pubkey_hex, arm.pubkey_hex());
    assert_eq!(migrated.trusted_hold_bridge_pubkey_hex.as_deref(), Some(BRIDGE));
    assert_eq!(migrated.trusted_backup_pubkey_hex.as_deref(), Some(BACKUP));
    assert_eq!(migrated.quorum_threshold, Some(2));
    assert_eq!(migrated.trusted_consensus_voters, voters());
    assert_eq!(std::fs::read(&arm_seed).unwrap(), arm_seed_bytes, "arm seed must be preserved");
    assert!(!SafeGcRepoTrustConfig::seed_path(root.path(), repo_id, "quorum").exists());
    assert_eq!(SafeGcRepoTrustConfig::load(root.path(), repo_id).unwrap(), migrated);

    let again = SafeGcRepoTrustConfig::migrate_legacy_trust_file(root.path(), repo_id, 2, voters()).unwrap();
    assert_eq!(again, migrated);
    assert_eq!(SafeGcRepoTrustConfig::load(root.path(), repo_id).unwrap(), migrated);
}

#[test]
fn production_authority_source_never_falls_back_to_sealed_file_or_in_process_sm() {
    let root = tempdir().unwrap();
    let repo_id = Uuid::new_v4();
    let sm = RefCasStateMachine::new();
    let sealed = persist_refcas_cutpoint_snapshot(root.path(), repo_id, 0, &sm, &[]).unwrap();
    assert!(sealed.is_file(), "sealed envelope must exist to prove it is ignored");
    register_live_sm_cutpoint_source(root.path(), repo_id, 0, &Arc::new(Mutex::new(RefCasStateMachine::new())));

    let source = ProductionRefCasAuthoritySource::new(root.path());
    assert_eq!(source.storage_root(), root.path());
    assert!(source.capture_state_machine(repo_id).unwrap().is_none(), "production authority must fail closed");
}

#[test]
fn legacy_distributed_journal_fails_closed_and_migrate_preserves_pending_delete_idempotently() {
    let root = tempdir().unwrap();
    let (repo_id, tenant_id, history_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (arm, bridge, backup) = (
        SafeGcEd25519Signer::from_seed([0x41; 32]).unwrap(),
        SafeGcEd25519Signer::from_seed([0x42; 32]).unwrap(),
        SafeGcEd25519Signer::from_seed([0x43; 32]).unwrap(),
    );
    let authority = authority(tenant_id, repo_id, history_id, &arm);
    let holds = vec![hold(&authority)];
    let lane = dist_lane(&authority, &holds, &bridge, &backup);
    let batch_id = Uuid::new_v4();
    let snapshot = snapshot_with_pending(&authority, &lane, &holds, batch_id);
    let journal = journal_path(root.path(), repo_id);
    write_legacy_trust(root.path(), &authority, &arm, &bridge, &backup);
    arm.write_seed_file(&SafeGcRepoTrustConfig::seed_path(root.path(), repo_id, "arm")).unwrap();
    let doc = legacy_document(serde_json::to_value(&snapshot).unwrap());
    let bytes = serde_json::to_vec_pretty(&doc).unwrap();
    std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
    std::fs::write(&journal, &bytes).unwrap();

    let err = DurableSafeGcAuthority::open_with_journal(&journal, None).unwrap_err();
    assert!(matches!(
        err,
        SafeGcError::ArmingRejected(
            "legacy DistributedRefCas journal snapshot requires explicit migration and safe re-arm"
        )
    ));
    assert_eq!(std::fs::read(&journal).unwrap(), bytes, "fail-closed open must not mutate the journal");

    let (migrated, report) =
        SafeGcRepoTrustConfig::migrate_legacy_trust_and_journal(root.path(), &journal, repo_id, 2, voters()).unwrap();
    assert!(report.journal_migrated && report.disarmed_for_voter_rearm);
    assert_eq!(report.preserved_pending_batch_id, Some(batch_id));
    assert_eq!(report.preserved_deleted_keys, vec!["deleted-key".to_owned()]);
    assert_eq!(report.preserved_pending_keys, vec!["pending-key".to_owned()]);
    assert!(!SafeGcRepoTrustConfig::seed_path(root.path(), repo_id, "quorum").exists());
    assert!(SafeGcRepoTrustConfig::seed_path(root.path(), repo_id, "arm").is_file());
    let opened = DurableSafeGcAuthority::open_with_journal(&journal, None).unwrap();
    let snapshot = opened.snapshot();
    assert_eq!(snapshot.gc_mode, GcMode::DisabledByDefault);
    let batch = snapshot.pending_delete.as_ref().unwrap();
    assert_eq!(batch.batch_id, batch_id);
    assert_eq!(batch.deleted_keys, vec!["deleted-key".to_owned()]);
    assert_eq!(batch.pending_keys, vec!["pending-key".to_owned()]);
    let preserved = snapshot.pending_delete.clone();
    drop(opened);

    let (again, second) =
        SafeGcRepoTrustConfig::migrate_legacy_trust_and_journal(root.path(), &journal, repo_id, 2, voters()).unwrap();
    assert_eq!(again, migrated);
    assert!(!second.journal_migrated);
    let reopened = DurableSafeGcAuthority::open_with_journal(&journal, None).unwrap();
    assert_eq!(reopened.snapshot().pending_delete, preserved, "idempotent migration must preserve pending delete");
    drop(reopened);

    let epoch = authority.incarnation_epoch;
    let arm = migrated.rearm_distributed_with_quorum(root.path(), &journal, current_quorum(&lane), None).unwrap();
    assert!(matches!(&arm.lane, AuthorityLane::DistributedRefCas { .. }));
    let rearmed = DurableSafeGcAuthority::open_with_journal(&journal, None).unwrap().snapshot();
    assert!(matches!(&rearmed.gc_mode, GcMode::ArmedDestructive(_)));
    assert_eq!(rearmed.authority.incarnation_epoch, epoch);
    let batch = rearmed.pending_delete.as_ref().unwrap();
    assert_eq!(batch.batch_id, batch_id);
    assert_eq!(batch.deleted_keys, vec!["deleted-key".to_owned()]);
    assert_eq!(batch.pending_keys, vec!["pending-key".to_owned()]);
}

#[test]
fn migrate_legacy_journal_rejects_mismatched_repo_without_mutating_disk() {
    for untrusted_bridge in [false, true] {
        let root = tempdir().unwrap();
        let (repo_id, tenant_id, history_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let (arm, bridge, backup) = (
            SafeGcEd25519Signer::from_seed([0x41; 32]).unwrap(),
            SafeGcEd25519Signer::from_seed([0x42; 32]).unwrap(),
            SafeGcEd25519Signer::from_seed([0x43; 32]).unwrap(),
        );
        let authority = authority(tenant_id, repo_id, history_id, &arm);
        let holds = vec![hold(&authority)];
        let rogue = SafeGcEd25519Signer::from_seed([0x99; 32]).unwrap();
        let lane = if untrusted_bridge {
            dist_lane(&authority, &holds, &rogue, &backup)
        } else {
            dist_lane(&authority, &holds, &bridge, &backup)
        };
        let snapshot = snapshot_with_pending(&authority, &lane, &holds, Uuid::new_v4());
        let mut doc = legacy_document(serde_json::to_value(&snapshot).unwrap());
        if !untrusted_bridge {
            doc["authority"]["repo_id"] = json!(Uuid::new_v4());
        }
        write_legacy_trust(root.path(), &authority, &arm, &bridge, &backup);
        let journal = journal_path(root.path(), repo_id);
        std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
        std::fs::write(&journal, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        let trust_path = SafeGcRepoTrustConfig::config_path(root.path(), repo_id);
        let before = std::fs::read(&trust_path).unwrap();
        let seed = SafeGcRepoTrustConfig::seed_path(root.path(), repo_id, "quorum");
        let seed_before = std::fs::read(&seed).unwrap();

        let err = SafeGcRepoTrustConfig::migrate_legacy_trust_and_journal(root.path(), &journal, repo_id, 2, voters())
            .unwrap_err();
        assert!(matches!(err, SafeGcError::ArmingRejected(_)));
        assert_eq!(std::fs::read(&trust_path).unwrap(), before, "rejected migration must not rewrite trust");
        assert_eq!(std::fs::read(&seed).unwrap(), seed_before, "rejected migration must preserve legacy seed");
        assert!(seed.is_file());
    }
}

#[test]
fn voter_service_config_validates_bounds_and_rejects_unknown_fields() {
    let config = SafeGcVoterServiceConfig {
        voter_id: 1,
        key_id: 1,
        group_id: 0,
        bind_addr: "127.0.0.1:0".into(),
        signer_seed_path: PathBuf::from("voter.seed"),
        raft_node_addr: "127.0.0.1:7000".into(),
        raft_server_name: "raft-node-1.refcas.internal".into(),
        ca_cert_pem: PathBuf::from("ca.crt"),
        client_cert_pem: PathBuf::from("v1.crt"),
        client_key_pem: PathBuf::from("v1.key"),
        listener_ca_cert_pem: PathBuf::from("ca.crt"),
        listener_server_cert_pem: PathBuf::from("vs1.crt"),
        listener_server_key_pem: PathBuf::from("vs1.key"),
        listener_auth_token_path: PathBuf::from("voter-auth.token"),
        allowed_client_san: "safe-gc-worker.refcas.internal".into(),
        rpc_timeout_ms: 5_000,
    };
    config.validate().unwrap();
    let mut doc: Value = serde_json::to_value(&config).unwrap();
    doc["unexpected_field"] = json!(true);
    assert!(serde_json::from_value::<SafeGcVoterServiceConfig>(doc).is_err());
    let mut invalid = config.clone();
    invalid.voter_id = 0;
    assert!(matches!(invalid.validate(), Err(SafeGcError::ArmingRejected(_))));
    let mut empty_san = config.clone();
    empty_san.allowed_client_san = String::new();
    assert!(matches!(empty_san.validate(), Err(SafeGcError::ArmingRejected(_))));
    let mut wildcard_san = config;
    wildcard_san.allowed_client_san = "*.refcas.internal".into();
    assert!(matches!(wildcard_san.validate(), Err(SafeGcError::ArmingRejected(_))));
}

#[test]
fn boundary_crash_after_trust_commit_before_journal_persist_fails_closed_and_retries_cleanly() {
    let root = tempdir().unwrap();
    let (repo_id, tenant_id, history_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (arm, bridge, backup) = (
        SafeGcEd25519Signer::from_seed([0x41; 32]).unwrap(),
        SafeGcEd25519Signer::from_seed([0x42; 32]).unwrap(),
        SafeGcEd25519Signer::from_seed([0x43; 32]).unwrap(),
    );
    let authority = authority(tenant_id, repo_id, history_id, &arm);
    let holds = vec![hold(&authority)];
    let lane = dist_lane(&authority, &holds, &bridge, &backup);
    let batch_id = Uuid::new_v4();
    let snapshot = snapshot_with_pending(&authority, &lane, &holds, batch_id);
    let journal = journal_path(root.path(), repo_id);
    write_legacy_trust(root.path(), &authority, &arm, &bridge, &backup);
    arm.write_seed_file(&SafeGcRepoTrustConfig::seed_path(root.path(), repo_id, "arm")).unwrap();
    let doc = legacy_document(serde_json::to_value(&snapshot).unwrap());
    let bytes = serde_json::to_vec_pretty(&doc).unwrap();
    std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
    std::fs::write(&journal, &bytes).unwrap();

    let err = SafeGcRepoTrustConfig::migrate_legacy_trust_and_journal_with_boundary_hook(
        root.path(),
        &journal,
        repo_id,
        2,
        voters(),
        || Err(SafeGcError::Io("simulated crash after trust commit before journal persist".into())),
    )
    .unwrap_err();
    assert!(matches!(err, SafeGcError::Io(_)));
    let half = SafeGcRepoTrustConfig::load(root.path(), repo_id).unwrap();
    assert_eq!(half.quorum_threshold, Some(2));
    assert!(!SafeGcRepoTrustConfig::seed_path(root.path(), repo_id, "quorum").exists());
    assert_eq!(std::fs::read(&journal).unwrap(), bytes, "crash must leave the legacy journal byte-identical");
    assert!(matches!(
        DurableSafeGcAuthority::open_with_journal(&journal, None),
        Err(SafeGcError::ArmingRejected(
            "legacy DistributedRefCas journal snapshot requires explicit migration and safe re-arm"
        ))
    ));
    let mismatched: Vec<_> = voters().into_iter().rev().collect();
    assert!(
        SafeGcRepoTrustConfig::migrate_legacy_trust_and_journal(root.path(), &journal, repo_id, 2, mismatched).is_err()
    );
    assert_eq!(std::fs::read(&journal).unwrap(), bytes, "a mismatched retry must not corrupt the journal");

    let (trust, report) =
        SafeGcRepoTrustConfig::migrate_legacy_trust_and_journal(root.path(), &journal, repo_id, 2, voters()).unwrap();
    assert_eq!(trust.quorum_threshold, Some(2));
    assert!(report.journal_migrated && report.disarmed_for_voter_rearm);
    assert_eq!(report.preserved_pending_batch_id, Some(batch_id));
    assert_eq!(report.preserved_deleted_keys, vec!["deleted-key".to_owned()]);
    assert_eq!(report.preserved_pending_keys, vec!["pending-key".to_owned()]);
    let opened = DurableSafeGcAuthority::open_with_journal(&journal, None).unwrap();
    let snapshot = opened.snapshot();
    assert_eq!(snapshot.gc_mode, GcMode::DisabledByDefault);
    let batch = snapshot.pending_delete.as_ref().unwrap();
    assert_eq!(batch.batch_id, batch_id);
    assert_eq!(batch.deleted_keys, vec!["deleted-key".to_owned()]);
    assert_eq!(batch.pending_keys, vec!["pending-key".to_owned()]);
}
