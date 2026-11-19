//! Fail-closed legacy safe-gc trust migration tests (#122).

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use tempfile::tempdir;
use uuid::Uuid;

use crate::ref_store::core::state_machine::RefCasStateMachine;

use super::super::{
    SafeGcError,
    pg_maintenance_dist::{
        ProductionRefCasAuthoritySource, RefCasCutpointSource, persist_refcas_cutpoint_snapshot,
        register_live_sm_cutpoint_source,
    },
};
use super::{
    SafeGcEd25519Signer, SafeGcRepoTrustConfig, TrustedConsensusVoter, ensure_private_dir, write_private_file,
};

const BRIDGE: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const BACKUP: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn legacy_json(repo_id: Uuid, tenant_id: Uuid, history_id: Uuid, arm: &str) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "repo_id": repo_id,
        "tenant_id": tenant_id,
        "history_id": history_id,
        "trusted_arm_pubkey_hex": arm,
        "trusted_quorum_pubkey_hex": "1".repeat(64),
        "trusted_hold_bridge_pubkey_hex": BRIDGE,
        "trusted_backup_pubkey_hex": BACKUP,
        "refcas_keyring_dir": "/var/lib/rootyard/refcas-keyring",
    }))
    .unwrap()
}

fn write_legacy_fixture(root: &Path, repo_id: Uuid, tenant_id: Uuid, history_id: Uuid, arm: &str) {
    let dir = SafeGcRepoTrustConfig::trust_dir(root);
    ensure_private_dir(&dir).unwrap();
    write_private_file(
        &SafeGcRepoTrustConfig::config_path(root, repo_id),
        &legacy_json(repo_id, tenant_id, history_id, arm),
    )
    .unwrap();
    write_private_file(&SafeGcRepoTrustConfig::seed_path(root, repo_id, "quorum"), &[0x55; 32]).unwrap();
}

fn voters() -> Vec<TrustedConsensusVoter> {
    [0x71_u8, 0x72]
        .into_iter()
        .enumerate()
        .map(|(index, byte)| TrustedConsensusVoter {
            voter_id: index as u64 + 1,
            key_id: 1,
            ed25519_pubkey_hex: SafeGcEd25519Signer::from_seed([byte; 32]).unwrap().pubkey_hex().to_owned(),
            endpoint_url: format!("http://127.0.0.1:{}/", 18_101 + index),
        })
        .collect()
}

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
