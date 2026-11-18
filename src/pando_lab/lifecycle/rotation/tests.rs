use super::*;

fn legacy_checkpoint() -> KmsRotationCheckpoint {
    serde_json::from_value(serde_json::json!({
        "rotation_id": "00000000-0000-0000-0000-000000000001",
        "repo": "00000000-0000-0000-0000-000000000002",
        "from_key_id": "kms-local-a",
        "from_key_version": 1,
        "to_key_id": "kms-local-b",
        "to_key_version": 2,
        "state": "IN_PROGRESS",
        "revoke_previous": false,
        "target_pack_ids": [],
        "completed_pack_ids": [],
        "failed_pack_id": null
    }))
    .unwrap()
}

fn vault_checkpoint(issued: bool, stage: KmsReconcileStage) -> KmsRotationCheckpoint {
    KmsRotationCheckpoint {
        rotation_id: Uuid::new_v4(),
        repo: Uuid::new_v4(),
        from_key_id: "pando-vault-key".to_owned(),
        from_key_version: 3,
        to_key_id: "pando-vault-key".to_owned(),
        to_key_version: 4,
        state: "IN_PROGRESS".to_owned(),
        revoke_previous: false,
        target_pack_ids: Vec::new(),
        completed_pack_ids: Vec::new(),
        failed_pack_id: None,
        from_provider_kind: super::super::provider::PROVIDER_KIND_VAULT.to_owned(),
        to_provider_kind: super::super::provider::PROVIDER_KIND_VAULT.to_owned(),
        expected_to_version: 4,
        external_rotate_issued: issued,
        reconcile_stage: stage,
        target_contract: "existing-vault-version/v1".to_owned(),
        write_epoch: 1,
    }
}

#[test]
fn old_local_checkpoint_defaults_are_compatible() {
    let cp = legacy_checkpoint();
    assert_eq!(cp.from_provider_kind, super::super::provider::PROVIDER_KIND_LOCAL);
    assert_eq!(cp.to_provider_kind, super::super::provider::PROVIDER_KIND_LOCAL);
    assert_eq!(cp.expected_version(), 2);
    assert!(!cp.external_rotate_issued);
    assert_eq!(cp.reconcile_stage, KmsReconcileStage::NotIssued);
    assert!(!cp.is_vault_target());
}

#[test]
fn vault_checkpoint_roundtrips_through_json() {
    let cp = vault_checkpoint(true, KmsReconcileStage::RotateIssued);
    let encoded = serde_json::to_vec(&cp).unwrap();
    let decoded: KmsRotationCheckpoint = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded.from_provider_kind, super::super::provider::PROVIDER_KIND_VAULT);
    assert_eq!(decoded.to_provider_kind, super::super::provider::PROVIDER_KIND_VAULT);
    assert_eq!(decoded.expected_to_version, 4);
    assert!(decoded.external_rotate_issued);
    assert_eq!(decoded.reconcile_stage, KmsReconcileStage::RotateIssued);
}

#[test]
fn existing_target_contract_versions_and_legacy_checkpoints_are_checked() {
    let cp = vault_checkpoint(false, KmsReconcileStage::TargetObserved);
    assert!(ensure_existing_target_contract(&cp).is_ok());
    assert!(ensure_target_available(4, 4, 0).is_ok());
    assert!(ensure_target_available(4, 6, 0).is_ok());
    assert!(ensure_target_available(4, 6, 4).is_ok());
    assert!(ensure_target_available(4, 3, 0).is_err());
    assert!(ensure_target_available(4, 6, 5).is_err());
    assert!(ensure_no_version_downgrade(super::super::provider::PROVIDER_KIND_VAULT, "k", 6, "k", 4).is_err());
    assert!(ensure_no_version_downgrade(super::super::provider::PROVIDER_KIND_VAULT, "k", 4, "k", 4).is_ok());
    assert!(ensure_no_version_downgrade(super::super::provider::PROVIDER_KIND_LOCAL, "l", 6, "k", 4).is_ok());
    let mut legacy = cp;
    legacy.target_contract.clear();
    assert!(ensure_existing_target_contract(&legacy).is_err());
}

#[test]
fn vault_retention_changes_are_refused() {
    let mut opts = KmsRotateOptions::default();
    assert!(ensure_vault_retention_option(&opts).is_ok());
    opts.revoke_previous = true;
    assert!(ensure_vault_retention_option(&opts).is_err());
}
