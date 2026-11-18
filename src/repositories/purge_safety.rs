//! Fail-closed final purge safety evaluation and shared-object planning (#85).
use crate::storage::remote_objects::ObjectKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurgeHoldKind {
    NotSoftDeleted,
    RecoveryWindowOpen,
    PgRefstoreImmutable,
    ActiveTransfer,
    BackupRetentionRoot,
    ActiveReadLease,
    ActiveWriteAdmission,
    ActiveStorageMaintenance,
    PhysicalGcFence,
    ActiveCiPin,
    ActiveCiCheckoutLease,
    ArtifactHold,
    PendingPublicationFence,
    RecoveryResolutionHistory,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeHold {
    pub kind: PurgeHoldKind,
    pub detail: String,
    pub blocking_count: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PurgePreconditions {
    pub deleted: bool,
    pub recovery_window_elapsed: bool,
    pub is_pg_refstore: bool,
    pub active_transfer_count: usize,
    pub backup_retention_roots: usize,
    pub active_read_leases: usize,
    pub active_write_admissions: usize,
    pub active_maintenance_jobs: usize,
    pub physical_gc_fenced: bool,
    pub active_ci_pins: usize,
    pub active_ci_checkout_leases: usize,
    pub active_artifact_holds: usize,
    pub pending_publication_fences: usize,
    pub recovery_resolutions: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeEvaluation {
    pub allowed: bool,
    pub holds: Vec<PurgeHold>,
}

pub fn evaluate_purge_holds(p: &PurgePreconditions) -> PurgeEvaluation {
    let mut holds = Vec::new();
    let mut push = |kind, count: usize, detail: &str| {
        if count > 0 {
            holds.push(PurgeHold { kind, detail: detail.to_owned(), blocking_count: count });
        }
    };
    if !p.deleted {
        push(PurgeHoldKind::NotSoftDeleted, 1, "repository must be soft-deleted before final purge");
    } else if !p.recovery_window_elapsed {
        push(PurgeHoldKind::RecoveryWindowOpen, 1, "repository recovery grace window has not elapsed");
    }
    if p.is_pg_refstore {
        push(PurgeHoldKind::PgRefstoreImmutable, 1, "pg_refstore repositories refuse destructive final purge");
    }
    push(PurgeHoldKind::ActiveTransfer, p.active_transfer_count, "ownership transfer is active");
    push(
        PurgeHoldKind::BackupRetentionRoot,
        p.backup_retention_roots,
        "repository objects are pinned by active backup or PITR retention roots",
    );
    push(PurgeHoldKind::ActiveReadLease, p.active_read_leases, "active serving read lease holds repository");
    push(
        PurgeHoldKind::ActiveWriteAdmission,
        p.active_write_admissions,
        "active storage write admission holds repository",
    );
    push(
        PurgeHoldKind::ActiveStorageMaintenance,
        p.active_maintenance_jobs,
        "storage maintenance job is queued or running",
    );
    if p.physical_gc_fenced {
        push(PurgeHoldKind::PhysicalGcFence, 1, "physical GC lease fences repository");
    }
    push(PurgeHoldKind::ActiveCiPin, p.active_ci_pins, "active CI retention pin protects commits");
    push(
        PurgeHoldKind::ActiveCiCheckoutLease,
        p.active_ci_checkout_leases,
        "active CI checkout job or lease protects repository",
    );
    push(PurgeHoldKind::ArtifactHold, p.active_artifact_holds, "active artifact hold blocks purge");
    push(
        PurgeHoldKind::PendingPublicationFence,
        p.pending_publication_fences,
        "active Pando publication fence protects objects",
    );
    push(
        PurgeHoldKind::RecoveryResolutionHistory,
        p.recovery_resolutions,
        "immutable recovery or operation resolution history blocks purge",
    );
    PurgeEvaluation { allowed: holds.is_empty(), holds }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemoteDeletePlan {
    pub deletable_lfs_keys: Vec<String>,
    pub preserved_shared_lfs_keys: Vec<String>,
    pub deletable_workspace_keys: Vec<String>,
    pub preserved_shared_workspace_keys: Vec<String>,
    pub retirable_pando_paths: Vec<String>,
    pub preserved_shared_pando_paths: Vec<String>,
}

/// Partition candidate remote objects belonging to `tenant_id` into exclusively
/// owned objects safe to queue/delete vs objects referenced by any other repo,
/// other tenant, or external retention pin.
pub fn plan_safe_remote_cleanup(
    tenant_id: Uuid,
    repo_lfs_oids: &[String],
    shared_lfs_oids: &BTreeSet<String>,
    repo_workspace_digests: &[String],
    shared_workspace_digests: &BTreeSet<String>,
    repo_pando_paths: &[(String, bool)],
) -> RemoteDeletePlan {
    let mut plan = RemoteDeletePlan::default();
    let mut seen_lfs = BTreeSet::new();
    for oid in repo_lfs_oids {
        if !seen_lfs.insert(oid.as_str()) {
            continue;
        }
        let Ok(key) = ObjectKey::new(tenant_id, "lfs", oid) else {
            continue;
        };
        if shared_lfs_oids.contains(oid) {
            plan.preserved_shared_lfs_keys.push(key.path());
        } else {
            plan.deletable_lfs_keys.push(key.path());
        }
    }
    let mut seen_ws = BTreeSet::new();
    for digest in repo_workspace_digests {
        if !seen_ws.insert(digest.as_str()) {
            continue;
        }
        let Ok(key) = ObjectKey::new(tenant_id, "workspace", digest) else {
            continue;
        };
        if shared_workspace_digests.contains(digest) {
            plan.preserved_shared_workspace_keys.push(key.path());
        } else {
            plan.deletable_workspace_keys.push(key.path());
        }
    }
    for (path, shared_or_legacy) in repo_pando_paths {
        // Authority-scoped objects alone may retire; legacy tenant-only paths and
        // artifacts shared with another repo/manifest are never deleted.
        let expected_prefix = format!("tenants/{tenant_id}/authorities/");
        if *shared_or_legacy || !path.starts_with(&expected_prefix) {
            plan.preserved_shared_pando_paths.push(path.clone());
        } else {
            plan.retirable_pando_paths.push(path.clone());
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_evaluation_blocks_every_protected_resource() {
        let ok = PurgePreconditions { deleted: true, recovery_window_elapsed: true, ..Default::default() };
        assert!(evaluate_purge_holds(&ok).allowed);

        let blocked = PurgePreconditions {
            deleted: true,
            recovery_window_elapsed: false,
            backup_retention_roots: 1,
            active_read_leases: 2,
            active_ci_pins: 1,
            active_ci_checkout_leases: 1,
            ..Default::default()
        };
        let eval = evaluate_purge_holds(&blocked);
        assert!(!eval.allowed);
        let kinds: Vec<_> = eval.holds.iter().map(|h| h.kind).collect();
        assert!(kinds.contains(&PurgeHoldKind::RecoveryWindowOpen));
        assert!(kinds.contains(&PurgeHoldKind::BackupRetentionRoot));
        assert!(kinds.contains(&PurgeHoldKind::ActiveReadLease));
        assert!(kinds.contains(&PurgeHoldKind::ActiveCiPin));
        assert!(kinds.contains(&PurgeHoldKind::ActiveCiCheckoutLease));
    }

    #[test]
    fn shared_remote_cleanup_preserves_shared_and_cross_tenant_or_legacy_objects() {
        let tenant = Uuid::new_v4();
        let other = Uuid::new_v4();
        let auth = Uuid::new_v4();
        let shared_oid = "1".repeat(64);
        let unique_oid = "2".repeat(64);
        let ws_shared = "3".repeat(64);
        let ws_unique = "4".repeat(64);
        let pando_owned = format!("tenants/{tenant}/authorities/{auth}/g1/pando-cipher/{unique_oid}");
        let pando_shared = format!("tenants/{tenant}/authorities/{auth}/g1/pando-cipher/{shared_oid}");
        let pando_other_tenant = format!("tenants/{other}/authorities/{auth}/g1/pando-cipher/{unique_oid}");
        let pando_legacy = format!("tenants/{tenant}/pando-cipher/{unique_oid}");

        let plan = plan_safe_remote_cleanup(
            tenant,
            &[shared_oid.clone(), unique_oid.clone()],
            &BTreeSet::from([shared_oid.clone()]),
            &[ws_shared.clone(), ws_unique.clone()],
            &BTreeSet::from([ws_shared.clone()]),
            &[
                (pando_owned.clone(), false),
                (pando_shared.clone(), true),
                (pando_other_tenant.clone(), false),
                (pando_legacy.clone(), false),
            ],
        );
        assert_eq!(plan.deletable_lfs_keys, vec![format!("tenants/{tenant}/lfs/{unique_oid}")]);
        assert_eq!(plan.preserved_shared_lfs_keys, vec![format!("tenants/{tenant}/lfs/{shared_oid}")]);
        assert_eq!(plan.deletable_workspace_keys, vec![format!("tenants/{tenant}/workspace/{ws_unique}")]);
        assert_eq!(plan.preserved_shared_workspace_keys, vec![format!("tenants/{tenant}/workspace/{ws_shared}")]);
        assert_eq!(plan.retirable_pando_paths, vec![pando_owned]);
        assert_eq!(plan.preserved_shared_pando_paths, vec![pando_shared, pando_other_tenant, pando_legacy]);
    }
}
