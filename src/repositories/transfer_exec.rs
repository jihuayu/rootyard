//! Ownership transfer authorization planning, safe rollback/post-commit remote
//! key planning, and durable transition state helpers (#85).
use super::transfer_model::{CopiedRemoteObject, TransferPhase, TransferStatusView};
use crate::{Error, storage::remote_objects::ObjectKey};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceKind {
    User,
    Organization,
}

impl NamespaceKind {
    pub fn parse(raw: &str) -> Result<Self, Error> {
        match raw {
            "user" => Ok(Self::User),
            "organization" => Ok(Self::Organization),
            _ => Err(Error::internal("invalid namespace kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferAuditSummary {
    pub transfer_id: Uuid,
    pub repository_id: Uuid,
    pub from_owner: String,
    pub to_owner: String,
    pub old_name: String,
    pub new_name: String,
    pub revoke_collaborators: bool,
    pub copied_objects: usize,
    pub cleaned_legacy_objects: usize,
}

/// Verify ownership transfer target namespace permission rules:
/// - Target personal (`user`) namespace is allowed only when the initiating
///   admin actor owns that personal namespace (`target_user_id == actor_id`).
/// - Target `organization` namespace requires the actor to hold at least
///   `maintain` role in the destination organization.
pub fn check_target_namespace_authority(
    actor_id: Uuid,
    target_kind: NamespaceKind,
    target_user_id: Option<Uuid>,
    target_org_allows_create: bool,
) -> Result<(), Error> {
    match target_kind {
        NamespaceKind::User => {
            if target_user_id == Some(actor_id) {
                Ok(())
            } else {
                Err(Error(StatusCode::FORBIDDEN, "personal ownership transfer requires target user identity"))
            }
        }
        NamespaceKind::Organization => {
            if target_org_allows_create {
                Ok(())
            } else {
                Err(Error(StatusCode::FORBIDDEN, "organization maintain role required in target namespace"))
            }
        }
    }
}

/// Partition `(kind, ObjectKey)` pairs created in `to_tenant` that can be safely
/// deleted if transfer rolls back BEFORE `rekeying_db` commits, excluding any key
/// already shared by another repository under `to_tenant`.
pub fn plan_rollback_cleanup_keys(
    to_tenant: Uuid,
    copied: &[CopiedRemoteObject],
    shared_to_paths: &BTreeSet<String>,
) -> Vec<(String, ObjectKey)> {
    plan_side_cleanup_keys(to_tenant, copied, true, shared_to_paths)
}

/// Partition `(kind, ObjectKey)` pairs left under `from_tenant` that can be
/// safely retired AFTER `rekeying_db` has durably committed to `to_tenant`,
/// preserving every key still referenced by another repo or PITR root under `from_tenant`.
pub fn plan_post_commit_legacy_keys(
    from_tenant: Uuid,
    copied: &[CopiedRemoteObject],
    shared_from_paths: &BTreeSet<String>,
) -> Vec<(String, ObjectKey)> {
    plan_side_cleanup_keys(from_tenant, copied, false, shared_from_paths)
}

fn plan_side_cleanup_keys(
    tenant: Uuid,
    copied: &[CopiedRemoteObject],
    use_destination: bool,
    preserved_paths: &BTreeSet<String>,
) -> Vec<(String, ObjectKey)> {
    let prefix = format!("tenants/{tenant}/");
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in copied {
        let raw_path = if use_destination { &item.to_key } else { &item.from_key };
        if preserved_paths.contains(raw_path) || !raw_path.starts_with(&prefix) || !seen.insert(raw_path.clone()) {
            continue;
        }
        if let Some(key) = parse_tenant_key(tenant, raw_path) {
            out.push((item.kind.clone(), key));
        }
    }
    out
}

fn parse_tenant_key(tenant: Uuid, raw_path: &str) -> Option<ObjectKey> {
    let prefix = format!("tenants/{tenant}/");
    let rest = raw_path.strip_prefix(&prefix)?;
    if let Some(after_auth) = rest.strip_prefix("authorities/") {
        let mut parts = after_auth.split('/');
        let auth_id = Uuid::parse_str(parts.next()?).ok()?;
        let gen_seg = parts.next()?;
        let generation: i64 = gen_seg.strip_prefix('g')?.parse().ok()?;
        let namespace = parts.next()?;
        let sha256 = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        return ObjectKey::scoped(tenant, auth_id, generation, namespace, sha256).ok();
    }
    let (namespace, sha256) = rest.split_once('/')?;
    if sha256.contains('/') {
        return None;
    }
    ObjectKey::new(tenant, namespace, sha256).ok()
}

pub fn http_status_for_transfer_phase(phase: TransferPhase) -> StatusCode {
    match phase {
        TransferPhase::Completed | TransferPhase::RolledBack | TransferPhase::Failed => StatusCode::OK,
        _ => StatusCode::ACCEPTED,
    }
}

pub fn transfer_view_is_active(view: &TransferStatusView) -> bool {
    !view.state.is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_namespace_authority_enforces_personal_and_org_rules() {
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        assert!(check_target_namespace_authority(alice, NamespaceKind::User, Some(alice), false).is_ok());
        assert_eq!(
            check_target_namespace_authority(alice, NamespaceKind::User, Some(bob), true).unwrap_err().0,
            StatusCode::FORBIDDEN
        );
        assert!(check_target_namespace_authority(alice, NamespaceKind::Organization, None, true).is_ok());
        assert_eq!(
            check_target_namespace_authority(alice, NamespaceKind::Organization, None, false).unwrap_err().0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn rollback_and_post_commit_cleanup_preserve_shared_and_cross_tenant_keys() {
        let from = Uuid::new_v4();
        let to = Uuid::new_v4();
        let auth = Uuid::new_v4();
        let h1 = "1".repeat(64);
        let h2 = "2".repeat(64);
        let p_from_shared = format!("tenants/{from}/lfs/{h1}");
        let p_to_shared = format!("tenants/{to}/lfs/{h1}");
        let p_from_unique = format!("tenants/{from}/authorities/{auth}/g2/pando-cipher/{h2}");
        let p_to_unique = format!("tenants/{to}/authorities/{auth}/g1/pando-cipher/{h2}");

        let copied = vec![
            CopiedRemoteObject {
                kind: "lfs".into(),
                from_key: p_from_shared.clone(),
                to_key: p_to_shared.clone(),
                size: 10,
                sha256: Some(h1.clone()),
            },
            CopiedRemoteObject {
                kind: "pando_cipher".into(),
                from_key: p_from_unique.clone(),
                to_key: p_to_unique.clone(),
                size: 20,
                sha256: Some(h2.clone()),
            },
        ];

        let rollback = plan_rollback_cleanup_keys(to, &copied, &BTreeSet::from([p_to_shared]));
        assert_eq!(rollback.len(), 1);
        assert_eq!(rollback[0].1.path(), p_to_unique);

        let post_commit = plan_post_commit_legacy_keys(from, &copied, &BTreeSet::from([p_from_shared]));
        assert_eq!(post_commit.len(), 1);
        assert_eq!(post_commit[0].1.path(), p_from_unique);
    }

    #[test]
    fn transfer_audit_summary_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<TransferAuditSummary>(
                r#"{"transfer_id":"00000000-0000-0000-0000-000000000000","repository_id":"00000000-0000-0000-0000-000000000000","from_owner":"a","to_owner":"b","old_name":"r","new_name":"r","revoke_collaborators":true,"copied_objects":0,"cleaned_legacy_objects":0,"extra":1}"#
            )
            .is_err()
        );
        assert_eq!(http_status_for_transfer_phase(TransferPhase::Completed), StatusCode::OK);
        assert_eq!(http_status_for_transfer_phase(TransferPhase::CopyingRemote), StatusCode::ACCEPTED);
    }
}
