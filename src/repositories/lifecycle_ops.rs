//! Lifecycle response DTOs, CAS/idempotency framing, and pure state-transition helpers (#85).
use super::{
    lifecycle::{IdempotencyDecision, LifecycleAction, check_cas_version, evaluate_idempotency},
    purge_safety::PurgeHold,
};
use crate::Error;
use axum::{
    Json,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteRepoResponse {
    pub deleted: bool,
    pub deleted_at: String,
    pub purge_after: String,
    pub version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeBlockedResponse {
    pub error: String,
    pub holds: Vec<PurgeHold>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeRepoResponse {
    pub purged: bool,
    pub repository_id: Uuid,
    pub deleted_lfs_keys: usize,
    pub preserved_shared_lfs_keys: usize,
    pub deleted_workspace_keys: usize,
    pub preserved_shared_workspace_keys: usize,
    pub retired_pando_paths: usize,
    pub preserved_shared_pando_paths: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasDeleteResponse {
    pub deleted: bool,
    pub owner: String,
    pub name: String,
}

/// Normalize CAS + Idempotency-Key evaluation before applying a repository
/// lifecycle state transition inside a `FOR UPDATE` PostgreSQL transaction.
pub fn decide_idempotent_cas(
    stored: Option<(&str, i16, &Value)>,
    incoming_hash: &str,
    actual_version: i64,
    expected_version: i64,
) -> Result<Option<(StatusCode, Value)>, Error> {
    if let Some((stored_hash, stored_status, stored_body)) = stored {
        return match evaluate_idempotency(Some(stored_hash), incoming_hash) {
            IdempotencyDecision::Replay => {
                let status = u16::try_from(stored_status)
                    .ok()
                    .and_then(|code| StatusCode::from_u16(code).ok())
                    .ok_or_else(|| Error::internal("invalid stored status"))?;
                Ok(Some((status, stored_body.clone())))
            }
            IdempotencyDecision::Mismatch => {
                Err(Error(StatusCode::CONFLICT, "idempotency key reused with different request parameters"))
            }
            IdempotencyDecision::Fresh => {
                check_cas_version(actual_version, expected_version)?;
                Ok(None)
            }
        };
    }
    check_cas_version(actual_version, expected_version)?;
    Ok(None)
}

pub fn json_no_store<T: Serialize>(status: StatusCode, payload: &T) -> Result<Response, Error> {
    let value = serde_json::to_value(payload).map_err(Error::internal)?;
    Ok((status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response())
}

pub fn lifecycle_action_audit_name(action: LifecycleAction) -> &'static str {
    match action {
        LifecycleAction::Archive => "repository.archived",
        LifecycleAction::Unarchive => "repository.unarchived",
        LifecycleAction::Rename => "repository.renamed",
        LifecycleAction::Delete => "repository.soft_deleted",
        LifecycleAction::Restore => "repository.restored",
        LifecycleAction::Purge => "repository.purged",
        LifecycleAction::Transfer => "repository.transferred",
    }
}

pub fn require_idempotency_key_valid(headers: &HeaderMap) -> Result<Option<String>, Error> {
    Ok(crate::auth::idempotency_key(headers)?.map(ToOwned::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::purge_safety::PurgeHoldKind;

    #[test]
    fn reject_unknown_fields_on_lifecycle_responses() {
        assert!(
            serde_json::from_str::<DeleteRepoResponse>(
                r#"{"deleted":true,"deleted_at":"2026-01-01T00:00:00Z","purge_after":"2026-01-08T00:00:00Z","version":2,"x":1}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<AliasDeleteResponse>(r#"{"deleted":true,"owner":"a","name":"b","x":1}"#).is_err()
        );
        assert!(serde_json::from_str::<PurgeBlockedResponse>(r#"{"error":"blocked","holds":[],"x":1}"#).is_err());
    }

    #[test]
    fn idempotent_cas_replays_after_version_bump_and_rejects_mismatch() {
        let saved_body = serde_json::json!({"deleted": true, "version": 4});
        let replay = decide_idempotent_cas(Some(("abc", 200, &saved_body)), "abc", 4, 3).unwrap();
        assert_eq!(replay, Some((StatusCode::OK, saved_body.clone())));

        let mismatch = decide_idempotent_cas(Some(("abc", 200, &saved_body)), "def", 4, 3).unwrap_err();
        assert_eq!(mismatch.0, StatusCode::CONFLICT);

        let fresh_conflict = decide_idempotent_cas(None, "abc", 4, 3).unwrap_err();
        assert_eq!(fresh_conflict.0, StatusCode::CONFLICT);

        assert_eq!(decide_idempotent_cas(None, "abc", 3, 3).unwrap(), None);
    }

    #[test]
    fn blocked_purge_serializes_structured_holds() {
        let resp = PurgeBlockedResponse {
            error: "final purge blocked by active holds".into(),
            holds: vec![PurgeHold {
                kind: PurgeHoldKind::BackupRetentionRoot,
                detail: "active root".into(),
                blocking_count: 1,
            }],
        };
        let encoded = serde_json::to_value(&resp).unwrap();
        assert_eq!(encoded["holds"][0]["kind"], "backup_retention_root");
        assert_eq!(lifecycle_action_audit_name(LifecycleAction::Purge), "repository.purged");
    }
}
