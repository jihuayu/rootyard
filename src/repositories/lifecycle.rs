//! Repository lifecycle state rules, CAS/idempotency contracts, and input models (#85).
use crate::{Error, db};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const DEFAULT_DELETE_GRACE_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const MAX_DELETE_GRACE_SECONDS: i64 = 365 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Archive,
    Unarchive,
    Rename,
    Delete,
    Restore,
    Purge,
    Transfer,
}

impl LifecycleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Unarchive => "unarchive",
            Self::Rename => "rename",
            Self::Delete => "delete",
            Self::Restore => "restore",
            Self::Purge => "purge",
            Self::Transfer => "transfer",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRepoInput {
    pub expected_version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnarchiveRepoInput {
    pub expected_version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenameRepoInput {
    pub new_name: String,
    pub expected_version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeleteRepoInput {
    pub expected_version: i64,
    pub grace_period_seconds: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreRepoInput {
    pub expected_version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PurgeRepoInput {
    pub expected_version: i64,
    pub confirm_repository: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAliasView {
    pub owner: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryLifecycleView {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub owner: String,
    pub name: String,
    pub version: i64,
    pub state: String,
    pub storage_backend: String,
    pub storage_generation: i64,
    pub object_format: String,
    pub archived: bool,
    pub archived_at: Option<String>,
    pub deleted: bool,
    pub deleted_at: Option<String>,
    pub purge_after: Option<String>,
    pub aliases: Vec<RepositoryAliasView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdempotencyDecision {
    Fresh,
    Replay,
    Mismatch,
}

pub fn validate_expected_version(expected_version: i64) -> Result<(), Error> {
    if expected_version <= 0 {
        return Err(Error::bad_request());
    }
    Ok(())
}

pub fn validate_grace_period(seconds: Option<i64>) -> Result<i64, Error> {
    let grace = seconds.unwrap_or(DEFAULT_DELETE_GRACE_SECONDS);
    if !(0..=MAX_DELETE_GRACE_SECONDS).contains(&grace) {
        return Err(Error::bad_request());
    }
    Ok(grace)
}

pub fn validate_rename_input(current_name: &str, input: &RenameRepoInput) -> Result<(), Error> {
    validate_expected_version(input.expected_version)?;
    if !db::valid_name(&input.new_name) {
        return Err(Error::bad_request());
    }
    if input.new_name == current_name {
        return Err(Error(StatusCode::CONFLICT, "new repository name matches current name"));
    }
    Ok(())
}

pub fn validate_purge_confirmation(owner: &str, name: &str, input: &PurgeRepoInput) -> Result<(), Error> {
    validate_expected_version(input.expected_version)?;
    let expected = format!("{owner}/{name}");
    if input.confirm_repository != expected {
        return Err(Error(StatusCode::CONFLICT, "purge confirmation must match owner/name"));
    }
    Ok(())
}

pub fn check_cas_version(actual_version: i64, expected_version: i64) -> Result<(), Error> {
    validate_expected_version(expected_version)?;
    if actual_version != expected_version {
        return Err(Error(StatusCode::CONFLICT, "repository version conflict"));
    }
    Ok(())
}

pub fn enforce_mutating_availability(deleted: bool, archived: bool, transfer_in_progress: bool) -> Result<(), Error> {
    if deleted {
        return Err(Error::not_found());
    }
    if transfer_in_progress {
        return Err(Error(StatusCode::CONFLICT, "repository ownership transfer in progress"));
    }
    if archived {
        return Err(Error(StatusCode::FORBIDDEN, "repository is archived and read-only"));
    }
    Ok(())
}

pub fn request_sha256<T: Serialize>(value: &T) -> Result<String, Error> {
    let bytes = serde_json::to_vec(value).map_err(Error::internal)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

pub fn evaluate_idempotency(stored_hash: Option<&str>, incoming_hash: &str) -> IdempotencyDecision {
    match stored_hash {
        None => IdempotencyDecision::Fresh,
        Some(prev) if prev == incoming_hash => IdempotencyDecision::Replay,
        Some(_) => IdempotencyDecision::Mismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_unknown_fields_on_lifecycle_inputs() {
        assert!(serde_json::from_str::<ArchiveRepoInput>(r#"{"expected_version":1,"extra":true}"#).is_err());
        assert!(serde_json::from_str::<UnarchiveRepoInput>(r#"{"expected_version":1,"x":1}"#).is_err());
        assert!(serde_json::from_str::<RenameRepoInput>(r#"{"new_name":"beta","expected_version":1,"x":1}"#).is_err());
        assert!(serde_json::from_str::<DeleteRepoInput>(r#"{"expected_version":1,"x":1}"#).is_err());
        assert!(serde_json::from_str::<RestoreRepoInput>(r#"{"expected_version":1,"x":1}"#).is_err());
        assert!(
            serde_json::from_str::<PurgeRepoInput>(r#"{"expected_version":1,"confirm_repository":"a/b","x":1}"#)
                .is_err()
        );
    }

    #[test]
    fn rename_and_purge_validators_enforce_invariants() {
        let same = RenameRepoInput { new_name: "alpha".into(), expected_version: 1 };
        assert_eq!(validate_rename_input("alpha", &same).unwrap_err().0, StatusCode::CONFLICT);
        let bad = RenameRepoInput { new_name: "../escape".into(), expected_version: 1 };
        assert_eq!(validate_rename_input("alpha", &bad).unwrap_err().0, StatusCode::BAD_REQUEST);
        let ok = RenameRepoInput { new_name: "beta".into(), expected_version: 2 };
        assert!(validate_rename_input("alpha", &ok).is_ok());

        let wrong_purge = PurgeRepoInput { expected_version: 3, confirm_repository: "alice/other".into() };
        assert_eq!(validate_purge_confirmation("alice", "alpha", &wrong_purge).unwrap_err().0, StatusCode::CONFLICT);
        let ok_purge = PurgeRepoInput { expected_version: 3, confirm_repository: "alice/alpha".into() };
        assert!(validate_purge_confirmation("alice", "alpha", &ok_purge).is_ok());
    }

    #[test]
    fn availability_fence_blocks_deleted_transfer_and_archived() {
        assert_eq!(enforce_mutating_availability(true, false, false).unwrap_err().0, StatusCode::NOT_FOUND);
        assert_eq!(enforce_mutating_availability(false, true, true).unwrap_err().0, StatusCode::CONFLICT);
        assert_eq!(enforce_mutating_availability(false, true, false).unwrap_err().0, StatusCode::FORBIDDEN);
        assert!(enforce_mutating_availability(false, false, false).is_ok());
    }

    #[test]
    fn idempotency_digest_distinguishes_replay_vs_conflict() {
        let a = RenameRepoInput { new_name: "beta".into(), expected_version: 1 };
        let b = RenameRepoInput { new_name: "gamma".into(), expected_version: 1 };
        let ha = request_sha256(&a).unwrap();
        let hb = request_sha256(&b).unwrap();
        assert_eq!(evaluate_idempotency(None, &ha), IdempotencyDecision::Fresh);
        assert_eq!(evaluate_idempotency(Some(&ha), &ha), IdempotencyDecision::Replay);
        assert_eq!(evaluate_idempotency(Some(&ha), &hb), IdempotencyDecision::Mismatch);
    }

    #[test]
    fn grace_period_bounds_reject_negative_or_unbounded() {
        assert_eq!(validate_grace_period(None).unwrap(), DEFAULT_DELETE_GRACE_SECONDS);
        assert_eq!(validate_grace_period(Some(0)).unwrap(), 0);
        assert!(validate_grace_period(Some(-1)).is_err());
        assert!(validate_grace_period(Some(MAX_DELETE_GRACE_SECONDS + 1)).is_err());
    }
}
