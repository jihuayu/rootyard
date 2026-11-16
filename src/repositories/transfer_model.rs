//! Crash-recoverable repository ownership transfer state machine and key planning (#85).
use crate::{Error, db, storage::remote_objects::ObjectKey, workspaces::remote::RemoteManifest};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferInput {
    pub new_owner: String,
    pub new_name: Option<String>,
    pub expected_version: Option<i64>,
    pub revoke_collaborators: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferPhase {
    Preparing,
    Draining,
    CopyingRemote,
    RekeyingDb,
    RevokingLegacy,
    Completed,
    RollingBack,
    RolledBack,
    Failed,
}

impl TransferPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Draining => "draining",
            Self::CopyingRemote => "copying_remote",
            Self::RekeyingDb => "rekeying_db",
            Self::RevokingLegacy => "revoking_legacy",
            Self::Completed => "completed",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::Failed => "failed",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "preparing" => Some(Self::Preparing),
            "draining" => Some(Self::Draining),
            "copying_remote" => Some(Self::CopyingRemote),
            "rekeying_db" => Some(Self::RekeyingDb),
            "revoking_legacy" => Some(Self::RevokingLegacy),
            "completed" => Some(Self::Completed),
            "rolling_back" => Some(Self::RollingBack),
            "rolled_back" => Some(Self::RolledBack),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::RolledBack | Self::Failed)
    }

    /// Before `RekeyingDb` commits in PostgreSQL, `from_owner_id` remains the sole
    /// authoritative owner; once `RekeyingDb` commits (`RevokingLegacy` / `Completed`),
    /// `to_owner_id` is the sole authoritative owner.
    pub fn owner_committed_to_target(self) -> bool {
        matches!(self, Self::RevokingLegacy | Self::Completed)
    }

    pub fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Preparing, Self::Draining | Self::RollingBack)
                | (Self::Draining, Self::CopyingRemote | Self::RollingBack)
                | (Self::CopyingRemote, Self::RekeyingDb | Self::RollingBack)
                | (Self::RekeyingDb, Self::RevokingLegacy | Self::RollingBack)
                | (Self::RevokingLegacy, Self::Completed | Self::Failed)
                | (Self::RollingBack, Self::RolledBack | Self::Failed)
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CopiedRemoteObject {
    pub kind: String,
    pub from_key: String,
    pub to_key: String,
    pub size: u64,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferStatusView {
    pub transfer_id: Uuid,
    pub repository_id: Uuid,
    pub from_owner_id: Uuid,
    pub to_owner_id: Uuid,
    pub from_owner: String,
    pub to_owner: String,
    pub old_name: String,
    pub new_name: String,
    pub state: TransferPhase,
    pub revoke_collaborators: bool,
    pub copied_object_count: usize,
    pub version: i64,
    pub last_error: Option<String>,
}

pub fn validate_transfer_input(
    current_owner: &str,
    current_name: &str,
    input: &TransferInput,
) -> Result<(String, bool), Error> {
    if !db::valid_name(&input.new_owner) {
        return Err(Error::bad_request());
    }
    let Some(expected_version) = input.expected_version else {
        return Err(Error(StatusCode::CONFLICT, "expected_version is required for repository ownership transfer"));
    };
    if expected_version <= 0 {
        return Err(Error::bad_request());
    }
    let target_name = input.new_name.as_deref().unwrap_or(current_name);
    if !db::valid_name(target_name) {
        return Err(Error::bad_request());
    }
    if input.new_owner == current_owner && target_name == current_name {
        return Err(Error(StatusCode::CONFLICT, "target owner and name match current repository"));
    }
    Ok((target_name.to_owned(), input.revoke_collaborators.unwrap_or(true)))
}

pub fn plan_lfs_copy(from_tenant: Uuid, to_tenant: Uuid, oid: &str) -> Result<(ObjectKey, ObjectKey), Error> {
    let src = ObjectKey::new(from_tenant, "lfs", oid).map_err(Error::internal)?;
    let dst = ObjectKey::new(to_tenant, "lfs", oid).map_err(Error::internal)?;
    Ok((src, dst))
}

pub fn plan_workspace_blob_copy(
    from_tenant: Uuid,
    to_tenant: Uuid,
    digest: &str,
) -> Result<(ObjectKey, ObjectKey), Error> {
    let src = ObjectKey::new(from_tenant, "workspace", digest).map_err(Error::internal)?;
    let dst = ObjectKey::new(to_tenant, "workspace", digest).map_err(Error::internal)?;
    Ok((src, dst))
}

/// Update a serialized `RemoteManifest`'s `tenant_id` to `to_tenant` and return
/// `(new_manifest_bytes, new_manifest_sha256, destination_key)`.
pub(crate) fn rekey_workspace_manifest(
    mut manifest: RemoteManifest,
    to_tenant: Uuid,
) -> Result<(Vec<u8>, String, ObjectKey), Error> {
    manifest.tenant_id = to_tenant;
    let bytes = serde_json::to_vec(&manifest).map_err(Error::internal)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let dst = ObjectKey::new(to_tenant, "workspace", &digest).map_err(Error::internal)?;
    Ok((bytes, digest, dst))
}

pub fn plan_pando_copy(
    from_tenant: Uuid,
    to_tenant: Uuid,
    authority_id: Option<(Uuid, i64, i64)>,
    namespace: &str,
    sha256: &str,
) -> Result<(ObjectKey, ObjectKey), Error> {
    let (src, dst) = match authority_id {
        Some((auth_id, src_gen, dst_gen)) => (
            ObjectKey::scoped(from_tenant, auth_id, src_gen, namespace, sha256).map_err(Error::internal)?,
            ObjectKey::scoped(to_tenant, auth_id, dst_gen, namespace, sha256).map_err(Error::internal)?,
        ),
        None => (
            ObjectKey::new(from_tenant, namespace, sha256).map_err(Error::internal)?,
            ObjectKey::new(to_tenant, namespace, sha256).map_err(Error::internal)?,
        ),
    };
    Ok((src, dst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_unknown_fields_and_missing_cas() {
        assert!(serde_json::from_str::<TransferInput>(r#"{"new_owner":"org","x":1}"#).is_err());
        let no_cas = TransferInput {
            new_owner: "org".into(),
            new_name: None,
            expected_version: None,
            revoke_collaborators: None,
        };
        assert_eq!(validate_transfer_input("alice", "app", &no_cas).unwrap_err().0, StatusCode::CONFLICT);
        let zero_cas = TransferInput { expected_version: Some(0), ..no_cas.clone() };
        assert_eq!(validate_transfer_input("alice", "app", &zero_cas).unwrap_err().0, StatusCode::BAD_REQUEST);
        let same_target = TransferInput {
            new_owner: "alice".into(),
            new_name: None,
            expected_version: Some(1),
            revoke_collaborators: None,
        };
        assert_eq!(validate_transfer_input("alice", "app", &same_target).unwrap_err().0, StatusCode::CONFLICT);
        let valid = TransferInput {
            new_owner: "org".into(),
            new_name: None,
            expected_version: Some(1),
            revoke_collaborators: None,
        };
        assert_eq!(validate_transfer_input("alice", "app", &valid).unwrap(), ("app".into(), true));
    }

    #[test]
    fn transfer_state_machine_enforces_single_commit_point_and_rollback() {
        use TransferPhase::*;
        let chain = [Preparing, Draining, CopyingRemote, RekeyingDb, RevokingLegacy, Completed];
        for pair in chain.windows(2) {
            assert!(pair[0].can_transition(pair[1]));
        }
        assert!(!Preparing.owner_committed_to_target());
        assert!(!Draining.owner_committed_to_target());
        assert!(!CopyingRemote.owner_committed_to_target());
        assert!(!RekeyingDb.owner_committed_to_target());
        assert!(RevokingLegacy.owner_committed_to_target());
        assert!(Completed.owner_committed_to_target());

        assert!(CopyingRemote.can_transition(RollingBack));
        assert!(RollingBack.can_transition(RolledBack));
        assert!(!RevokingLegacy.can_transition(RollingBack));
        assert!(Completed.is_terminal());
        assert!(RolledBack.is_terminal());
    }

    #[test]
    fn remote_copy_plans_rekey_destination_without_mutating_source() {
        let from = Uuid::new_v4();
        let to = Uuid::new_v4();
        let auth = Uuid::new_v4();
        let oid = "a".repeat(64);
        let (l_src, l_dst) = plan_lfs_copy(from, to, &oid).unwrap();
        assert_eq!(l_src.path(), format!("tenants/{from}/lfs/{oid}"));
        assert_eq!(l_dst.path(), format!("tenants/{to}/lfs/{oid}"));

        let (p_src, p_dst) = plan_pando_copy(from, to, Some((auth, 2, 3)), "pando-cipher", &oid).unwrap();
        assert_eq!(p_src.path(), format!("tenants/{from}/authorities/{auth}/g2/pando-cipher/{oid}"));
        assert_eq!(p_dst.path(), format!("tenants/{to}/authorities/{auth}/g3/pando-cipher/{oid}"));

        let manifest = RemoteManifest {
            schema: 1,
            checkpoint_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            tenant_id: from,
            captured_revision: 1,
            entries: vec![],
        };
        let (bytes, digest, dst) = rekey_workspace_manifest(manifest, to).unwrap();
        let parsed: RemoteManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.tenant_id, to);
        assert_eq!(dst.path(), format!("tenants/{to}/workspace/{digest}"));
    }
}
