//! Restored-incarnation deleter admission and destructive-GC refusal.
//!
//! A restored Pando authority keeps a strictly higher epoch and a hard remote
//! delete fence. A caller presenting any pre-restore epoch is `Stale`, and a
//! caller presenting the new epoch is still refused while either the storage
//! maintenance worker or a remote destructive switch is enabled.
use serde::Serialize;
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::config::WorkspaceRemoteDeletePolicy;
use crate::storage_lifecycle::models::Policy;

use super::{W8aError, W8aResult};

pub const ENV_DESTRUCTIVE_GC: &str = "ROOTYARD_STORAGE_MAINTENANCE";
pub const ENV_WORKSPACE_REMOTE_DELETE: &str = "ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE";
pub const ENV_BLOB_DELETE: &str = "ROOTYARD_BLOB_DELETE";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DeleterAdmissionReceipt {
    pub authority_id: Uuid,
    pub restore_generation: i64,
    pub authority_epoch: i64,
    pub candidate_epoch: i64,
    pub minimum_required_epoch: i64,
    pub remote_delete_fenced: bool,
    pub destructive_gc_enabled: bool,
}

pub async fn admit_deleter_epoch(
    client: &(impl GenericClient + Sync),
    candidate_epoch: i64,
    policy: &Policy,
) -> W8aResult<DeleterAdmissionReceipt> {
    let row = client
        .query_opt(
            "SELECT authority_id, authority_epoch, restore_generation, remote_delete_fenced
             FROM public.pando_storage_authorities WHERE singleton=true",
            &[],
        )
        .await
        .map_err(|error| W8aError::RestoreFailed(format!("reading the restored storage authority: {error}")))?;
    let row = row.ok_or_else(|| W8aError::RestoreFailed("restored storage authority is missing".into()))?;
    let authority_id: Uuid = row.get(0);
    let authority_epoch: i64 = row.get(1);
    let restore_generation: i64 = row.get(2);
    let remote_delete_fenced: bool = row.get(3);
    let minimum_required_epoch = authority_epoch;
    if candidate_epoch < minimum_required_epoch {
        return Err(W8aError::StaleDeleterFenced { candidate_epoch, minimum_required_epoch, remote_delete_fenced });
    }
    ensure_destructive_gc_disabled(policy)?;
    if remote_delete_fenced {
        return Err(W8aError::StaleDeleterFenced { candidate_epoch, minimum_required_epoch, remote_delete_fenced });
    }
    Ok(DeleterAdmissionReceipt {
        authority_id,
        restore_generation,
        authority_epoch,
        candidate_epoch,
        minimum_required_epoch,
        remote_delete_fenced,
        destructive_gc_enabled: false,
    })
}

pub fn ensure_destructive_gc_disabled(policy: &Policy) -> W8aResult<()> {
    let workspace = WorkspaceRemoteDeletePolicy::from_env()
        .map_err(|error| W8aError::DestructiveGcForbidden(format!("workspace policy: {error:#}")))?;
    let blob_delete = std::env::var(ENV_BLOB_DELETE).ok();
    ensure_destructive_gc_disabled_with(policy, workspace.enabled(), blob_delete.as_deref())
}

pub(super) fn ensure_destructive_gc_disabled_with(
    policy: &Policy,
    workspace_remote_delete: bool,
    blob_delete: Option<&str>,
) -> W8aResult<()> {
    if policy.enabled {
        return Err(W8aError::DestructiveGcForbidden(format!("{ENV_DESTRUCTIVE_GC}=true")));
    }
    if workspace_remote_delete {
        return Err(W8aError::DestructiveGcForbidden(format!("{ENV_WORKSPACE_REMOTE_DELETE}=true")));
    }
    if matches!(blob_delete, Some("true" | "enabled")) {
        return Err(W8aError::DestructiveGcForbidden(format!("{ENV_BLOB_DELETE} enables remote deletes")));
    }
    Ok(())
}
