//! Mandatory fail-closed deletion gate and retention-root predicates for
//! Pando remote artifact pruning (#77).
use crate::{
    AppState,
    pando_gateway::pitr_fence::{self, AuthorityState},
    storage::remote_objects::{ObjectKey, RemoteObjectStore},
};
use anyhow::{Result, bail, ensure};
use std::env;
use tokio::time::Instant;
use uuid::Uuid;

pub const ENV_PANDO_REMOTE_DELETE: &str = "ROOTYARD_PANDO_REMOTE_DELETE";

#[derive(Clone, Debug)]
pub enum DeleteGateDecision {
    Disabled { reason: &'static str },
    Fenced { reason: String },
    Allowed(Box<AuthorityState>),
}

/// Strictly parse `ROOTYARD_PANDO_REMOTE_DELETE`: unset or `"false"` keeps
/// destructive remote delete off; `"true"` opts in subject to authority/PITR
/// fencing; any other value fails closed.
pub fn remote_delete_env_enabled() -> Result<bool> {
    match env::var(ENV_PANDO_REMOTE_DELETE) {
        Err(env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "false" => Ok(false),
        Ok(value) if value == "true" => Ok(true),
        Ok(_) | Err(env::VarError::NotUnicode(_)) => {
            bail!("{ENV_PANDO_REMOTE_DELETE} must be true or false")
        }
    }
}

pub fn validate_startup_env() -> Result<()> {
    let _ = remote_delete_env_enabled()?;
    Ok(())
}

/// Evaluate whether the scheduler may enqueue `pando_tombstone_delete`.
/// When `ROOTYARD_PANDO_REMOTE_DELETE=true`, performs full local + external
/// bucket proof verification and refuses (plus latches PG fence on mismatch)
/// before enqueuing any destructive work.
pub async fn check_scheduler_gate(state: &AppState, deadline: Instant) -> Result<DeleteGateDecision> {
    if !remote_delete_env_enabled()? {
        return Ok(DeleteGateDecision::Disabled { reason: "ROOTYARD_PANDO_REMOTE_DELETE is not enabled" });
    }
    let remote = match RemoteObjectStore::from_env(state.storage.root.join("pando-pack-work")) {
        Ok(store) => store,
        Err(error) => {
            pitr_fence::latch_fence(&state.pool, &format!("remote object store unavailable: {error}")).await;
            return Ok(DeleteGateDecision::Fenced { reason: error.to_string() });
        }
    };
    match pitr_fence::verify_or_attest(&state.pool, &state.storage.root, &remote, deadline, "attest").await {
        Ok(authority) => Ok(DeleteGateDecision::Allowed(Box::new(authority))),
        Err(error) => Ok(DeleteGateDecision::Fenced { reason: error.to_string() }),
    }
}

/// Enforce attestation, epoch freshness, and advance `authority_epoch` (`E -> E+1`)
/// in both the object store (`If-None-Match: *`) and PostgreSQL before any
/// `pando_tombstone_delete` job may issue a remote delete.
pub async fn enter_fenced_delete_execution(
    state: &AppState,
    remote: &RemoteObjectStore,
    deadline: Instant,
) -> Result<AuthorityState> {
    ensure!(remote_delete_env_enabled()?, "ROOTYARD_PANDO_REMOTE_DELETE is not enabled");
    pitr_fence::advance_epoch(&state.pool, &state.storage.root, remote, "delete_epoch", deadline).await
}

/// Verify an artifact row carries an authoritative scoped key owned by the
/// current attested `authority_id` and is never a legacy or authority-proof key.
pub fn validate_scoped_delete_target(
    current_authority_id: Uuid,
    row_authority_id: Uuid,
    tenant_id: Uuid,
    object_generation: i64,
    namespace: &str,
    sha256: &str,
    remote_path: &str,
) -> Result<ObjectKey> {
    ensure!(row_authority_id == current_authority_id, "refusing delete for artifact outside active authority");
    ensure!(object_generation > 0, "refusing delete for non-positive artifact generation");
    ensure!(!remote_path.starts_with("pando-authorities/"), "refusing delete for authority proof object");
    let key = ObjectKey::scoped(tenant_id, current_authority_id, object_generation, namespace, sha256)?;
    ensure!(
        key.authority == Some((current_authority_id, object_generation)) && key.path() == remote_path,
        "refusing delete for legacy or unregistered remote path"
    );
    Ok(key)
}
