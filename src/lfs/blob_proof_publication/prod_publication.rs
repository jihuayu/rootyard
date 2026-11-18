//! Production `browse::policy::validate_hook` & `publication` S4 attestation bridge (`Refs #145`).

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use axum::{
    Json,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::Pool;
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    Error,
    journal::{Operation, RefChange},
    lfs::models::LFS_MEDIA_TYPE,
};

use super::attestation::{LfsPushAttestationRequest, attest_and_authorize_push_with_auth};
use super::authz::{LfsBlobRuntimeGate, derive_default_push_operation_id, operation_token_to_uuid};
use super::pg_store::PgLfsBlobStore;
use super::prod_auth_tx::PushCommitAuthCheck;
use super::transfer::{LfsTransferContext, acquire_transfer_permit};
use super::types::{AttestationOutcome, LfsBlobError, LfsProofRejectCode, LfsRefUpdateSpec};

static GATE_OVERRIDE: OnceLock<RwLock<Option<LfsBlobRuntimeGate>>> = OnceLock::new();

fn gate_slot() -> &'static RwLock<Option<LfsBlobRuntimeGate>> {
    GATE_OVERRIDE.get_or_init(|| RwLock::new(None))
}

pub fn set_runtime_gate_override(gate: Option<LfsBlobRuntimeGate>) {
    *gate_slot().write().unwrap_or_else(|e| e.into_inner()) = gate;
}

pub fn active_blob_gate() -> Option<LfsBlobRuntimeGate> {
    if let Some(g) = gate_slot().read().unwrap_or_else(|e| e.into_inner()).clone() {
        return Some(g);
    }
    LfsBlobRuntimeGate::blob_mode_requested().then(LfsBlobRuntimeGate::from_env_gate)
}

pub(crate) fn enforce_blob_gate_if_requested() -> Result<Option<LfsBlobRuntimeGate>, Error> {
    let Some(gate) = active_blob_gate() else {
        return Ok(None);
    };
    let _ = gate.require_store().map_err(to_app_error)?;
    Ok(Some(gate))
}

pub(crate) fn to_app_error(err: LfsBlobError) -> Error {
    Error(err.code.http_status(), err.code.as_str())
}

pub(super) fn lfs_blob_json(status: StatusCode, payload: impl Serialize) -> Response {
    let mut res = (status, Json(payload)).into_response();
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(LFS_MEDIA_TYPE));
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res.headers_mut().insert(HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
    res.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    if status == StatusCode::UNAUTHORIZED {
        res.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"Rootyard\", charset=\"UTF-8\""));
    }
    res
}

pub(super) fn lfs_blob_err_response(err: LfsBlobError) -> Response {
    lfs_blob_json(
        err.code.http_status(),
        json!({ "code": err.code.as_str(), "error": err.code.as_str(), "message": err.message }),
    )
}

pub(super) fn build_base_url(headers: &HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.eq_ignore_ascii_case("https"))
        .map(|_| "https")
        .unwrap_or("http");
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()).map(str::trim).filter(|h| !h.is_empty())
    else {
        return String::new();
    };
    format!("{scheme}://{host}")
}

pub(super) fn collect_forwarded_action_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(auth_val) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        out.insert("Authorization".to_owned(), auth_val.to_owned());
    }
    for name in ["X-Rootyard-Operation-Id", "Idempotency-Key"] {
        if let Some(val) = headers.get(name).and_then(|v| v.to_str().ok()) {
            out.insert(name.to_owned(), val.to_owned());
        }
    }
    out
}

#[derive(Clone)]
pub struct PushAttestationSession {
    pub pool: Pool,
    pub actor_id: Uuid,
    pub actor_username: String,
    pub operation_id: Option<Uuid>,
    pub git_object_dir: Option<String>,
    pub git_alternate_object_dirs: Option<String>,
}

tokio::task_local! {
    static ACTIVE_PUSH_SESSION: PushAttestationSession;
}

pub async fn with_push_attestation_session<F: Future>(session: PushAttestationSession, fut: F) -> F::Output {
    ACTIVE_PUSH_SESSION.scope(session, fut).await
}

pub(crate) fn active_push_quarantine_dirs() -> Option<(Option<String>, Option<String>)> {
    ACTIVE_PUSH_SESSION.try_with(|s| (s.git_object_dir.clone(), s.git_alternate_object_dirs.clone())).ok()
}

pub(super) fn ephemeral_scratch_root() -> PathBuf {
    std::env::temp_dir().join(format!("rootyard-s4-lfs-scratch-{}", std::process::id()))
}

fn to_ref_update_specs(changes: &[RefChange]) -> Vec<LfsRefUpdateSpec> {
    changes
        .iter()
        .map(|c| LfsRefUpdateSpec {
            ref_name: c.ref_name.clone(),
            old_oid: c.old_oid.clone(),
            new_oid: c.new_oid.clone(),
        })
        .collect()
}

/// Invoked directly from `crate::browse::policy::validate_hook` (`crate::lfs::publication::validate_new_refs_for_hook`),
/// binding the trusted admitted [`Operation`] (`op.actor_id`, `op.actor_name`, `op.idempotency`, `op.id`) and
/// relational `expected_tenant_id` without relying on untrusted environment overrides.
pub async fn prod_validate_and_attest_hook(
    gate: &LfsBlobRuntimeGate,
    db_url: &str,
    git_dir: &FsPath,
    data_root: &FsPath,
    timeout: Duration,
    expected_tenant_id: Uuid,
    op: &Operation,
    changes: &[RefChange],
) -> Result<AttestationOutcome, LfsBlobError> {
    let _ = gate.require_store()?;
    let _permit = acquire_transfer_permit(timeout).await?;
    let pool = crate::db::pool(db_url).map_err(|e| LfsBlobError::new(LfsProofRejectCode::PgDatabase, e.to_string()))?;
    let pg = PgLfsBlobStore::new(pool);
    super::prod_auth_tx::preflight_write_authority(
        &pg,
        op.repository_id,
        expected_tenant_id,
        op.actor_id,
        &op.actor_name,
    )
    .await?;
    let mut realm = pg.ensure_realm_for_repository(op.repository_id, data_root).await?;
    if realm.owner_tenant_id != expected_tenant_id {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::AttestationEquivocation,
            "repository ownership tenant changed during push hook validation",
        ));
    }
    if let Some(dir_str) = git_dir.to_str() {
        realm.bare_git_dir = dir_str.to_owned();
    }
    let access = pg
        .resolve_authoritative_repo_access(&realm, op.actor_id, &op.actor_name, true, false)
        .await?;
    let updates = to_ref_update_specs(changes);
    let op_id = if let Some(intent) = &op.idempotency {
        operation_token_to_uuid(&intent.key_sha256)?
    } else if pg.load_attestation(op.repository_id, op.id).await?.is_some() {
        op.id
    } else {
        derive_default_push_operation_id(op.repository_id, expected_tenant_id, op.actor_id, &updates)
    };
    let (git_obj_dir, git_alt_dirs) = active_push_quarantine_dirs().unwrap_or_else(|| {
        (std::env::var("GIT_OBJECT_DIRECTORY").ok(), std::env::var("GIT_ALTERNATE_OBJECT_DIRECTORIES").ok())
    });
    let scratch = ephemeral_scratch_root();
    let ctx = LfsTransferContext { gate, pg: &pg, realm: &realm, access: &access, scratch_dir: &scratch, timeout };
    let req = LfsPushAttestationRequest {
        operation_id: op_id,
        updates,
        git_object_dir: git_obj_dir,
        git_alternate_object_dirs: git_alt_dirs,
    };
    attest_and_authorize_push_with_auth(
        &ctx,
        &req,
        Some(PushCommitAuthCheck {
            actor_id: op.actor_id,
            token_id: Some(op.token_id),
            expected_generation: Some(op.storage_generation),
        }),
    )
    .await
}

pub async fn prod_validate_and_attest_push(
    gate: &LfsBlobRuntimeGate,
    git_dir: &FsPath,
    data_root: &FsPath,
    timeout: Duration,
    repo_id: Uuid,
    expected_tenant_id: Uuid,
    changes: &[RefChange],
) -> Result<AttestationOutcome, LfsBlobError> {
    let _ = gate.require_store()?;
    let _permit = acquire_transfer_permit(timeout).await?;
    let s = ACTIVE_PUSH_SESSION.try_with(Clone::clone).map_err(|_| {
        LfsBlobError::new(
            LfsProofRejectCode::UnauthorizedCollaborator,
            "missing trusted Operation or PushAttestationSession; native receive hooks must invoke validate_new_refs_for_hook",
        )
    })?;
    let pg = PgLfsBlobStore::new(s.pool);
    super::prod_auth_tx::preflight_write_authority(&pg, repo_id, expected_tenant_id, s.actor_id, &s.actor_username)
        .await?;
    let mut realm = pg.ensure_realm_for_repository(repo_id, data_root).await?;
    if realm.owner_tenant_id != expected_tenant_id {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::AttestationEquivocation,
            "repository ownership tenant changed during ref publication",
        ));
    }
    if let Some(dir_str) = git_dir.to_str() {
        realm.bare_git_dir = dir_str.to_owned();
    }
    let access = pg.resolve_authoritative_repo_access(&realm, s.actor_id, &s.actor_username, true, false).await?;
    let scratch = ephemeral_scratch_root();
    let ctx = LfsTransferContext { gate, pg: &pg, realm: &realm, access: &access, scratch_dir: &scratch, timeout };
    let updates = to_ref_update_specs(changes);
    let op_id = s
        .operation_id
        .unwrap_or_else(|| derive_default_push_operation_id(repo_id, expected_tenant_id, s.actor_id, &updates));
    let req = LfsPushAttestationRequest {
        operation_id: op_id,
        updates,
        git_object_dir: s.git_object_dir,
        git_alternate_object_dirs: s.git_alternate_object_dirs,
    };
    attest_and_authorize_push(&ctx, &req).await
}
