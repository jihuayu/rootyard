//! Production `publication::validate_new_refs_with_client` S4 attestation bridge (`Refs #145`).

use std::future::Future;
use std::path::{Path as FsPath, PathBuf};
use std::time::Duration;

use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::journal::RefChange;

use super::attestation::{LfsPushAttestationRequest, attest_and_authorize_push};
use super::authz::{LfsBlobRuntimeGate, derive_default_push_operation_id, operation_token_to_uuid};
use super::pg_store::PgLfsBlobStore;
use super::transfer::LfsTransferContext;
use super::types::{AttestationOutcome, LfsBlobError, LfsProofRejectCode, LfsRefUpdateSpec};

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

pub async fn prod_validate_and_attest_push(
    gate: &LfsBlobRuntimeGate,
    git_dir: &FsPath,
    data_root: &FsPath,
    timeout: Duration,
    repo_id: Uuid,
    changes: &[RefChange],
) -> Result<AttestationOutcome, LfsBlobError> {
    let _ = gate.require_store()?;
    let (pool, actor_id, actor_username, opt_op_id, git_obj_dir, git_alt_dirs) =
        if let Ok(s) = ACTIVE_PUSH_SESSION.try_with(Clone::clone) {
            (s.pool, s.actor_id, s.actor_username, s.operation_id, s.git_object_dir, s.git_alternate_object_dirs)
        } else {
            resolve_hook_env_session()?
        };
    let pg = PgLfsBlobStore::new(pool);
    let mut realm = pg.ensure_realm_for_repository(repo_id, data_root).await?;
    if let Some(dir_str) = git_dir.to_str() {
        realm.bare_git_dir = dir_str.to_owned();
    }
    let access = pg.resolve_authoritative_repo_access(&realm, actor_id, &actor_username, true, false).await?;
    let scratch = ephemeral_scratch_root();
    let ctx = LfsTransferContext { gate, pg: &pg, realm: &realm, access: &access, scratch_dir: &scratch, timeout };
    let updates: Vec<LfsRefUpdateSpec> = changes
        .iter()
        .map(|c| LfsRefUpdateSpec {
            ref_name: c.ref_name.clone(),
            old_oid: c.old_oid.clone(),
            new_oid: c.new_oid.clone(),
        })
        .collect();
    let op_id = opt_op_id.unwrap_or_else(|| derive_default_push_operation_id(repo_id, actor_id, &updates));
    let req = LfsPushAttestationRequest {
        operation_id: op_id,
        updates,
        git_object_dir: git_obj_dir,
        git_alternate_object_dirs: git_alt_dirs,
    };
    attest_and_authorize_push(&ctx, &req).await
}

fn resolve_hook_env_session() -> Result<(Pool, Uuid, String, Option<Uuid>, Option<String>, Option<String>), LfsBlobError>
{
    let db_url = std::env::var("ROOTYARD_DATABASE_URL")
        .or_else(|_| std::env::var("ROOTYARD_TEST_DATABASE_URL"))
        .map_err(|_| LfsBlobError::new(LfsProofRejectCode::PgDatabase, "missing database URL for push attestation"))?;
    let pool = crate::db::pool(&db_url).map_err(|e| LfsBlobError::new(LfsProofRejectCode::PgDatabase, e.to_string()))?;
    if let Ok(op_dir) = std::env::var("ROOTYARD_OPERATION_DIR")
        && let Ok(bytes) = std::fs::read(FsPath::new(&op_dir).join("operation.json"))
        && let Ok(op) = serde_json::from_slice::<crate::journal::Operation>(&bytes)
    {
        let explicit_op_id = op
            .idempotency
            .as_ref()
            .and_then(|i| operation_token_to_uuid(&i.key_sha256).ok());
        return Ok((
            pool,
            op.actor_id,
            op.actor_name,
            explicit_op_id,
            std::env::var("GIT_OBJECT_DIRECTORY").ok(),
            std::env::var("GIT_ALTERNATE_OBJECT_DIRECTORIES").ok(),
        ));
    }
    let explicit_op_id = std::env::var("ROOTYARD_OPERATION_ID")
        .ok()
        .and_then(|s| operation_token_to_uuid(&s).ok());
    let actor_id = std::env::var("ROOTYARD_ACTOR_ID")
        .ok()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "missing push actor_id"))?;
    let actor_username = std::env::var("ROOTYARD_ACTOR_NAME").unwrap_or_else(|_| "git-pusher".to_owned());
    Ok((
        pool,
        actor_id,
        actor_username,
        explicit_op_id,
        std::env::var("GIT_OBJECT_DIRECTORY").ok(),
        std::env::var("GIT_ALTERNATE_OBJECT_DIRECTORIES").ok(),
    ))
}
