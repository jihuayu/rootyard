#[path = "lease_takeover.rs"]
mod takeover;

use self::takeover::{TakeoverGuards, prepare_takeover, verify_takeover_checkpoint};
use super::models::{CreateWorkspace, LeaseRequest, WS_COLUMNS, Workspace};
use crate::{AppState, Error, auth, members::models::Role, storage::read_leases};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

pub fn workspace_root(state: &AppState) -> PathBuf {
    state.storage.root.join("workspace-service")
}
pub fn workspace_repo(state: &AppState, id: Uuid) -> PathBuf {
    if super::mounts::enabled() { super::mounts::mount_path(state, id) } else { super::mounts::lower_path(state, id) }
}
pub fn checkpoint_repo(state: &AppState, id: Uuid) -> PathBuf {
    workspace_root(state).join("checkpoints").join(id.to_string())
}
pub fn conflict() -> Error {
    Error(StatusCode::CONFLICT, "workspace version or lease conflict")
}

pub(crate) async fn creation_lock(
    tx: &deadpool_postgres::Transaction<'_>,
    actor: Uuid,
    key: &str,
) -> Result<(), Error> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':' || $2::text, 709))",
        &[&actor, &key],
    )
    .await
    .map_err(Error::internal)?;
    Ok(())
}

pub(super) async fn lookup_existing_creation(
    tx: &deadpool_postgres::Transaction<'_>,
    actor_id: Uuid,
    key: &str,
    digest: &str,
    for_update: bool,
) -> Result<Option<Workspace>, Error> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    let sql = format!(
        "SELECT request_sha256,workspace_id FROM workspace_creations WHERE actor_id=$1 AND idempotency_key=$2{lock}"
    );
    let Some(row) = tx.query_opt(&sql, &[&actor_id, &key]).await.map_err(Error::internal)? else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != digest {
        return Err(conflict());
    }
    let existing_id: Uuid = row.get(1);
    let row = tx
        .query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&existing_id])
        .await
        .map_err(Error::internal)?;
    Ok(Some(Workspace::from_row(&row)))
}

pub async fn git(state: &AppState, repo: &FsPath, args: &[&str], limit: usize) -> Result<Vec<u8>, Error> {
    super::git::run(state, repo, args, limit).await
}

pub async fn authorized(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    role: Role,
    action: crate::token_scopes::RepoAction,
) -> Result<Workspace, Error> {
    let actor = auth::authenticate(&state.pool, headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let sql = format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1");
    let row = tx.query_opt(&sql, &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let ws = Workspace::from_row(&row);
    let access = auth::authorize_repo_with_role(&tx, &actor, &ws.owner, &ws.repository, role, action).await?;
    if access.repo_id != ws.repository_id || ws.creator_id != actor.id || ws.state != "ready" {
        return Err(Error::not_found());
    }
    tx.commit().await.map_err(Error::internal)?;
    if !super::mounts::mounted(id) {
        return Err(Error::internal("workspace FUSE mount missing"));
    }
    Ok(ws)
}

pub async fn locked(
    tx: &deadpool_postgres::Transaction<'_>,
    actor: &crate::db::Identity,
    id: Uuid,
    role: Role,
    action: crate::token_scopes::RepoAction,
) -> Result<Workspace, Error> {
    locked_inner(tx, actor, id, role, action, true).await
}

async fn locked_inner(
    tx: &deadpool_postgres::Transaction<'_>,
    actor: &crate::db::Identity,
    id: Uuid,
    role: Role,
    action: crate::token_scopes::RepoAction,
    require_mount: bool,
) -> Result<Workspace, Error> {
    let sql = format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1");
    let row = tx.query_opt(&sql, &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let initial = Workspace::from_row(&row);
    let access = auth::authorize_repo_with_role(tx, actor, &initial.owner, &initial.repository, role, action).await?;
    if access.repo_id != initial.repository_id {
        return Err(Error::not_found());
    }
    let row = tx
        .query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1 FOR UPDATE"), &[&id])
        .await
        .map_err(Error::internal)?;
    let ws = Workspace::from_row(&row);
    if ws.repository_id != initial.repository_id
        || ws.creator_id != initial.creator_id
        || ws.owner != initial.owner
        || ws.repository != initial.repository
        || ws.creator_id != actor.id
        || ws.state != "ready"
    {
        return Err(Error::not_found());
    }
    if require_mount && !super::mounts::mounted(id) {
        return Err(Error::internal("workspace FUSE mount missing"));
    }
    Ok(ws)
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Workspace>, Error> {
    Ok(Json(authorized(&state, &headers, id, Role::Read, crate::token_scopes::RepoAction::WorkspacesRead).await?))
}

pub async fn lease(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<LeaseRequest>,
) -> Result<Json<Workspace>, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let _mutation = super::blocking::lock_mutation(id, state.config.git_timeout).await?;

    // Phase 1: short read pre-check without holding a row lock across S3 or disk work.
    let takeover = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let row = tx
            .query_opt(
                &format!(
                    "SELECT {WS_COLUMNS},lease_until<=clock_timestamp() AS lease_expired FROM workspaces WHERE id=$1"
                ),
                &[&id],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        let ws = Workspace::from_row(&row);
        let access = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &ws.owner,
            &ws.repository,
            Role::Write,
            crate::token_scopes::RepoAction::WorkspacesWrite,
        )
        .await?;
        if access.repo_id != ws.repository_id || ws.creator_id != actor.id || ws.state != "ready" {
            return Err(Error::not_found());
        }
        if ws.lease_epoch != input.expected_lease_epoch {
            return Err(conflict());
        }
        let plan = if ws.host_id != state.storage.volume_id {
            if !row.get::<_, bool>("lease_expired") {
                return Err(conflict());
            }
            let cp = verify_takeover_checkpoint(&tx, &ws).await?;
            Some((cp, ws.repository_id, access.owner_id))
        } else {
            None
        };
        tx.commit().await.map_err(Error::internal)?;
        plan
    };

    // Phase 2: materialize cross-host takeover or check local repo off-thread with no DB TX held.
    // Newly materialized lower/sidecar paths remain armed until disarmed right before COMMIT.
    let mut takeover_guards = if let Some((cp, repository_id, tenant)) = takeover {
        prepare_takeover(&state, id, cp, repository_id, tenant).await?
    } else {
        let lower = super::mounts::lower_path(&state, id);
        if !super::blocking::run(move || Ok(lower.join(".git").is_dir())).await? {
            return Err(conflict());
        }
        TakeoverGuards::default()
    };

    // Phase 3: short FOR UPDATE commit transaction; clean up uncommitted takeover on pre-COMMIT failure.
    let commit_started = Arc::new(AtomicBool::new(false));
    let phase3: Result<(Workspace, i64), Error> = async {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let ws =
            locked_inner(&tx, &actor, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite, false).await?;
        if ws.lease_epoch != input.expected_lease_epoch {
            return Err(conflict());
        }
        if ws.host_id != state.storage.volume_id {
            let expired: bool = tx
                .query_one("SELECT lease_until<=clock_timestamp() FROM workspaces WHERE id=$1", &[&id])
                .await
                .map_err(Error::internal)?
                .get(0);
            if !expired {
                return Err(conflict());
            }
            let cp = verify_takeover_checkpoint(&tx, &ws).await?;
            if takeover.map(|(planned_cp, _, _)| planned_cp) != Some(cp) {
                return Err(conflict());
            }
        }
        let same_host = ws.host_id == state.storage.volume_id;
        let commit_flag = commit_started.clone();
        let commit = async {
            let active: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM sandbox_jobs WHERE workspace_id=$1 AND state IN ('queued','running'))",
                    &[&id],
                )
                .await
                .map_err(Error::internal)?
                .get(0);
            if active {
                return Err(conflict());
            }
            let row = tx
                .query_opt(
                    &format!(
                        "UPDATE workspaces SET host_id=$2,lease_epoch=lease_epoch+1,lease_until=clock_timestamp()+interval '5 minutes' \
                         WHERE id=$1 AND lease_epoch=$3 AND (host_id=$2 OR lease_until<=clock_timestamp()) \
                         RETURNING {WS_COLUMNS},EXTRACT(EPOCH FROM lease_until)::bigint AS lease_deadline"
                    ),
                    &[&id, &state.storage.volume_id, &input.expected_lease_epoch],
                )
                .await
                .map_err(Error::internal)?
                .ok_or_else(conflict)?;
            let deadline: i64 = row.get("lease_deadline");
            takeover_guards.keep();
            commit_flag.store(true, Ordering::Release);
            tx.commit().await.map_err(Error::internal)?;
            Ok((Workspace::from_row(&row), deadline))
        };
        if same_host {
            super::mounts::with_frozen_async(id, commit_started.clone(), commit).await
        } else {
            commit.await
        }
    }
    .await;

    let (saved, deadline) = match phase3 {
        Ok(pair) => pair,
        Err(error) => {
            if !commit_started.load(Ordering::Acquire) {
                takeover_guards.cleanup().await;
            }
            return Err(error);
        }
    };
    super::mounts::ensure_async(&state, id, saved.lease_epoch, deadline).await?;
    Ok(Json(saved))
}

pub async fn fence_restored(pool: &deadpool_postgres::Pool) -> Result<(), Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    tx.execute(
        "UPDATE workspaces SET lease_epoch=lease_epoch+1,lease_until=clock_timestamp()-interval '1 second' WHERE state='ready'",
        &[],
    )
    .await
    .map_err(Error::internal)?;
    tx.execute(
        "UPDATE sandbox_jobs SET state='cancelled',pid=NULL,finished_at=clock_timestamp() WHERE state IN ('queued','preparing','running')",
        &[],
    )
    .await
    .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<CreateWorkspace>,
) -> Result<(StatusCode, Json<Workspace>), Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = auth::idempotency_key(&headers)?.ok_or_else(Error::bad_request)?.to_owned();
    if input.agent_id.is_empty()
        || input.agent_id.len() > 128
        || !input.agent_id.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return Err(Error::bad_request());
    }
    if let Some(base) = &input.base_oid
        && !crate::browse::models::valid_non_zero_oid(base)
    {
        return Err(Error::bad_request());
    }
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&(&input.owner, &input.repository, &input.agent_id, &input.base_oid))
            .map_err(Error::internal)?,
    ));

    // Phase 1: short read pre-check and idempotency fast path.
    let repo = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let repo = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &input.owner,
            &input.repository,
            Role::Write,
            crate::token_scopes::RepoAction::WorkspacesWrite,
        )
        .await?;
        if let Some(saved) = lookup_existing_creation(&tx, actor.id, &key, &digest, false).await? {
            tx.commit().await.map_err(Error::internal)?;
            super::mounts::ensure_from_database(&state, saved.id).await?;
            return Ok((StatusCode::OK, Json(saved)));
        }
        tx.commit().await.map_err(Error::internal)?;
        repo
    };

    // Phase 2: clone under bounded Git slot + source read lease, then compute
    // initial fingerprint on the bounded blocking pool with zero DB locks held.
    let id = Uuid::new_v4();
    let _mutation = super::blocking::lock_mutation(id, state.config.git_timeout).await?;
    let dest = super::mounts::lower_path(&state, id);
    let dest_parent = dest.clone();
    super::blocking::run(move || {
        if let Some(parent) = dest_parent.parent() {
            fs::create_dir_all(parent).map_err(Error::internal)?;
        }
        Ok(())
    })
    .await?;
    let mut cleanup = Some(super::blocking::DirCleanupGuard::new(dest.clone()));
    let phase2_and_3: Result<(StatusCode, Workspace), Error> = async {
        {
            let _clone_slot = super::git::try_slot(&state)?;
            let source_lease =
                read_leases::shared(&state.pool, repo.repo_id, tokio::time::Instant::now() + state.config.git_timeout)
                    .await?;
            let _local = tokio::time::timeout(state.config.git_timeout, state.storage.read_snapshot_lock(repo.repo_id))
                .await
                .map_err(|_| Error::timeout())?;
            source_lease.ensure_active()?;
            {
                let mut client = state.pool.get().await.map_err(Error::internal)?;
                let tx = client.transaction().await.map_err(Error::internal)?;
                let refreshed = auth::authorize_repo_with_role(
                    &tx,
                    &actor,
                    &input.owner,
                    &input.repository,
                    Role::Write,
                    crate::token_scopes::RepoAction::WorkspacesWrite,
                )
                .await?;
                if refreshed.repo_id != repo.repo_id {
                    return Err(Error::not_found());
                }
                tx.commit().await.map_err(Error::internal)?;
            }
            let repo_id = repo.repo_id;
            let state_verify = state.clone();
            let source =
                super::blocking::run(move || state_verify.storage.verify_path(repo_id).map_err(Error::internal))
                    .await?;
            let mut clone = state.storage.git(&state.config);
            clone
                .args(["-c", "core.hooksPath=/dev/null", "clone", "--no-local", "--no-hardlinks", "--"])
                .arg(&source)
                .arg(&dest);
            source_lease
                .guard(crate::git_http::collect_git_output(clone, 4096, state.config.git_timeout))
                .await?
                .map_err(Error::internal)?;
            source_lease.ensure_active()?;
        }

        let head = String::from_utf8(git(&state, &dest, &["rev-parse", "HEAD"], 4096).await.unwrap_or_default())
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| crate::browse::models::valid_non_zero_oid(value));
        if let Some(base) = &input.base_oid
            && head.as_deref() != Some(base.as_str())
        {
            return Err(conflict());
        }
        let base_oid = input.base_oid.clone().or(head);
        let dest_fp = dest.clone();
        let initial_fingerprint = super::blocking::run(move || super::capture::fingerprint(&dest_fp)).await?;

        // Phase 3: short commit transaction with zero filesystem or Git work.
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let refreshed = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &input.owner,
            &input.repository,
            Role::Write,
            crate::token_scopes::RepoAction::WorkspacesWrite,
        )
        .await?;
        if refreshed.repo_id != repo.repo_id {
            return Err(Error::not_found());
        }
        creation_lock(&tx, actor.id, &key).await?;
        if let Some(saved) = lookup_existing_creation(&tx, actor.id, &key, &digest, true).await? {
            tx.commit().await.map_err(Error::internal)?;
            return Ok((StatusCode::OK, saved));
        }
        let host_id = state.storage.volume_id;
        tx.execute(
            "INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,state,host_id,lease_until,base_oid) \
             VALUES($1,$2,$3,$4,$5,$6,'ready',$7,clock_timestamp()+interval '5 minutes',$8)",
            &[&id, &repo.repo_id, &input.owner, &input.repository, &input.agent_id, &actor.id, &host_id, &base_oid],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO workspace_creations(actor_id,idempotency_key,request_sha256,workspace_id) VALUES($1,$2,$3,$4)",
            &[&actor.id, &key, &digest, &id],
        )
        .await
        .map_err(Error::internal)?;
        super::capture::record_fingerprint(&tx, id, &initial_fingerprint).await?;
        let row = tx
            .query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id])
            .await
            .map_err(Error::internal)?;
        if let Some(guard) = cleanup.take() {
            guard.keep();
        }
        tx.commit().await.map_err(Error::internal)?;
        Ok((StatusCode::CREATED, Workspace::from_row(&row)))
    }
    .await;

    if let Some(guard) = cleanup.take() {
        guard.cleanup().await;
    }
    let (status, saved) = phase2_and_3?;
    super::mounts::ensure_from_database(&state, saved.id).await?;
    Ok((status, Json(saved)))
}
