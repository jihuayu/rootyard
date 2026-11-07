use super::models::{CreateWorkspace, LeaseRequest, WS_COLUMNS, Workspace};
use crate::{AppState, Error, auth, members::models::Role, storage::read_leases};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path as FsPath, PathBuf},
    sync::Arc,
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

/// Bounded native Git command. Output and lifetime are capped by the shared
/// GitFS collector; the process group is cleaned up on timeout or cancellation.
pub async fn git(state: &AppState, repo: &FsPath, args: &[&str], limit: usize) -> Result<Vec<u8>, Error> {
    super::git::run(state, repo, args, limit).await
}

pub async fn authorized(state: &AppState, headers: &HeaderMap, id: Uuid, role: Role) -> Result<Workspace, Error> {
    let actor = auth::authenticate(&state.pool, headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let sql = format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1");
    let row = tx.query_opt(&sql, &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let ws = Workspace::from_row(&row);
    let access = auth::authorize_repo_with_role(&tx, &actor, &ws.owner, &ws.repository, role).await?;
    if access.repo_id != ws.repository_id {
        return Err(Error::not_found());
    }
    if ws.creator_id != actor.id || ws.state != "ready" {
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
) -> Result<Workspace, Error> {
    locked_inner(tx, actor, id, role, true).await
}

async fn locked_inner(
    tx: &deadpool_postgres::Transaction<'_>,
    actor: &crate::db::Identity,
    id: Uuid,
    role: Role,
    require_mount: bool,
) -> Result<Workspace, Error> {
    let sql = format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1");
    let row = tx.query_opt(&sql, &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let initial = Workspace::from_row(&row);
    let access = auth::authorize_repo_with_role(tx, actor, &initial.owner, &initial.repository, role).await?;
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
    Ok(Json(authorized(&state, &headers, id, Role::Read).await?))
}

pub async fn lease(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<LeaseRequest>,
) -> Result<Json<Workspace>, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ws = locked_inner(&tx, &actor, id, Role::Write, false).await?;
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
        let cp = ws.last_checkpoint_id.ok_or_else(conflict)?;
        let row = tx
            .query_opt(
                "SELECT state,captured_revision FROM workspace_checkpoints WHERE id=$1 AND workspace_id=$2",
                &[&cp, &id],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(conflict)?;
        if row.get::<_, String>(0) != "committed" || ws.revision != row.get::<_, i64>(1) + 1 {
            return Err(conflict());
        }
        let tenant: Uuid = tx
            .query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&ws.repository_id])
            .await
            .map_err(Error::internal)?
            .get(0);
        if super::mounts::enabled() {
            super::lazy::prepare(&state, id, cp, ws.repository_id, tenant).await?;
        } else {
            super::remote::ensure_local(&state, cp, ws.repository_id, tenant).await?;
            materialize_takeover(&state, id, cp)?;
        }
    } else if !super::mounts::lower_path(&state, id).join(".git").is_dir() {
        return Err(conflict());
    }
    let same_host = ws.host_id == state.storage.volume_id;
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
        let changed=tx.execute("UPDATE workspaces SET host_id=$2,lease_epoch=lease_epoch+1,lease_until=clock_timestamp()+interval '5 minutes' WHERE id=$1 AND lease_epoch=$3 AND (host_id=$2 OR lease_until<=clock_timestamp())", &[&id,&state.storage.volume_id,&input.expected_lease_epoch]).await.map_err(Error::internal)?;
        if changed != 1 {
            return Err(conflict());
        }
        let row = tx
            .query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id])
            .await
            .map_err(Error::internal)?;
        let deadline: i64 = tx
            .query_one("SELECT EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces WHERE id=$1", &[&id])
            .await
            .map_err(Error::internal)?
            .get(0);
        tx.commit().await.map_err(Error::internal)?;
        Ok((Workspace::from_row(&row), deadline))
    };
    // On this host the commit runs inside one freeze that fences the superseded
    // epoch before it is released, so that epoch cannot admit writes between the
    // commit and the authorization below. A failed, unknown or cancelled commit
    // leaves the gate fenced rather than thawing the old epoch, and the mount
    // stays read-only until a later committed epoch is authorized here.
    let (saved, deadline) =
        if same_host { super::mounts::with_frozen_async(id, commit).await? } else { commit.await? };
    super::mounts::ensure(&state, id, saved.lease_epoch, deadline)?;
    Ok(Json(saved))
}

fn materialize_takeover(state: &AppState, id: Uuid, cp: Uuid) -> Result<(), Error> {
    use crate::workspace_lab::core;
    use std::fs;
    let source = checkpoint_repo(state, cp);
    let destination = super::mounts::lower_path(state, id);
    if destination.exists() {
        if core::inventory(&destination).map_err(Error::internal)?
            != core::inventory(&source).map_err(Error::internal)?
        {
            return Err(conflict());
        }
        return Ok(());
    }
    let parent = destination.parent().ok_or_else(Error::bad_request)?;
    fs::create_dir_all(parent).map_err(Error::internal)?;
    let stage = parent.join(format!(".transfer-{}", Uuid::new_v4()));
    let copied = (|| {
        core::copy_all(&source, &stage).map_err(Error::internal)?;
        core::sync_tree(&stage).map_err(Error::internal)?;
        fs::rename(&stage, &destination).map_err(Error::internal)?;
        fs::File::open(parent).and_then(|f| f.sync_all()).map_err(Error::internal)
    })();
    if copied.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    copied
}

pub async fn fence_restored(pool: &deadpool_postgres::Pool) -> Result<(), Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    tx.execute("UPDATE workspaces SET lease_epoch=lease_epoch+1,lease_until=clock_timestamp()-interval '1 second' WHERE state='ready'", &[]).await.map_err(Error::internal)?;
    tx.execute("UPDATE sandbox_jobs SET state='cancelled',pid=NULL,finished_at=clock_timestamp() WHERE state IN ('queued','preparing','running')", &[]).await.map_err(Error::internal)?;
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
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&(&input.owner, &input.repository, &input.agent_id, &input.base_oid))
            .map_err(Error::internal)?,
    ));
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = auth::authorize_repo_with_role(&tx, &actor, &input.owner, &input.repository, Role::Write).await?;
    creation_lock(&tx, actor.id, &key).await?;
    if let Some(row) = tx.query_opt("SELECT request_sha256,workspace_id FROM workspace_creations WHERE actor_id=$1 AND idempotency_key=$2 FOR UPDATE", &[&actor.id,&key]).await.map_err(Error::internal)? {
        let existing: String = row.get(0);
        if existing != digest { return Err(conflict()); }
        let id: Uuid = row.get(1);
        let row = tx.query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id]).await.map_err(Error::internal)?;
        let saved = Workspace::from_row(&row);
        tx.commit().await.map_err(Error::internal)?;
        super::mounts::ensure_from_database(&state, id).await?;
        return Ok((StatusCode::OK, Json(saved)));
    }
    let id = Uuid::new_v4();
    let source_lease =
        read_leases::shared(&state.pool, repo.repo_id, tokio::time::Instant::now() + state.config.git_timeout).await?;
    let _local = tokio::time::timeout(state.config.git_timeout, state.storage.read_snapshot_lock(repo.repo_id))
        .await
        .map_err(|_| Error::timeout())?;
    source_lease.ensure_active()?;
    let refreshed = auth::authorize_repo_with_role(&tx, &actor, &input.owner, &input.repository, Role::Write).await?;
    if refreshed.repo_id != repo.repo_id {
        return Err(Error::not_found());
    }
    let source = state.storage.verify_path(repo.repo_id).map_err(Error::internal)?;
    let dest = super::mounts::lower_path(&state, id);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(Error::internal)?;
    }
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
    drop(_local);
    drop(source_lease);
    let head = String::from_utf8(git(&state, &dest, &["rev-parse", "HEAD"], 4096).await.unwrap_or_default())
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| crate::browse::models::valid_non_zero_oid(value));
    if let Some(base) = &input.base_oid {
        if !crate::browse::models::valid_non_zero_oid(base) {
            return Err(Error::bad_request());
        }
        if head.as_deref() != Some(base.as_str()) {
            return Err(conflict());
        }
    }
    let base_oid = input.base_oid.clone().or(head);
    let host_id = state.storage.volume_id;
    tx.execute("INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,state,host_id,lease_until,base_oid) VALUES($1,$2,$3,$4,$5,$6,'ready',$7,clock_timestamp()+interval '5 minutes',$8)", &[&id,&repo.repo_id,&input.owner,&input.repository,&input.agent_id,&actor.id,&host_id,&base_oid]).await.map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO workspace_creations(actor_id,idempotency_key,request_sha256,workspace_id) VALUES($1,$2,$3,$4)",
        &[&actor.id, &key, &digest, &id],
    )
    .await
    .map_err(Error::internal)?;
    super::capture::record_current_at(&tx, id, &dest).await?;
    let row = tx
        .query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id])
        .await
        .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    super::mounts::ensure_from_database(&state, id).await?;
    Ok((StatusCode::CREATED, Json(Workspace::from_row(&row))))
}
