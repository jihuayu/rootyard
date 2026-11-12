#[path = "files_rollback.rs"]
mod rollback;

use self::rollback::{GitRollback, PutRollback, atomic_put, safe_file, safe_path};
use super::{
    models::{FilePut, FileQuery, GitAction},
    service,
};
use crate::{AppState, Error, auth, members::models::Role};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use deadpool_postgres::Transaction;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;

fn upper_fallback_root(state: &AppState, id: Uuid) -> Option<PathBuf> {
    super::mounts::enabled().then(|| state.storage.root.join("workspace-service/uppers").join(id.to_string()))
}

fn read_working_bounded(repo: &FsPath, raw: &str) -> Result<Vec<u8>, Error> {
    let path = safe_file(repo, raw)?;
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound { Error::not_found() } else { Error::internal(error) }
    })?;
    let meta = file.metadata().map_err(Error::internal)?;
    if !meta.is_file() {
        return Err(Error::bad_request());
    }
    if meta.len() > MAX_FILE_BYTES as u64 {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "file too large"));
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_FILE_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(Error::internal)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "file too large"));
    }
    Ok(bytes)
}

async fn check_idempotency(tx: &Transaction<'_>, id: Uuid, key: &str, hash: &str) -> Result<Option<Value>, Error> {
    let Some(row) = tx
        .query_opt(
            "SELECT request_sha256,state,result FROM workspace_operations WHERE workspace_id=$1 AND idempotency_key=$2",
            &[&id, &key],
        )
        .await
        .map_err(Error::internal)?
    else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != hash {
        return Err(service::conflict());
    }
    if row.get::<_, String>(1) == "committed" {
        return Ok(Some(row.get(2)));
    }
    Err(service::conflict())
}

async fn check_lease_live(tx: &Transaction<'_>, id: Uuid, volume_id: Uuid, lease_epoch: i64) -> Result<(), Error> {
    let lease_ok: bool = tx
        .query_one(
            "SELECT host_id=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() FROM workspaces WHERE id=$1",
            &[&id, &volume_id, &lease_epoch],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    if !lease_ok {
        return Err(service::conflict());
    }
    Ok(())
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<FileQuery>,
) -> Result<Json<Value>, Error> {
    let ws =
        service::authorized(&state, &headers, id, Role::Read, crate::token_scopes::RepoAction::WorkspacesRead).await?;
    let repo = service::workspace_repo(&state, id);
    let rel = safe_path(&query.path)?;
    let raw = match query.view.as_deref().unwrap_or("working") {
        "working" => {
            let path_arg = query.path.clone();
            super::blocking::run(move || read_working_bounded(&repo, &path_arg)).await?
        }
        "head" => service::git(&state, &repo, &["show", &format!("HEAD:{}", rel.display())], MAX_FILE_BYTES).await?,
        "index" => service::git(&state, &repo, &["show", &format!(":{}", rel.display())], MAX_FILE_BYTES).await?,
        _ => return Err(Error::bad_request()),
    };
    if raw.len() > MAX_FILE_BYTES {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "file too large"));
    }
    let client = state.pool.get().await.map_err(Error::internal)?;
    let version: i64 = client
        .query_opt("SELECT entry_version FROM workspace_entries WHERE workspace_id=$1 AND path=$2", &[&id, &query.path])
        .await
        .map_err(Error::internal)?
        .map(|r| r.get(0))
        .unwrap_or(0);
    Ok(Json(json!({
        "path": query.path,
        "view": query.view.unwrap_or_else(|| "working".into()),
        "content_base64": STANDARD.encode(&raw),
        "sha256": hex::encode(Sha256::digest(&raw)),
        "entry_version": version,
        "workspace_revision": ws.revision,
        "captured": false,
        "durability": "live_local"
    })))
}

pub async fn put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<FileQuery>,
    Json(input): Json<FilePut>,
) -> Result<Json<Value>, Error> {
    if query.view.as_deref().is_some_and(|v| v != "working") {
        return Err(Error::bad_request());
    }
    let bytes = STANDARD.decode(&input.content_base64).map_err(|_| Error::bad_request())?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "file too large"));
    }
    let permit = super::blocking::try_put_slot()?;
    let job = PutJob { raw_path: query.path, bytes, input };
    let response = super::git::spawn_job(put_mutation(state, headers, id, job, permit));
    match response.await {
        Ok(result) => result.map(Json),
        Err(_) => Err(Error::internal("owned workspace write job ended without a result")),
    }
}

struct PutJob {
    raw_path: String,
    bytes: Vec<u8>,
    input: FilePut,
}

async fn put_mutation(
    state: Arc<AppState>,
    headers: HeaderMap,
    id: Uuid,
    job: PutJob,
    permit: OwnedSemaphorePermit,
) -> Result<Value, Error> {
    let _permit = permit;
    let PutJob { raw_path, bytes, input } = job;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = auth::idempotency_key(&headers)?.ok_or_else(Error::bad_request)?.to_owned();
    let hash = hex::encode(Sha256::digest(
        serde_json::to_vec(&(
            &raw_path,
            &input.content_base64,
            input.expected_entry_version,
            input.expected_workspace_revision,
            input.lease_epoch,
        ))
        .map_err(Error::internal)?,
    ));
    let _mutation = super::blocking::lock_mutation(id, super::blocking::io_timeout()).await?;

    // Phase 1: short pre-check transaction without holding DB locks across disk work.
    {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let ws =
            service::locked(&tx, &actor, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite).await?;
        if let Some(replayed) = check_idempotency(&tx, id, &key, &hash).await? {
            tx.commit().await.map_err(Error::internal)?;
            return Ok(replayed);
        }
        check_lease_live(&tx, id, state.storage.volume_id, input.lease_epoch).await?;
        if ws.revision != input.expected_workspace_revision {
            return Err(service::conflict());
        }
        let prior: i64 = tx
            .query_opt(
                "SELECT entry_version FROM workspace_entries WHERE workspace_id=$1 AND path=$2",
                &[&id, &raw_path],
            )
            .await
            .map_err(Error::internal)?
            .map(|r| r.get(0))
            .unwrap_or(0);
        if prior != input.expected_entry_version {
            return Err(service::conflict());
        }
        tx.commit().await.map_err(Error::internal)?;
    }

    // Phase 2: capture rollback state (direct + FUSE), write atomically, and compute baseline.
    let repo = service::workspace_repo(&state, id);
    let upper_root = upper_fallback_root(&state, id);
    let path_arg = raw_path.clone();
    let (digest, scanned, mut put_rb) = super::blocking::run(move || {
        let mut rb = PutRollback::capture(&repo, &path_arg, upper_root)?;
        let target = rb.target().to_path_buf();
        if let Err(error) = atomic_put(&target, &bytes, 0o600) {
            rb.restore_now();
            return Err(error);
        }
        let scanned = match super::capture::fingerprint(&repo) {
            Ok(fp) => fp,
            Err(error) => {
                rb.restore_now();
                return Err(error);
            }
        };
        Ok((hex::encode(Sha256::digest(&bytes)), scanned, rb))
    })
    .await?;

    // Phase 3: short FOR UPDATE commit transaction; roll back disk if rejected before COMMIT.
    let mut commit_sent = false;
    let outcome: Result<Value, Error> = async {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let ws =
            service::locked(&tx, &actor, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite).await?;
        if let Some(replayed) = check_idempotency(&tx, id, &key, &hash).await? {
            tx.commit().await.map_err(Error::internal)?;
            return Ok(replayed);
        }
        check_lease_live(&tx, id, state.storage.volume_id, input.lease_epoch).await?;
        if ws.revision != input.expected_workspace_revision {
            return Err(service::conflict());
        }
        let prior: i64 = tx
            .query_opt(
                "SELECT entry_version FROM workspace_entries WHERE workspace_id=$1 AND path=$2 FOR UPDATE",
                &[&id, &raw_path],
            )
            .await
            .map_err(Error::internal)?
            .map(|r| r.get(0))
            .unwrap_or(0);
        if prior != input.expected_entry_version {
            return Err(service::conflict());
        }
        let version = prior + 1;
        tx.execute(
            "INSERT INTO workspace_entries(workspace_id,path,entry_version,digest) VALUES($1,$2,$3,$4) \
             ON CONFLICT(workspace_id,path) DO UPDATE SET entry_version=$3,digest=$4,deleted=false",
            &[&id, &raw_path, &version, &digest],
        )
        .await
        .map_err(Error::internal)?;
        let revision = ws.revision + 1;
        let result = json!({
            "path": raw_path,
            "entry_version": version,
            "workspace_revision": revision,
            "sha256": digest,
            "lease_epoch": input.lease_epoch
        });
        tx.execute(
            "UPDATE workspaces SET revision=$2,lease_until=clock_timestamp()+interval '5 minutes' WHERE id=$1",
            &[&id, &revision],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO workspace_events(workspace_id,revision,kind,payload) VALUES($1,$2,'file_put',$3)",
            &[&id, &revision, &result],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO workspace_operations(id,workspace_id,idempotency_key,request_sha256,kind,state,result) \
             VALUES($1,$2,$3,$4,'file_put','committed',$5)",
            &[&Uuid::new_v4(), &id, &key, &hash, &result],
        )
        .await
        .map_err(Error::internal)?;
        super::capture::record_fingerprint(&tx, id, &scanned).await?;
        commit_sent = true;
        put_rb.disarm();
        tx.commit().await.map_err(Error::internal)?;
        Ok(result)
    }
    .await;

    if !commit_sent {
        put_rb.rollback().await;
    }
    outcome
}

pub async fn git(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<GitAction>,
) -> Result<Json<Value>, Error> {
    let permit = super::git::try_slot(&state)?;
    let response = super::git::spawn_job(git_mutation(state, headers, id, input, permit));
    match response.await {
        Ok(result) => result.map(Json),
        Err(_) => Err(Error::internal("owned workspace Git job ended without a result")),
    }
}

async fn git_mutation(
    state: Arc<AppState>,
    headers: HeaderMap,
    id: Uuid,
    input: GitAction,
    permit: OwnedSemaphorePermit,
) -> Result<Value, Error> {
    let _permit = permit;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = auth::idempotency_key(&headers)?.ok_or_else(Error::bad_request)?.to_owned();
    let request_hash = hex::encode(Sha256::digest(
        serde_json::to_vec(&(
            &input.action,
            &input.paths,
            input.expected_git_generation,
            input.expected_workspace_revision,
            input.lease_epoch,
        ))
        .map_err(Error::internal)?,
    ));
    let _mutation = super::blocking::lock_mutation(id, state.config.git_timeout).await?;

    // Phase 1: short pre-check transaction without holding DB locks across Git or FS work.
    {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let ws =
            service::locked(&tx, &actor, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite).await?;
        if let Some(replayed) = check_idempotency(&tx, id, &key, &request_hash).await? {
            tx.commit().await.map_err(Error::internal)?;
            return Ok(replayed);
        }
        check_lease_live(&tx, id, state.storage.volume_id, input.lease_epoch).await?;
        if ws.revision != input.expected_workspace_revision || ws.git_generation != input.expected_git_generation {
            return Err(service::conflict());
        }
        tx.commit().await.map_err(Error::internal)?;
    }

    let paths = input.paths.unwrap_or_default();
    if paths.len() > 128 {
        return Err(Error::bad_request());
    }
    let mut args: Vec<&str> = match input.action.as_str() {
        "add" if !paths.is_empty() => vec!["add", "--"],
        "reset" if !paths.is_empty() => vec!["reset", "HEAD", "--"],
        _ => return Err(Error::bad_request()),
    };
    args.extend(paths.iter().map(String::as_str));

    // Phase 2: snapshot .git/index and .git/objects, run Git, and compute baseline.
    let repo = service::workspace_repo(&state, id);
    let upper_root = upper_fallback_root(&state, id);
    let repo_cap = repo.clone();
    let paths_cap = paths.clone();
    let mut git_rb = super::blocking::run(move || GitRollback::capture(&repo_cap, &paths_cap, upper_root)).await?;

    let output =
        match super::git::run_in_job_with_git(&state.config.git, &repo, &args, 64 * 1024, state.config.git_timeout)
            .await
        {
            Ok(out) => out,
            Err(error) => {
                git_rb.rollback().await;
                return Err(error);
            }
        };
    let repo_fp = repo.clone();
    let scanned = match super::blocking::run(move || super::capture::fingerprint(&repo_fp)).await {
        Ok(fp) => fp,
        Err(error) => {
            git_rb.rollback().await;
            return Err(error);
        }
    };

    // Phase 3: short FOR UPDATE commit transaction; roll back .git state if rejected before COMMIT.
    let mut commit_sent = false;
    let outcome: Result<Value, Error> = async {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let ws =
            service::locked(&tx, &actor, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite).await?;
        if let Some(replayed) = check_idempotency(&tx, id, &key, &request_hash).await? {
            tx.commit().await.map_err(Error::internal)?;
            return Ok(replayed);
        }
        check_lease_live(&tx, id, state.storage.volume_id, input.lease_epoch).await?;
        if ws.revision != input.expected_workspace_revision || ws.git_generation != input.expected_git_generation {
            return Err(service::conflict());
        }
        let revision = ws.revision + 1;
        let generation = ws.git_generation + 1;
        let result = json!({
            "action": input.action,
            "workspace_revision": revision,
            "git_generation": generation,
            "output_base64": STANDARD.encode(output)
        });
        tx.execute(
            "UPDATE workspaces SET revision=$2,git_generation=$3,lease_until=clock_timestamp()+interval '5 minutes' WHERE id=$1",
            &[&id, &revision, &generation],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO workspace_events(workspace_id,revision,kind,payload) VALUES($1,$2,'git',$3)",
            &[&id, &revision, &result],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO workspace_operations(id,workspace_id,idempotency_key,request_sha256,kind,state,result) \
             VALUES($1,$2,$3,$4,'git','committed',$5)",
            &[&Uuid::new_v4(), &id, &key, &request_hash, &result],
        )
        .await
        .map_err(Error::internal)?;
        super::capture::record_fingerprint(&tx, id, &scanned).await?;
        commit_sent = true;
        git_rb.disarm();
        tx.commit().await.map_err(Error::internal)?;
        Ok(result)
    }
    .await;

    if !commit_sent {
        git_rb.rollback().await;
    }
    outcome
}
