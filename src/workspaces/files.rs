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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

fn safe_path(raw: &str) -> Result<PathBuf, Error> {
    Ok(PathBuf::from(crate::browse::models::normalize_rel_path(Some(raw))?))
}
fn safe_file(repo: &FsPath, raw: &str) -> Result<PathBuf, Error> {
    let rel = safe_path(raw)?;
    if rel.as_os_str().is_empty() {
        return Err(Error::bad_request());
    }
    let path = repo.join(rel);
    let mut cur = repo.to_path_buf();
    for seg in path.strip_prefix(repo).map_err(Error::internal)?.components() {
        cur.push(seg);
        if let Ok(meta) = fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                return Err(Error::bad_request());
            }
        }
    }
    Ok(path)
}
fn atomic_put(path: &FsPath, bytes: &[u8]) -> Result<(), Error> {
    let parent = path.parent().ok_or_else(Error::bad_request)?;
    fs::create_dir_all(parent).map_err(Error::internal)?;
    let tmp = parent.join(format!(".rootyard-{}", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(Error::internal)?;
    file.write_all(bytes).map_err(Error::internal)?;
    file.sync_all().map_err(Error::internal)?;
    drop(file);
    fs::rename(&tmp, path).map_err(Error::internal)?;
    File::open(parent).and_then(|d| d.sync_all()).map_err(Error::internal)?;
    Ok(())
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<FileQuery>,
) -> Result<Json<Value>, Error> {
    let ws = service::authorized(&state, &headers, id, Role::Read).await?;
    let repo = service::workspace_repo(&state, id);
    let rel = safe_path(&query.path)?;
    let raw = match query.view.as_deref().unwrap_or("working") {
        "working" => {
            let path = safe_file(&repo, &query.path)?;
            fs::read(path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound { Error::not_found() } else { Error::internal(error) }
            })?
        }
        "head" => service::git(&repo, &["show", &format!("HEAD:{}", rel.display())])?,
        "index" => service::git(&repo, &["show", &format!(":{}", rel.display())])?,
        _ => return Err(Error::bad_request()),
    };
    if raw.len() > 4 * 1024 * 1024 {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "file too large"));
    }
    let client = state.pool.get().await.map_err(Error::internal)?;
    let version: i64 = client
        .query_opt("SELECT entry_version FROM workspace_entries WHERE workspace_id=$1 AND path=$2", &[&id, &query.path])
        .await
        .map_err(Error::internal)?
        .map(|r| r.get(0))
        .unwrap_or(0);
    Ok(Json(
        json!({"path":query.path,"view":query.view.unwrap_or_else(||"working".into()),"content_base64":STANDARD.encode(&raw),"sha256":hex::encode(Sha256::digest(&raw)),"entry_version":version,"workspace_revision":ws.revision,"captured":false,"durability":"live_local"}),
    ))
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
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "file too large"));
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = auth::idempotency_key(&headers)?.ok_or_else(Error::bad_request)?.to_owned();
    let hash = hex::encode(Sha256::digest(
        serde_json::to_vec(&(
            &query.path,
            &input.content_base64,
            input.expected_entry_version,
            input.expected_workspace_revision,
            input.lease_epoch,
        ))
        .map_err(Error::internal)?,
    ));
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ws = service::locked(&tx, &actor, id, Role::Write).await?;
    if let Some(row) = tx
        .query_opt(
            "SELECT request_sha256,state,result FROM workspace_operations WHERE workspace_id=$1 AND idempotency_key=$2",
            &[&id, &key],
        )
        .await
        .map_err(Error::internal)?
    {
        let old: String = row.get(0);
        if old != hash {
            return Err(service::conflict());
        }
        if row.get::<_, String>(1) == "committed" {
            return Ok(Json(row.get(2)));
        }
        return Err(service::conflict());
    }
    let lease_ok: bool = tx
        .query_one(
            "SELECT host_id=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() FROM workspaces WHERE id=$1",
            &[&id, &state.storage.volume_id, &input.lease_epoch],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    if !lease_ok || ws.revision != input.expected_workspace_revision {
        return Err(service::conflict());
    }
    let prior: i64 = tx
        .query_opt("SELECT entry_version FROM workspace_entries WHERE workspace_id=$1 AND path=$2", &[&id, &query.path])
        .await
        .map_err(Error::internal)?
        .map(|r| r.get(0))
        .unwrap_or(0);
    if prior != input.expected_entry_version {
        return Err(service::conflict());
    }
    let path = safe_file(&service::workspace_repo(&state, id), &query.path)?;
    atomic_put(&path, &bytes)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let version = prior + 1;
    tx.execute("INSERT INTO workspace_entries(workspace_id,path,entry_version,digest) VALUES($1,$2,$3,$4) ON CONFLICT(workspace_id,path) DO UPDATE SET entry_version=$3,digest=$4,deleted=false", &[&id,&query.path,&version,&digest]).await.map_err(Error::internal)?;
    let revision = ws.revision + 1;
    let result = json!({"path":query.path,"entry_version":version,"workspace_revision":revision,"sha256":digest,"lease_epoch":input.lease_epoch});
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
    tx.execute("INSERT INTO workspace_operations(id,workspace_id,idempotency_key,request_sha256,kind,state,result) VALUES($1,$2,$3,$4,'file_put','committed',$5)", &[&Uuid::new_v4(),&id,&key,&hash,&result]).await.map_err(Error::internal)?;
    super::capture::record_current(&tx, &state, id).await?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(Json(result))
}

pub async fn git(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<GitAction>,
) -> Result<Json<Value>, Error> {
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
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ws = service::locked(&tx, &actor, id, Role::Write).await?;
    if let Some(row) = tx
        .query_opt(
            "SELECT request_sha256,state,result FROM workspace_operations WHERE workspace_id=$1 AND idempotency_key=$2",
            &[&id, &key],
        )
        .await
        .map_err(Error::internal)?
    {
        if row.get::<_, String>(0) != request_hash {
            return Err(service::conflict());
        }
        if row.get::<_, String>(1) == "committed" {
            return Ok(Json(row.get(2)));
        }
        return Err(service::conflict());
    }
    let lease_ok: bool = tx
        .query_one(
            "SELECT host_id=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() FROM workspaces WHERE id=$1",
            &[&id, &state.storage.volume_id, &input.lease_epoch],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    if !lease_ok
        || ws.revision != input.expected_workspace_revision
        || ws.git_generation != input.expected_git_generation
    {
        return Err(service::conflict());
    }
    let paths = input.paths.unwrap_or_default();
    if paths.len() > 128 {
        return Err(Error::bad_request());
    }
    for path in &paths {
        safe_file(&service::workspace_repo(&state, id), path)?;
    }
    let mut args: Vec<&str> = match input.action.as_str() {
        "add" if !paths.is_empty() => vec!["add", "--"],
        "reset" if !paths.is_empty() => vec!["reset", "HEAD", "--"],
        _ => return Err(Error::bad_request()),
    };
    args.extend(paths.iter().map(String::as_str));
    let output = service::git(&service::workspace_repo(&state, id), &args)?;
    let revision = ws.revision + 1;
    let generation = ws.git_generation + 1;
    let result = json!({"action":input.action,"workspace_revision":revision,"git_generation":generation,"output_base64":STANDARD.encode(output)});
    tx.execute("UPDATE workspaces SET revision=$2,git_generation=$3,lease_until=clock_timestamp()+interval '5 minutes' WHERE id=$1", &[&id,&revision,&generation]).await.map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO workspace_events(workspace_id,revision,kind,payload) VALUES($1,$2,'git',$3)",
        &[&id, &revision, &result],
    )
    .await
    .map_err(Error::internal)?;
    tx.execute("INSERT INTO workspace_operations(id,workspace_id,idempotency_key,request_sha256,kind,state,result) VALUES($1,$2,$3,$4,'git','committed',$5)", &[&Uuid::new_v4(),&id,&key,&request_hash,&result]).await.map_err(Error::internal)?;
    super::capture::record_current(&tx, &state, id).await?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(Json(result))
}
