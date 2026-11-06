use super::models::{CreateWorkspace, LeaseRequest, WS_COLUMNS, Workspace};
use crate::{AppState, Error, auth, members::models::Role};
use axum::{Json, extract::{Path, State}, http::{HeaderMap, StatusCode}};
use sha2::{Digest, Sha256};
use std::{path::{Path as FsPath, PathBuf}, process::Command, sync::Arc};
use uuid::Uuid;

pub fn workspace_root(state: &AppState) -> PathBuf { state.storage.root.join("workspace-service") }
pub fn workspace_repo(state: &AppState, id: Uuid) -> PathBuf { workspace_root(state).join("workspaces").join(id.to_string()) }
pub fn checkpoint_repo(state: &AppState, id: Uuid) -> PathBuf { workspace_root(state).join("checkpoints").join(id.to_string()) }
pub fn conflict() -> Error { Error(StatusCode::CONFLICT, "workspace version or lease conflict") }

pub fn git(repo: &FsPath, args: &[&str]) -> Result<Vec<u8>, Error> {
    let output = Command::new("git").arg("-c").arg("core.hooksPath=/dev/null")
        .arg("--no-replace-objects").arg("-C").arg(repo).args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0").env("GIT_OPTIONAL_LOCKS", "0")
        .output().map_err(Error::internal)?;
    if !output.status.success() { return Err(conflict()); }
    Ok(output.stdout)
}

pub fn clone_repo(source: &FsPath, dest: &FsPath) -> Result<(), Error> {
    if let Some(parent) = dest.parent() { std::fs::create_dir_all(parent).map_err(Error::internal)?; }
    let output = Command::new("git").args(["-c", "core.hooksPath=/dev/null", "clone", "--no-hardlinks", "--"])
        .arg(source).arg(dest).env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_TERMINAL_PROMPT", "0")
        .output().map_err(Error::internal)?;
    if !output.status.success() { return Err(Error::internal("native git clone failed")); }
    Ok(())
}

pub async fn authorized(state: &AppState, headers: &HeaderMap, id: Uuid, role: Role) -> Result<Workspace, Error> {
    let actor = auth::authenticate(&state.pool, headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let sql = format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1");
    let row = tx.query_opt(&sql, &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let ws = Workspace::from_row(&row);
    let access=auth::authorize_repo_with_role(&tx, &actor, &ws.owner, &ws.repository, role).await?;
    if access.repo_id!=ws.repository_id{return Err(Error::not_found());}
    if ws.creator_id != actor.id || ws.state != "ready" { return Err(Error::not_found()); }
    tx.commit().await.map_err(Error::internal)?;
    Ok(ws)
}

pub async fn locked(tx:&deadpool_postgres::Transaction<'_>,actor:&crate::db::Identity,id:Uuid,role:Role)->Result<Workspace,Error>{
    let sql=format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1");
    let row=tx.query_opt(&sql,&[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let initial=Workspace::from_row(&row);
    let access=auth::authorize_repo_with_role(tx,actor,&initial.owner,&initial.repository,role).await?;
    if access.repo_id!=initial.repository_id{return Err(Error::not_found());}
    let row=tx.query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1 FOR UPDATE"),&[&id]).await.map_err(Error::internal)?;
    let ws=Workspace::from_row(&row);
    if ws.repository_id!=initial.repository_id || ws.creator_id!=initial.creator_id || ws.owner!=initial.owner || ws.repository!=initial.repository || ws.creator_id!=actor.id || ws.state!="ready" {return Err(Error::not_found());}
    Ok(ws)
}

pub async fn get(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Workspace>, Error> {
    Ok(Json(authorized(&state, &headers, id, Role::Read).await?))
}

pub async fn lease(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<LeaseRequest>) -> Result<Json<Workspace>,Error> {
    let actor=auth::authenticate(&state.pool,&headers).await?;
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    let ws=locked(&tx,&actor,id,Role::Write).await?;
    if ws.lease_epoch!=input.expected_lease_epoch || !workspace_repo(&state,id).join(".git").is_dir(){return Err(conflict());}
    let changed=tx.execute("UPDATE workspaces SET host_id=$2,lease_epoch=lease_epoch+1,lease_until=clock_timestamp()+interval '5 minutes' WHERE id=$1 AND lease_epoch=$3 AND (host_id=$2 OR lease_until<=clock_timestamp())", &[&id,&state.storage.volume_id,&input.expected_lease_epoch]).await.map_err(Error::internal)?;
    if changed!=1{return Err(conflict());}
    let row=tx.query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id]).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(Json(Workspace::from_row(&row)))
}

pub async fn fence_restored(pool:&deadpool_postgres::Pool)->Result<(),Error>{
    let mut client=pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    tx.execute("UPDATE workspaces SET lease_epoch=lease_epoch+1,lease_until=clock_timestamp()-interval '1 second' WHERE state='ready'", &[]).await.map_err(Error::internal)?;
    tx.execute("UPDATE sandbox_jobs SET state='cancelled',pid=NULL,finished_at=clock_timestamp() WHERE state IN ('queued','running')", &[]).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)
}

pub async fn create(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(input): Json<CreateWorkspace>) -> Result<(StatusCode, Json<Workspace>), Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = auth::idempotency_key(&headers)?.ok_or_else(Error::bad_request)?.to_owned();
    if input.agent_id.is_empty() || input.agent_id.len() > 128 || !input.agent_id.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)) { return Err(Error::bad_request()); }
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&(&input.owner, &input.repository, &input.agent_id, &input.base_oid)).map_err(Error::internal)?));
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = auth::authorize_repo_with_role(&tx, &actor, &input.owner, &input.repository, Role::Write).await?;
    if let Some(row) = tx.query_opt("SELECT request_sha256,workspace_id FROM workspace_creations WHERE actor_id=$1 AND idempotency_key=$2 FOR UPDATE", &[&actor.id,&key]).await.map_err(Error::internal)? {
        let existing: String = row.get(0);
        if existing != digest { return Err(conflict()); }
        let id: Uuid = row.get(1);
        let row = tx.query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id]).await.map_err(Error::internal)?;
        return Ok((StatusCode::OK, Json(Workspace::from_row(&row))));
    }
    let id = Uuid::new_v4();
    let source = state.storage.verify_path(repo.repo_id).map_err(Error::internal)?;
    let dest = workspace_repo(&state, id);
    clone_repo(&source, &dest)?;
    if let Some(base) = &input.base_oid {
        if !crate::browse::models::valid_non_zero_oid(base) { return Err(Error::bad_request()); }
        let head = String::from_utf8(git(&dest, &["rev-parse", "HEAD"])?).map_err(Error::internal)?;
        if head.trim() != base { return Err(conflict()); }
    }
    let host_id = state.storage.volume_id;
    tx.execute("INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,state,host_id,lease_until) VALUES($1,$2,$3,$4,$5,$6,'ready',$7,clock_timestamp()+interval '5 minutes')", &[&id,&repo.repo_id,&input.owner,&input.repository,&input.agent_id,&actor.id,&host_id]).await.map_err(Error::internal)?;
    tx.execute("INSERT INTO workspace_creations(actor_id,idempotency_key,request_sha256,workspace_id) VALUES($1,$2,$3,$4)", &[&actor.id,&key,&digest,&id]).await.map_err(Error::internal)?;
    super::capture::record_current(&tx,&state,id).await?;
    let row = tx.query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id]).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok((StatusCode::CREATED, Json(Workspace::from_row(&row))))
}
