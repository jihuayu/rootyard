use super::{models::{CheckpointRequest, ForkRequest, RestoreRequest, WS_COLUMNS, Workspace}, service};
use crate::{AppState, Error, auth, members::models::Role, workspace_lab::core};
use axum::{Json, extract::{Path, State}, http::{HeaderMap, StatusCode}};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path as FsPath, sync::Arc};
use uuid::Uuid;

fn copy_snapshot(source: &FsPath, dest: &FsPath) -> Result<(), Error> {
    if let Some(parent) = dest.parent() { fs::create_dir_all(parent).map_err(Error::internal)?; }
    core::copy_all(source,dest).map_err(Error::internal)?;
    core::sync_tree(dest).map_err(Error::internal)
}
fn valid_agent(value: &str) -> bool { !value.is_empty() && value.len()<=128 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) }

pub async fn create(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<CheckpointRequest>) -> Result<(StatusCode,Json<Value>), Error> {
    let actor = auth::authenticate(&state.pool,&headers).await?;
    let key = auth::idempotency_key(&headers)?.ok_or_else(Error::bad_request)?.to_owned();
    let hash = hex::encode(Sha256::digest(format!("checkpoint:{}:{}",input.expected_workspace_revision,input.lease_epoch)));
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx.query_opt(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1 FOR UPDATE"), &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let ws = Workspace::from_row(&row);
    auth::authorize_repo_with_role(&tx,&actor,&ws.owner,&ws.repository,Role::Write).await?;
    if ws.creator_id != actor.id || ws.state != "ready" { return Err(Error::not_found()); }
    if let Some(row) = tx.query_opt("SELECT request_sha256,state,result FROM workspace_operations WHERE workspace_id=$1 AND idempotency_key=$2", &[&id,&key]).await.map_err(Error::internal)? {
        if row.get::<_,String>(0)!=hash { return Err(service::conflict()); }
        if row.get::<_,String>(1)=="committed" { return Ok((StatusCode::OK,Json(row.get(2)))); }
        return Err(service::conflict());
    }
    let lease_ok: bool = tx.query_one("SELECT host_id=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() FROM workspaces WHERE id=$1", &[&id,&state.storage.volume_id,&input.lease_epoch]).await.map_err(Error::internal)?.get(0);
    if !lease_ok || ws.revision!=input.expected_workspace_revision { return Err(service::conflict()); }
    let cp = Uuid::new_v4();
    let source = service::workspace_repo(&state,id);
    let dest = service::checkpoint_repo(&state,cp);
    // Check the native index and worktree around the immutable copy. A changed
    // source is rejected; external editors are not fenced by this DB lock.
    let before = service::git(&source,&["status","--porcelain=v1","-z","--untracked-files=all"])?;
    let before_index = fs::read(source.join(".git/index")).unwrap_or_default();
    copy_snapshot(&source,&dest)?;
    let after = service::git(&source,&["status","--porcelain=v1","-z","--untracked-files=all"])?;
    let after_index = fs::read(source.join(".git/index")).unwrap_or_default();
    if before!=after || before_index!=after_index {
        let _ = fs::remove_dir_all(&dest); return Err(service::conflict());
    }
    let revision = ws.revision+1;
    let result = json!({"checkpoint_id":cp,"workspace_id":id,"captured_revision":ws.revision,"workspace_revision":revision,"state":"local_complete","durability":"local_filesystem_only","excluded_native_state":"none"});
    tx.execute("INSERT INTO workspace_checkpoints(id,workspace_id,repository_id,captured_revision,lease_epoch,state,excluded_summary) VALUES($1,$2,$3,$4,$5,'local_complete',$6)", &[&cp,&id,&ws.repository_id,&ws.revision,&ws.lease_epoch,&json!({"native_entries":"included"})]).await.map_err(Error::internal)?;
    tx.execute("UPDATE workspaces SET revision=$2,last_checkpoint_id=$3,lease_until=clock_timestamp()+interval '5 minutes' WHERE id=$1", &[&id,&revision,&cp]).await.map_err(Error::internal)?;
    tx.execute("INSERT INTO workspace_events(workspace_id,revision,kind,payload) VALUES($1,$2,'checkpoint',$3)", &[&id,&revision,&result]).await.map_err(Error::internal)?;
    tx.execute("INSERT INTO workspace_operations(id,workspace_id,idempotency_key,request_sha256,kind,state,result) VALUES($1,$2,$3,$4,'checkpoint','committed',$5)", &[&Uuid::new_v4(),&id,&key,&hash,&result]).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok((StatusCode::CREATED,Json(result)))
}

async fn restore_inner(state: Arc<AppState>, headers: HeaderMap, cp: Uuid, agent: String) -> Result<(StatusCode,Json<Workspace>),Error> {
    if !valid_agent(&agent) { return Err(Error::bad_request()); }
    let actor = auth::authenticate(&state.pool,&headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx.query_opt("SELECT w.id,w.repository_id,w.owner_slug,w.repository_name,w.agent_id,w.creator_id,w.state,w.host_id,w.lease_epoch,w.revision,w.git_generation,w.last_checkpoint_id FROM workspace_checkpoints c JOIN workspaces w ON w.id=c.workspace_id WHERE c.id=$1 AND c.state IN ('local_complete','committed')", &[&cp]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let parent = Workspace::from_row(&row);
    auth::authorize_repo_with_role(&tx,&actor,&parent.owner,&parent.repository,Role::Write).await?;
    if parent.creator_id != actor.id { return Err(Error::not_found()); }
    let id = Uuid::new_v4();
    copy_snapshot(&service::checkpoint_repo(&state,cp),&service::workspace_repo(&state,id))?;
    tx.execute("INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,parent_checkpoint_id,state,host_id,lease_until) VALUES($1,$2,$3,$4,$5,$6,$7,'ready',$8,clock_timestamp()+interval '5 minutes')", &[&id,&parent.repository_id,&parent.owner,&parent.repository,&agent,&actor.id,&cp,&state.storage.volume_id]).await.map_err(Error::internal)?;
    let row = tx.query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id]).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok((StatusCode::CREATED,Json(Workspace::from_row(&row))))
}

pub async fn restore(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<RestoreRequest>) -> Result<(StatusCode,Json<Workspace>),Error> {
    restore_inner(state,headers,id,input.agent_id).await
}
pub async fn fork(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<ForkRequest>) -> Result<(StatusCode,Json<Workspace>),Error> {
    let ws = service::authorized(&state,&headers,id,Role::Write).await?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client.query_opt("SELECT workspace_id FROM workspace_checkpoints WHERE id=$1", &[&input.checkpoint_id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    if row.get::<_,Uuid>(0)!=ws.id { return Err(Error::not_found()); }
    restore_inner(state,headers,input.checkpoint_id,input.new_agent_id).await
}
