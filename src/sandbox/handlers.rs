use super::runner;
use crate::{AppState, Error, members::models::Role, workspaces::service};
use axum::{Json, extract::{Path,State}, http::{HeaderMap,StatusCode}};
use base64::{Engine,engine::general_purpose::STANDARD};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use std::{fs,sync::Arc};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start { pub argv: Vec<String>, pub timeout_seconds: Option<u64>, pub lease_epoch: i64, pub ci_run_id: Option<Uuid>, pub ci_attempt: Option<i64>, pub ci_lease_generation: Option<i64> }
#[derive(Serialize)]
pub struct Job { pub id: Uuid, pub workspace_id: Uuid, pub state: String, pub exit_code: Option<i32>, pub timeout_seconds: i32 }

fn job(row: &tokio_postgres::Row) -> Job {
    Job { id:row.get("id"),workspace_id:row.get("workspace_id"),state:row.get("state"),exit_code:row.get("exit_code"),timeout_seconds:row.get("timeout_seconds") }
}
async fn authorized_job(state: &AppState, headers: &HeaderMap, id: Uuid) -> Result<Job,Error> {
    let client=state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_opt("SELECT id,workspace_id,state,exit_code,timeout_seconds FROM sandbox_jobs WHERE id=$1", &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let job=job(&row);
    service::authorized(state,headers,job.workspace_id,Role::Read).await?;
    Ok(job)
}

pub async fn start(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<Start>) -> Result<(StatusCode,Json<Job>),Error> {
    let ws=service::authorized(&state,&headers,id,Role::Write).await?;
    if ws.lease_epoch!=input.lease_epoch || ws.host_id!=state.storage.volume_id { return Err(service::conflict()); }
    let timeout=input.timeout_seconds.unwrap_or(60);
    if !(1..=3600).contains(&timeout) || input.argv.is_empty() || input.argv.len()>64 || input.argv.iter().any(|s|s.is_empty() || s.len()>4096 || s.contains('\0')) { return Err(Error::bad_request()); }
    if input.ci_run_id.is_some() != input.ci_attempt.is_some() || input.ci_run_id.is_some()!=input.ci_lease_generation.is_some() { return Err(Error::bad_request()); }
    // CI attempts must be claimed by the CI runner adapter, not arbitrary user
    // requests. The binding columns are reserved until that adapter is wired.
    if input.ci_run_id.is_some() { return Err(Error(StatusCode::FORBIDDEN,"CI runner capability required")); }
    let client=state.pool.get().await.map_err(Error::internal)?;
    let live: bool=client.query_one("SELECT lease_epoch=$2 AND host_id=$3 AND lease_until>clock_timestamp() FROM workspaces WHERE id=$1", &[&id,&input.lease_epoch,&state.storage.volume_id]).await.map_err(Error::internal)?.get(0);
    if !live { return Err(service::conflict()); }
    let job_id=Uuid::new_v4();
    let argv=json!(input.argv);
    client.execute("INSERT INTO sandbox_jobs(id,workspace_id,actor_id,host_id,state,argv,timeout_seconds) VALUES($1,$2,$3,$4,'queued',$5,$6)", &[&job_id,&id,&ws.creator_id,&state.storage.volume_id,&argv,&(timeout as i32)]).await.map_err(Error::internal)?;
    let args: Vec<String>=serde_json::from_value(argv).map_err(Error::internal)?;
    if runner::launch(state.clone(),job_id,id,args,timeout).await.is_err() {
        client.execute("UPDATE sandbox_jobs SET state='failed',finished_at=clock_timestamp() WHERE id=$1", &[&job_id]).await.map_err(Error::internal)?;
        return Err(Error::internal("sandbox launch failed"));
    }
    let row=client.query_one("SELECT id,workspace_id,state,exit_code,timeout_seconds FROM sandbox_jobs WHERE id=$1", &[&job_id]).await.map_err(Error::internal)?;
    Ok((StatusCode::CREATED,Json(job(&row))))
}

pub async fn status(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Job>,Error> {
    Ok(Json(authorized_job(&state,&headers,id).await?))
}
pub async fn stop(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Job>,Error> {
    let existing=authorized_job(&state,&headers,id).await?;
    service::authorized(&state,&headers,existing.workspace_id,Role::Write).await?;
    let client=state.pool.get().await.map_err(Error::internal)?;
    client.execute("UPDATE sandbox_jobs SET state='cancelled',finished_at=clock_timestamp() WHERE id=$1 AND state IN ('queued','running')", &[&id]).await.map_err(Error::internal)?;
    let row=client.query_one("SELECT id,workspace_id,state,exit_code,timeout_seconds FROM sandbox_jobs WHERE id=$1", &[&id]).await.map_err(Error::internal)?;
    Ok(Json(job(&row)))
}
pub async fn logs(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>,Error> {
    authorized_job(&state,&headers,id).await?;
    let root=runner::job_root(&state,id);
    let stdout=fs::read(root.join("stdout.log")).map_err(Error::internal)?;
    let stderr=fs::read(root.join("stderr.log")).map_err(Error::internal)?;
    if stdout.len()>16*1024*1024 || stderr.len()>16*1024*1024 { return Err(Error::internal("sandbox log limit exceeded")); }
    Ok(Json(json!({"stdout_base64":STANDARD.encode(stdout),"stderr_base64":STANDARD.encode(stderr)})))
}
