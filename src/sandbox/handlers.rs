use super::{export, runner, terminal};
use crate::{AppState, Error, members::models::Role, workspaces::service};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub argv: Vec<String>,
    pub timeout_seconds: Option<u64>,
    pub lease_epoch: i64,
    pub workspace_access: Option<String>,
    pub ci_run_id: Option<Uuid>,
    pub ci_attempt: Option<i64>,
    pub ci_lease_generation: Option<i64>,
    #[serde(default)]
    pub terminal: bool,
}
#[derive(Serialize)]
pub struct Job {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub state: String,
    pub exit_code: Option<i32>,
    pub timeout_seconds: i32,
    pub terminal: bool,
}

fn job(row: &tokio_postgres::Row) -> Job {
    Job {
        id: row.get("id"),
        workspace_id: row.get("workspace_id"),
        state: row.get("state"),
        exit_code: row.get("exit_code"),
        timeout_seconds: row.get("timeout_seconds"),
        terminal: row.get("terminal"),
    }
}
async fn authorized_job(state: &AppState, headers: &HeaderMap, id: Uuid) -> Result<Job, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT id,workspace_id,state,exit_code,timeout_seconds,terminal FROM sandbox_jobs WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if row.get::<_, Option<Uuid>>("workspace_id").is_none() {
        return Err(Error::not_found());
    }
    let job = job(&row);
    service::authorized(state, headers, job.workspace_id, Role::Read, crate::token_scopes::RepoAction::WorkspacesRead)
        .await?;
    Ok(job)
}

pub async fn start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Start>,
) -> Result<(StatusCode, Json<Job>), Error> {
    let ws = service::authorized(&state, &headers, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite)
        .await?;
    if ws.lease_epoch != input.lease_epoch || ws.host_id != state.storage.volume_id {
        return Err(service::conflict());
    }
    let timeout = input.timeout_seconds.unwrap_or(60);
    if !(1..=3600).contains(&timeout)
        || input.argv.is_empty()
        || input.argv.len() > 64
        || input.argv.iter().any(|s| s.is_empty() || s.len() > 4096 || s.contains('\0'))
    {
        return Err(Error::bad_request());
    }
    if input.ci_run_id.is_some() != input.ci_attempt.is_some()
        || input.ci_run_id.is_some() != input.ci_lease_generation.is_some()
    {
        return Err(Error::bad_request());
    }
    // CI attempts must be claimed by the CI runner adapter, not arbitrary user
    // requests. The binding columns are reserved until that adapter is wired.
    if input.ci_run_id.is_some() {
        return Err(Error(StatusCode::FORBIDDEN, "CI runner capability required"));
    }
    let live_workspace = match input.workspace_access.as_deref().unwrap_or("private") {
        "private" => false,
        "live"
            if crate::workspaces::mounts::enabled()
                && crate::workspaces::mounts::mounted(id)
                && std::env::var("ROOTYARD_SANDBOX_MODE").as_deref() == Ok("dev") =>
        {
            true
        }
        _ => return Err(Error::bad_request()),
    };
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    // A shared workspace-row lock serializes admission with lease-epoch handoff.
    let lease_live: bool=tx.query_one("SELECT lease_epoch=$2 AND host_id=$3 AND lease_until>clock_timestamp() FROM workspaces WHERE id=$1 FOR SHARE", &[&id,&input.lease_epoch,&state.storage.volume_id]).await.map_err(Error::internal)?.get(0);
    if !lease_live {
        return Err(service::conflict());
    }
    let job_id = Uuid::new_v4();
    let argv = json!(input.argv);
    let access = if live_workspace { "live" } else { "private" };
    tx.execute("INSERT INTO sandbox_jobs(id,workspace_id,actor_id,host_id,state,argv,timeout_seconds,lease_epoch,workspace_access,terminal) VALUES($1,$2,$3,$4,'queued',$5,$6,$7,$8,$9)", &[&job_id,&id,&ws.creator_id,&state.storage.volume_id,&argv,&(timeout as i32),&input.lease_epoch,&access,&input.terminal]).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    let args: Vec<String> = serde_json::from_value(argv).map_err(Error::internal)?;
    if runner::launch(state.clone(), job_id, id, args, timeout, live_workspace, input.terminal).await.is_err() {
        client
            .execute("UPDATE sandbox_jobs SET state='failed',finished_at=clock_timestamp() WHERE id=$1", &[&job_id])
            .await
            .map_err(Error::internal)?;
        return Err(Error::internal("sandbox launch failed"));
    }
    let row = client
        .query_one(
            "SELECT id,workspace_id,state,exit_code,timeout_seconds,terminal FROM sandbox_jobs WHERE id=$1",
            &[&job_id],
        )
        .await
        .map_err(Error::internal)?;
    Ok((StatusCode::CREATED, Json(job(&row))))
}

pub async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Job>, Error> {
    Ok(Json(authorized_job(&state, &headers, id).await?))
}
pub async fn stop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Job>, Error> {
    let existing = authorized_job(&state, &headers, id).await?;
    service::authorized(
        &state,
        &headers,
        existing.workspace_id,
        Role::Write,
        crate::token_scopes::RepoAction::WorkspacesWrite,
    )
    .await?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    client.execute("UPDATE sandbox_jobs SET state='cancelled',finished_at=clock_timestamp() WHERE id=$1 AND state IN ('queued','preparing','running')", &[&id]).await.map_err(Error::internal)?;
    let row = client
        .query_one(
            "SELECT id,workspace_id,state,exit_code,timeout_seconds,terminal FROM sandbox_jobs WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(Error::internal)?;
    Ok(Json(job(&row)))
}
pub async fn logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    authorized_job(&state, &headers, id).await?;
    Ok(Json(export::logs(&runner::job_root(&state, id), export::LOG_LIMIT)?))
}

/// Remove a terminal job's retained logs and artifacts. The result row remains
/// as the durable job identity; a second request is an idempotent no-op.
pub async fn cleanup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    let existing = authorized_job(&state, &headers, id).await?;
    service::authorized(
        &state,
        &headers,
        existing.workspace_id,
        Role::Write,
        crate::token_scopes::RepoAction::WorkspacesWrite,
    )
    .await?;
    export::require_terminal(&state, id).await?;
    let removed = runner::cleanup_job(&state, id)?;
    Ok(Json(json!({"id":id,"removed":removed})))
}

async fn terminal_job(state: &AppState, headers: &HeaderMap, id: Uuid, write: bool) -> Result<Job, Error> {
    let job = authorized_job(state, headers, id).await?;
    if !job.terminal {
        return Err(Error::not_found());
    }
    if write {
        service::authorized(
            state,
            headers,
            job.workspace_id,
            Role::Write,
            crate::token_scopes::RepoAction::WorkspacesWrite,
        )
        .await?;
        if job.state != "running" {
            return Err(Error(StatusCode::CONFLICT, "terminal is not running"));
        }
    }
    Ok(job)
}
pub async fn terminal_input(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<terminal::Input>,
) -> Result<Json<Value>, Error> {
    terminal_job(&state, &headers, id, true).await?;
    Ok(Json(terminal::write_input(id, input)?))
}
pub async fn terminal_output(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<terminal::OutputQuery>,
) -> Result<Json<Value>, Error> {
    terminal_job(&state, &headers, id, false).await?;
    Ok(Json(terminal::read_output(&runner::job_root(&state, id).join("stdout.log"), query)?))
}
pub async fn terminal_resize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(size): Json<terminal::Resize>,
) -> Result<Json<Value>, Error> {
    terminal_job(&state, &headers, id, true).await?;
    terminal::resize(id, size.rows, size.columns)?;
    Ok(Json(json!({"rows":size.rows,"columns":size.columns})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactQuery {
    pub path: String,
}

pub async fn artifact(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<ArtifactQuery>,
) -> Result<Json<Value>, Error> {
    authorized_job(&state, &headers, id).await?;
    export::require_terminal(&state, id).await?;
    Ok(Json(export::artifact(&runner::artifacts_root(&state, id), &query.path)?))
}
