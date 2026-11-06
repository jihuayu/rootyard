//! HTTP handlers for commit-bound Check Runs with monotonic `(attempt, sequence)` enforcement.
use crate::{
    AppState, Error, db, git_http,
    auth::{self, authorize_repo as authorize, finish_tx as finish, idempotency_key},
    pulls::models::{
        CHECK_FIELDS, CheckRun, CheckRunInput, Page, body_valid, context_valid, creation_replay,
        json, positive, record_creation, valid_check_status_and_conclusion, valid_format,
        valid_oid, valid_oid_for_format, verify_commit_exists,
    },
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use std::sync::Arc;

async fn authorized_read_lease(state:&AppState,actor:&db::Identity,owner:&str,name:&str,
    write:bool)->Result<(uuid::Uuid,crate::storage::read_leases::Lease),Error>{
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    let repo=authorize(&tx,actor,owner,name,write).await?;
    finish(tx,actor,false).await?;
    drop(client);
    let lease=crate::storage::read_leases::shared(&state.pool,repo,
        tokio::time::Instant::now()+state.config.git_timeout).await?;
    Ok((repo,lease))
}

fn same_repository(expected:uuid::Uuid,actual:uuid::Uuid)->Result<(),Error>{
    if expected==actual {Ok(())}
    else {Err(Error(StatusCode::CONFLICT,"repository identity changed during check request"))}
}

async fn require_repo_oid_format(state:&AppState,repo:uuid::Uuid,oid:&str)->Result<(),Error>{
    let _slot=state.git_slots.clone().try_acquire_owned().map_err(|_|Error(
        StatusCode::SERVICE_UNAVAILABLE,"Git capacity exhausted; retry later"))?;
    let path=state.storage.verify_path(repo).map_err(Error::internal)?;
    let mut cmd=state.storage.git(&state.config);
    cmd.args(["--no-replace-objects","--git-dir"]).arg(path)
        .args(["rev-parse","--show-object-format"]);
    let format=git_http::collect_git_output(cmd,128,state.config.git_timeout).await
        .map_err(Error::internal)?;
    let detected=std::str::from_utf8(&format).map_err(Error::internal)?.trim();
    if !valid_format(detected) || !valid_oid_for_format(oid, detected) {
        return Err(Error(StatusCode::CONFLICT,"check commit OID format differs from repository"));
    }
    Ok(())
}

pub async fn upsert_check_run(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<CheckRunInput>,
) -> Result<Response, Error> {
    let commit_oid = input
        .commit_oid
        .clone()
        .ok_or_else(Error::bad_request)?;
    upsert_check_inner(state, owner, name, commit_oid, headers, input).await
}

pub async fn upsert_commit_check_run(
    State(state): State<Arc<AppState>>,
    Path((owner, name, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(input): Json<CheckRunInput>,
) -> Result<Response, Error> {
    if input
        .commit_oid
        .as_ref()
        .is_some_and(|body_oid| body_oid != &oid)
    {
        return Err(Error::bad_request());
    }
    upsert_check_inner(state, owner, name, oid, headers, input).await
}

async fn upsert_check_inner(
    state: Arc<AppState>,
    owner: String,
    name: String,
    commit_oid: String,
    headers: HeaderMap,
    input: CheckRunInput,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !valid_oid(&commit_oid)
        || !context_valid(&input.context)
        || input.attempt <= 0
        || input.sequence <= 0
        || !valid_check_status_and_conclusion(&input.status, input.conclusion.as_deref())
        || !body_valid(&input.output, false)
    {
        return Err(Error::bad_request());
    }
    let key = idempotency_key(&headers)?;
    let (expected_repo,lease)=authorized_read_lease(&state,&actor,&owner,&name,true).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, true).await?;
    same_repository(expected_repo,repo)?;
    lease.guard(require_repo_oid_format(&state,repo,&commit_oid)).await??;
    lease.ensure_active()?;
    let trusted: bool = tx.query_one(
        "SELECT EXISTS(SELECT 1 FROM forge_trusted_check_contexts WHERE repository_id=$1 AND context=$2)",
        &[&repo,&input.context],
    ).await.map_err(Error::internal)?.get(0);
    if trusted {
        return Err(Error(StatusCode::FORBIDDEN, "trusted CI context requires integration evidence"));
    }

    if let Some(key) = key {
        let request = serde_json::json!({
            "operation": "check_run",
            "commit_oid": commit_oid,
            "context": input.context,
            "status": input.status,
            "conclusion": input.conclusion,
            "attempt": input.attempt,
            "sequence": input.sequence,
            "output": input.output,
        });
        if let Some(response) = creation_replay(&tx, actor.id, repo, key, &request).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::OK, response));
        }
    }

    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })?;
    let exists = lease.guard(verify_commit_exists(&state, repo, &commit_oid)).await??;
    drop(_slot);
    lease.ensure_active()?;
    if !exists {
        return Err(Error(StatusCode::CONFLICT, "commit object not found"));
    }

    let existing = tx
        .query_opt(
            &format!(
                "SELECT {CHECK_FIELDS} FROM forge_check_runs WHERE tenant_id=$1 AND repository_id=$2 AND commit_oid=$3 AND context=$4 FOR UPDATE"
            ),
            &[&actor.id, &repo, &commit_oid, &input.context],
        )
        .await
        .map_err(Error::internal)?;

    let (status_code, check_run) = match existing {
        None => {
            let row = tx
                .query_one(
                    &format!(
                        "INSERT INTO forge_check_runs (tenant_id,repository_id,commit_oid,context,attempt,sequence,status,conclusion,output) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING {CHECK_FIELDS}"
                    ),
                    &[
                        &actor.id,
                        &repo,
                        &commit_oid,
                        &input.context,
                        &input.attempt,
                        &input.sequence,
                        &input.status,
                        &input.conclusion,
                        &input.output,
                    ],
                )
                .await
                .map_err(Error::internal)?;
            (StatusCode::CREATED, CheckRun::row(&row))
        }
        Some(row) => {
            let cur = CheckRun::row(&row);
            let incoming_order = (input.attempt, input.sequence);
            let current_order = (cur.attempt, cur.sequence);
            if incoming_order > current_order {
                let updated = tx
                    .query_one(
                        &format!(
                            "UPDATE forge_check_runs SET attempt=$5,sequence=$6,status=$7,conclusion=$8,output=$9,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND commit_oid=$3 AND context=$4 RETURNING {CHECK_FIELDS}"
                        ),
                        &[
                            &actor.id,
                            &repo,
                            &commit_oid,
                            &input.context,
                            &input.attempt,
                            &input.sequence,
                            &input.status,
                            &input.conclusion,
                            &input.output,
                        ],
                    )
                    .await
                    .map_err(Error::internal)?;
                (StatusCode::OK, CheckRun::row(&updated))
            } else if incoming_order == current_order {
                if cur.status == input.status
                    && cur.conclusion == input.conclusion
                    && cur.output == input.output
                {
                    (StatusCode::OK, cur)
                } else {
                    return Err(Error(
                        StatusCode::CONFLICT,
                        "conflicting check run state for same attempt and sequence",
                    ));
                }
            } else {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "stale check run attempt or sequence",
                ));
            }
        }
    };

    let val = serde_json::to_value(&check_run).map_err(Error::internal)?;
    record_creation(&tx, actor.id, repo, key, &val).await?;
    finish(tx, &actor, true).await?;
    Ok(json(status_code, val))
}

pub async fn list_commit_checks(
    State(state): State<Arc<AppState>>,
    Path((owner, name, oid)): Path<(String, String, String)>,
    Query(page): Query<Page>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !valid_oid(&oid) {
        return Err(Error::bad_request());
    }
    let (after, limit) = page.bounds()?;
    let (expected_repo,lease)=authorized_read_lease(&state,&actor,&owner,&name,false).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    same_repository(expected_repo,repo)?;
    lease.guard(require_repo_oid_format(&state,repo,&oid)).await??;
    lease.ensure_active()?;
    let rows = tx
        .query(
            &format!(
                "SELECT {CHECK_FIELDS} FROM forge_check_runs WHERE tenant_id=$1 AND repository_id=$2 AND commit_oid=$3 ORDER BY context ASC OFFSET $4 LIMIT $5"
            ),
            &[&actor.id, &repo, &oid, &after, &(limit + 1)],
        )
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows
        .iter()
        .take(limit as usize)
        .map(CheckRun::row)
        .collect();
    let next_after = if more { Some(after + limit) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        serde_json::json!({
            "commit_oid": oid,
            "items": items,
            "next_after": next_after,
        }),
    ))
}

pub async fn list_pull_checks(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Query(page): Query<Page>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    let (after, limit) = page.bounds()?;
    let (expected_repo,lease)=authorized_read_lease(&state,&actor,&owner,&name,false).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    same_repository(expected_repo,repo)?;
    let head_oid: String = tx
        .query_opt(
            "SELECT head_oid FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3",
            &[&actor.id, &repo, &number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get("head_oid");
    lease.guard(require_repo_oid_format(&state,repo,&head_oid)).await??;
    lease.ensure_active()?;
    let rows = tx
        .query(
            &format!(
                "SELECT {CHECK_FIELDS} FROM forge_check_runs WHERE tenant_id=$1 AND repository_id=$2 AND commit_oid=$3 ORDER BY context ASC OFFSET $4 LIMIT $5"
            ),
            &[&actor.id, &repo, &head_oid, &after, &(limit + 1)],
        )
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows
        .iter()
        .take(limit as usize)
        .map(CheckRun::row)
        .collect();
    let next_after = if more { Some(after + limit) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        serde_json::json!({
            "pull_number": number,
            "head_oid": head_oid,
            "items": items,
            "next_after": next_after,
        }),
    ))
}
