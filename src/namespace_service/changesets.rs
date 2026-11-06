use super::handlers;
use crate::{
    auth,
    browse::{
        models::{RefTransactionRequest, RefUpdateInput},
        transactions,
    },
    members::models::Role,
    storage::read_leases,
    workspaces::service,
    AppState, Error,
};
use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepInput {
    pub mount_path: String,
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
    pub storage_generation: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Propose {
    pub steps: Vec<StepInput>,
}
#[derive(Serialize)]
pub struct Step {
    pub ordinal: i32,
    pub repository_id: Uuid,
    pub mount_path: String,
    pub owner: String,
    pub repository: String,
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
    pub storage_generation: i64,
    pub applied: bool,
}
#[derive(Serialize)]
pub struct ChangeSet {
    pub id: Uuid,
    pub namespace_id: Uuid,
    pub state: String,
    pub creator_id: Uuid,
    pub reviewer_id: Option<Uuid>,
    pub steps: Vec<Step>,
}
fn conflict() -> Error {
    Error(StatusCode::CONFLICT, "ChangeSet state or ref conflict")
}

async fn load(state: &AppState, headers: &HeaderMap, id: Uuid) -> Result<ChangeSet, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_opt("SELECT namespace_id,state,creator_id,reviewer_id FROM workspace_changesets WHERE id=$1", &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let namespace_id: Uuid = row.get(0);
    handlers::load(state, headers, namespace_id).await?;
    let rows=client.query("SELECT ordinal,repository_id,mount_path,owner_slug,repository_name,ref_name,old_oid,new_oid,storage_generation,applied FROM workspace_changeset_steps WHERE changeset_id=$1 ORDER BY ordinal", &[&id]).await.map_err(Error::internal)?;
    let steps = rows
        .into_iter()
        .map(|r| Step {
            ordinal: r.get(0),
            repository_id: r.get(1),
            mount_path: r.get(2),
            owner: r.get(3),
            repository: r.get(4),
            ref_name: r.get(5),
            old_oid: r.get(6),
            new_oid: r.get(7),
            storage_generation: r.get(8),
            applied: r.get(9),
        })
        .collect();
    Ok(ChangeSet {
        id,
        namespace_id,
        state: row.get(1),
        creator_id: row.get(2),
        reviewer_id: row.get(3),
        steps,
    })
}
pub async fn get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ChangeSet>, Error> {
    Ok(Json(load(&state, &headers, id).await?))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(namespace_id): Path<Uuid>,
    Json(input): Json<Propose>,
) -> Result<(StatusCode, Json<ChangeSet>), Error> {
    let ns = handlers::load(&state, &headers, namespace_id).await?;
    if input.steps.is_empty() || input.steps.len() > 32 {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let id = Uuid::new_v4();
    let mut steps = Vec::new();
    let mut targets = HashSet::new();
    for (ordinal, step) in input.steps.iter().enumerate() {
        let mount = ns
            .mounts
            .iter()
            .find(|m| m.path == step.mount_path)
            .ok_or_else(Error::not_found)?;
        let access = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &mount.owner,
            &mount.repository,
            Role::Write,
        )
        .await?;
        if !targets.insert((access.repo_id, step.ref_name.as_str())) {
            return Err(Error::bad_request());
        }
        if !crate::browse::models::valid_public_ref(&step.ref_name)
            || !crate::browse::models::valid_non_zero_oid(&step.old_oid)
            || !crate::browse::models::valid_non_zero_oid(&step.new_oid)
            || step.old_oid == step.new_oid
            || step.storage_generation <= 0
        {
            return Err(Error::bad_request());
        }
        let source_lease=read_leases::shared(&state.pool,access.repo_id,
            tokio::time::Instant::now()+state.config.git_timeout).await?;
        let refreshed=auth::authorize_repo_with_role(&tx,&actor,&mount.owner,&mount.repository,Role::Write).await?;
        if refreshed.repo_id!=access.repo_id { return Err(Error::not_found()); }
        let repo = state
            .storage
            .verify_path(access.repo_id)
            .map_err(Error::internal)?;
        service::git(
            &repo,
            &["cat-file", "-e", &format!("{}^{{commit}}", step.new_oid)],
        )?;
        source_lease.ensure_active()?;
        steps.push((ordinal as i32, mount, access.repo_id, step));
    }
    tx.execute("INSERT INTO workspace_changesets(id,namespace_id,state,creator_id) VALUES($1,$2,'proposed',$3)", &[&id,&namespace_id,&actor.id]).await.map_err(Error::internal)?;
    for (ordinal, mount, repo, step) in steps {
        tx.execute("INSERT INTO workspace_changeset_steps(changeset_id,ordinal,repository_id,mount_path,owner_slug,repository_name,ref_name,old_oid,new_oid,storage_generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", &[&id,&ordinal,&repo,&step.mount_path,&mount.owner,&mount.repository,&step.ref_name,&step.old_oid,&step.new_oid,&step.storage_generation]).await.map_err(Error::internal)?;
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok((StatusCode::CREATED, Json(load(&state, &headers, id).await?)))
}

pub async fn review(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ChangeSet>, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let cs = load(&state, &headers, id).await?;
    if cs.creator_id == actor.id {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "independent reviewer required",
        ));
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    for step in &cs.steps {
        let access = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &step.owner,
            &step.repository,
            Role::Maintain,
        )
        .await?;
        if access.repo_id != step.repository_id {
            return Err(Error::not_found());
        }
    }
    let changed=tx.execute("UPDATE workspace_changesets SET state='reviewed',reviewer_id=$2,updated_at=clock_timestamp() WHERE id=$1 AND state='proposed'", &[&id,&actor.id]).await.map_err(Error::internal)?;
    if changed != 1 {
        return Err(conflict());
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok(Json(load(&state, &headers, id).await?))
}

pub async fn integrate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ChangeSet>, Error> {
    run(state, headers, id, false).await.map(Json)
}
pub async fn recover(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ChangeSet>, Error> {
    run(state, headers, id, true).await.map(Json)
}

async fn run(
    state: Arc<AppState>,
    headers: HeaderMap,
    id: Uuid,
    recovery: bool,
) -> Result<ChangeSet, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    // A transaction-scoped advisory lock fences competing integrators across
    // service nodes. A process crash releases it; recover then inspects each
    // Git ref before replaying its durable step.
    let mut gate_client = state.pool.get().await.map_err(Error::internal)?;
    let gate = gate_client.transaction().await.map_err(Error::internal)?;
    gate.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text, 616))",
        &[&id],
    )
    .await
    .map_err(Error::internal)?;
    let cs = load(&state, &headers, id).await?;
    if cs.state == "complete" {
        return Ok(cs);
    }
    if !matches!(cs.state.as_str(), "reviewed" | "partial" | "integrating")
        || cs.reviewer_id.is_none()
    {
        return Err(conflict());
    }
    if !recovery && cs.state != "reviewed" {
        return Err(conflict());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    for step in &cs.steps {
        let access =
            auth::authorize_repo_with_role(&tx, &actor, &step.owner, &step.repository, Role::Write)
                .await?;
        if access.repo_id != step.repository_id {
            return Err(Error::not_found());
        }
    }
    let changed=tx.execute("UPDATE workspace_changesets SET state='integrating',updated_at=clock_timestamp() WHERE id=$1 AND state=$2", &[&id,&cs.state]).await.map_err(Error::internal)?;
    if changed != 1 {
        return Err(conflict());
    }
    tx.commit().await.map_err(Error::internal)?;
    for step in &cs.steps {
        if step.applied {
            continue;
        }
        let generation: i64 = state
            .pool
            .get()
            .await
            .map_err(Error::internal)?
            .query_one(
                "SELECT storage_generation FROM repositories WHERE id=$1",
                &[&step.repository_id],
            )
            .await
            .map_err(Error::internal)?
            .get(0);
        if generation != step.storage_generation {
            let client = state.pool.get().await.map_err(Error::internal)?;
            client.execute("UPDATE workspace_changesets SET state='conflict',updated_at=clock_timestamp() WHERE id=$1", &[&id]).await.map_err(Error::internal)?;
            return Err(conflict());
        }
        let source_lease=read_leases::shared(&state.pool,step.repository_id,
            tokio::time::Instant::now()+state.config.git_timeout).await?;
        auth::verify_active(&state.pool,&actor,step.repository_id,true).await?;
        let repo = state
            .storage
            .verify_path(step.repository_id)
            .map_err(Error::internal)?;
        let actual = String::from_utf8(service::git(
            &repo,
            &["rev-parse", "--verify", &step.ref_name],
        )?)
        .map_err(Error::internal)?;
        if actual.trim() != step.new_oid {
            if actual.trim() != step.old_oid {
                let client = state.pool.get().await.map_err(Error::internal)?;
                client.execute("UPDATE workspace_changesets SET state='conflict',updated_at=clock_timestamp() WHERE id=$1", &[&id]).await.map_err(Error::internal)?;
                return Err(conflict());
            }
            let mut step_headers = headers.clone();
            step_headers.insert(
                "idempotency-key",
                HeaderValue::from_str(&format!("changeset-{id}-{}", step.ordinal))
                    .map_err(Error::internal)?,
            );
            let request = RefTransactionRequest {
                storage_generation: Some(step.storage_generation),
                atomic: true,
                updates: vec![RefUpdateInput {
                    ref_name: step.ref_name.clone(),
                    old_oid: Some(step.old_oid.clone()),
                    new_oid: Some(step.new_oid.clone()),
                }],
            };
            let response = transactions::execute_ref_transaction(
                State(state.clone()),
                Path((step.owner.clone(), step.repository.clone())),
                Extension(actor.clone()),
                step_headers,
                Json(request),
            )
            .await;
            if response.is_err() || !response.as_ref().is_ok_and(|r| r.status().is_success()) {
                let client = state.pool.get().await.map_err(Error::internal)?;
                client.execute("UPDATE workspace_changesets SET state='partial',updated_at=clock_timestamp() WHERE id=$1", &[&id]).await.map_err(Error::internal)?;
                return Err(conflict());
            }
        }
        source_lease.ensure_active()?;
        let client = state.pool.get().await.map_err(Error::internal)?;
        client.execute("UPDATE workspace_changeset_steps SET applied=true WHERE changeset_id=$1 AND ordinal=$2", &[&id,&step.ordinal]).await.map_err(Error::internal)?;
        client.execute("UPDATE workspace_changesets SET state='partial',updated_at=clock_timestamp() WHERE id=$1", &[&id]).await.map_err(Error::internal)?;
        if std::env::var("ROOTYARD_CHANGESET_KILL_AFTER_STEP")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            == Some(step.ordinal + 1)
        {
            std::process::exit(79);
        }
    }
    let client = state.pool.get().await.map_err(Error::internal)?;
    client.execute("UPDATE workspace_changesets SET state='complete',updated_at=clock_timestamp() WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM workspace_changeset_steps WHERE changeset_id=$1 AND NOT applied)", &[&id]).await.map_err(Error::internal)?;
    gate.commit().await.map_err(Error::internal)?;
    load(&state, &headers, id).await
}
