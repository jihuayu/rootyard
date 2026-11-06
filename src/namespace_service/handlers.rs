use crate::{AppState, Error, auth, db, members::models::Role, storage::read_leases};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub path: String,
    pub owner: String,
    pub repository: String,
    pub base_oid: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub name: String,
    pub mounts: Vec<Mount>,
}
#[derive(Serialize)]
pub struct Namespace {
    pub id: Uuid,
    pub name: String,
    pub revision: i64,
    pub owner_id: Uuid,
    pub mounts: Vec<Mount>,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut input): Json<Create>,
) -> Result<(StatusCode, Json<Namespace>), Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !db::valid_name(&input.name) || input.mounts.is_empty() || input.mounts.len() > 32 {
        return Err(Error::bad_request());
    }
    input.mounts.sort_by(|a, b| a.path.cmp(&b.path));
    for (i, m) in input.mounts.iter().enumerate() {
        let path = crate::browse::models::normalize_rel_path(Some(&m.path))?;
        if path.is_empty()
            || path != m.path
            || !crate::browse::models::valid_non_zero_oid(&m.base_oid)
        {
            return Err(Error::bad_request());
        }
        if i > 0
            && (m.path == input.mounts[i - 1].path
                || m.path
                    .starts_with(&(input.mounts[i - 1].path.clone() + "/")))
        {
            return Err(Error::bad_request());
        }
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let mut owner_id = None;
    let mut repo_ids = Vec::new();
    for m in &input.mounts {
        let access =
            auth::authorize_repo_with_role(&tx, &actor, &m.owner, &m.repository, Role::Read)
                .await?;
        if owner_id.is_some_and(|id| id != access.owner_id) {
            return Err(Error::bad_request());
        }
        owner_id = Some(access.owner_id);
        let source_lease = read_leases::shared(
            &state.pool,
            access.repo_id,
            tokio::time::Instant::now() + state.config.git_timeout,
        )
        .await?;
        let _local = tokio::time::timeout(
            state.config.git_timeout,
            state.storage.read_snapshot_lock(access.repo_id),
        )
        .await
        .map_err(|_| Error::timeout())?;
        source_lease.ensure_active()?;
        let refreshed =
            auth::authorize_repo_with_role(&tx, &actor, &m.owner, &m.repository, Role::Read)
                .await?;
        if refreshed.repo_id != access.repo_id {
            return Err(Error::not_found());
        }
        let repo = state
            .storage
            .verify_path(access.repo_id)
            .map_err(Error::internal)?;
        let mut git = state.storage.git(&state.config);
        git.arg("--git-dir").arg(&repo).args([
            "cat-file",
            "-e",
            &format!("{}^{{commit}}", m.base_oid),
        ]);
        source_lease
            .guard(crate::git_http::collect_git_output(
                git,
                128,
                state.config.git_timeout,
            ))
            .await?
            .map_err(|_| Error::bad_request())?;
        source_lease.ensure_active()?;
        repo_ids.push(access.repo_id);
    }
    let owner_id = owner_id.ok_or_else(Error::bad_request)?;
    let id = Uuid::new_v4();
    tx.execute(
        "INSERT INTO workspace_namespaces(id,owner_id,name,creator_id) VALUES($1,$2,$3,$4)",
        &[&id, &owner_id, &input.name, &actor.id],
    )
    .await
    .map_err(Error::internal)?;
    for (m, repo) in input.mounts.iter().zip(repo_ids) {
        tx.execute("INSERT INTO workspace_namespace_mounts(namespace_id,mount_path,repository_id,owner_slug,repository_name,base_oid) VALUES($1,$2,$3,$4,$5,$6)", &[&id,&m.path,&repo,&m.owner,&m.repository,&m.base_oid]).await.map_err(Error::internal)?;
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(Namespace {
            id,
            name: input.name,
            revision: 1,
            owner_id,
            mounts: input.mounts,
        }),
    ))
}

pub async fn load(state: &AppState, headers: &HeaderMap, id: Uuid) -> Result<Namespace, Error> {
    let actor = auth::authenticate(&state.pool, headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx
        .query_opt(
            "SELECT owner_id,name,revision,creator_id FROM workspace_namespaces WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let rows=tx.query("SELECT mount_path,repository_id,owner_slug,repository_name,base_oid FROM workspace_namespace_mounts WHERE namespace_id=$1 ORDER BY mount_path", &[&id]).await.map_err(Error::internal)?;
    let mut mounts = Vec::new();
    for r in rows {
        let m = Mount {
            path: r.get(0),
            owner: r.get(2),
            repository: r.get(3),
            base_oid: r.get(4),
        };
        let access =
            auth::authorize_repo_with_role(&tx, &actor, &m.owner, &m.repository, Role::Read)
                .await?;
        if access.repo_id != r.get::<_, Uuid>(1) {
            return Err(Error::not_found());
        }
        mounts.push(m);
    }
    let result = Namespace {
        id,
        owner_id: row.get(0),
        name: row.get(1),
        revision: row.get(2),
        mounts,
    };
    tx.commit().await.map_err(Error::internal)?;
    Ok(result)
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Namespace>, Error> {
    Ok(Json(load(&state, &headers, id).await?))
}
