//! Authorized repository lifecycle and local provisioning recovery.
use crate::{AppState, Error, auth, browse, db, organizations, sharding};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateRepo {
    name: String,
    owner: Option<String>,
    object_format: Option<browse::object_format::ObjectFormat>,
}
pub(super) async fn create_repo(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<CreateRepo>,
) -> Result<Response, Error> {
    let identity = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&identity)?;
    if !db::valid_name(&input.name) {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid repository name"));
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let owner = input.owner.as_deref().unwrap_or(&identity.username);
    let owner_id = organizations::authorize_namespace_create(&tx, &identity, owner).await?;
    let format = input
        .object_format
        .unwrap_or(browse::object_format::ObjectFormat::Sha1);
    let id = Uuid::new_v4();
    let created=tx.execute("INSERT INTO repositories (id,owner_id,name,object_format) VALUES ($1,$2,$3,$4) ON CONFLICT (owner_id,name) DO NOTHING",&[&id,&owner_id,&input.name,&format.as_str()]).await.map_err(Error::internal)?==1;
    let row = tx
        .query_one(
            &format!("{} WHERE r.owner_id=$1 AND r.name=$2", db::REPO_SELECT),
            &[&owner_id, &input.name],
        )
        .await
        .map_err(Error::internal)?;
    let mut repo = db::Repository::from_row(&row);
    if input
        .object_format
        .is_some_and(|requested| requested.as_str() != repo.object_format)
    {
        return Err(Error(
            StatusCode::CONFLICT,
            "repository object format cannot change",
        ));
    }
    auth::finish_tx(tx, &identity, true).await?;
    drop(client);
    if repo.state == "provisioning"
        && sharding::transport::is_local_primary_for_repo(&state, owner_id, repo.id).await?
    {
        let _slot = state.git_slots.try_acquire().map_err(|_| {
            Error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Git capacity exhausted; retry later",
            )
        })?;
        if state
            .storage
            .provision_with_format(
                &state.config,
                repo.id,
                browse::object_format::ObjectFormat::from_str_name(&repo.object_format)
                    .ok_or_else(Error::bad_request)?,
            )
            .await
            .is_ok()
        {
            state
                .pool
                .get()
                .await
                .map_err(Error::internal)?
                .execute(
                    "UPDATE repositories SET state='ready' WHERE id=$1 AND state='provisioning'",
                    &[&repo.id],
                )
                .await
                .map_err(Error::internal)?;
            repo.state = "ready".into();
        } else {
            eprintln!("rootyard: repository {} provisioning pending", repo.id);
        }
    }
    let status = if repo.state != "ready" {
        StatusCode::ACCEPTED
    } else if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, [(header::CACHE_CONTROL, "no-store")], Json(repo)).into_response())
}
pub(super) async fn list_repos(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let identity = auth::authenticate(&state.pool, &headers).await?;
    let rows = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query(
            &format!(
                "{} WHERE r.owner_id=$1 OR EXISTS (SELECT 1 FROM repository_collaborators c WHERE c.repository_id=r.id AND c.user_id=$1) OR EXISTS (SELECT 1 FROM repository_teams t JOIN repository_team_members m ON m.team_id=t.id WHERE t.repository_id=r.id AND m.user_id=$1) OR EXISTS (SELECT 1 FROM organization_memberships m WHERE m.organization_id=r.owner_id AND m.user_id=$1) ORDER BY ns.slug,r.name LIMIT 1000",
                db::REPO_SELECT
            ),
            &[&identity.id],
        )
        .await
        .map_err(Error::internal)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(
            rows.iter()
                .map(db::Repository::from_row)
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}
pub(super) async fn get_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let identity = auth::authenticate(&state.pool, &headers).await?;
    if !db::valid_name(&owner) || !db::valid_name(&name) {
        return Err(Error::not_found());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id: Uuid = if owner == identity.username {
        tx.query_opt(
            "SELECT id FROM repositories WHERE owner_id=$1 AND name=$2",
            &[&identity.id, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get("id")
    } else {
        auth::authorize_repo(&tx, &identity, &owner, &name, false).await?
    };
    let row = tx
        .query_one(&format!("{} WHERE r.id=$1", db::REPO_SELECT), &[&repo_id])
        .await
        .map_err(Error::internal)?;
    let repo = db::Repository::from_row(&row);
    auth::finish_tx(tx, &identity, false).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(repo)).into_response())
}

pub async fn recover(state: &AppState) -> anyhow::Result<usize> {
    // The metadata row itself is a durable, idempotent provisioning job. There is
    // no memory-only enqueue window and no second authority for refs or objects.
    let rows = state
        .pool
        .get()
        .await?
        .query(
            "SELECT id, object_format, owner_id FROM repositories WHERE state='provisioning' AND next_retry_at <= clock_timestamp() ORDER BY next_retry_at, created_at LIMIT 64",
            &[],
        )
        .await?;
    let mut recovered = 0;
    for row in rows {
        let id: Uuid = row.get(0);
        if !sharding::transport::is_local_primary_for_repo(state, row.get(2), id)
            .await
            .map_err(|e| anyhow::anyhow!(e.1))?
        {
            continue;
        }
        let format = browse::object_format::ObjectFormat::from_str_name(row.get(1))
            .ok_or_else(|| anyhow::anyhow!("invalid stored object format"))?;
        let Ok(_slot) = state.git_slots.try_acquire() else {
            break;
        };
        state.pool.get().await?.execute("UPDATE repositories SET next_retry_at=clock_timestamp()+interval '30 seconds', provision_attempts=provision_attempts+1 WHERE id=$1 AND state='provisioning'", &[&id]).await?;
        match state
            .storage
            .provision_with_format(&state.config, id, format)
            .await
        {
            Ok(()) => {
                state.pool.get().await?.execute("UPDATE repositories SET state='ready' WHERE id=$1 AND state='provisioning'",&[&id]).await?;
                recovered += 1;
            }
            Err(_) => eprintln!("rootyard: repository {id} provisioning requires retry"),
        }
    }
    Ok(recovered)
}
