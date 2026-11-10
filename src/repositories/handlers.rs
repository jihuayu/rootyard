//! Authorized repository lifecycle and local provisioning recovery.
use crate::{AppState, Error, auth, browse, db, members::models::Role, organizations, pagination, sharding};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateRepo {
    name: String,
    owner: Option<String>,
    object_format: Option<browse::object_format::ObjectFormat>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RepoListQuery {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    page: Option<bool>,
}

#[derive(Serialize)]
struct RepoPage {
    items: Vec<db::Repository>,
    next_cursor: Option<String>,
}

fn decode_repo_cursor(raw: &str, actor: Uuid) -> Result<(String, String, Uuid), Error> {
    let scope = format!("repositories:{actor}");
    let fields = pagination::decode(raw, &scope, 3)?;
    let invalid = || Error(StatusCode::BAD_REQUEST, "invalid pagination cursor");
    let [owner, name, id] = fields.as_slice() else {
        return Err(invalid());
    };
    let id = Uuid::parse_str(id).map_err(|_| invalid())?;
    if id.is_nil() || !db::valid_name(owner) || !db::valid_name(name) {
        return Err(invalid());
    }
    Ok((owner.clone(), name.clone(), id))
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
    // There is no create scope in the restricted model yet: a restricted token
    // is refused explicitly instead of inferring creation from repo_admin.
    auth::reject_restricted_create(&tx, &identity).await?;
    let owner = input.owner.as_deref().unwrap_or(&identity.username);
    let owner_id = organizations::authorize_namespace_create(&tx, &identity, owner).await?;
    let format = input.object_format.unwrap_or(browse::object_format::ObjectFormat::Sha1);
    let id = Uuid::new_v4();
    let created=tx.execute("INSERT INTO repositories (id,owner_id,name,object_format) VALUES ($1,$2,$3,$4) ON CONFLICT (owner_id,name) DO NOTHING",&[&id,&owner_id,&input.name,&format.as_str()]).await.map_err(Error::internal)?==1;
    let row = tx
        .query_one(&format!("{} WHERE r.owner_id=$1 AND r.name=$2", db::REPO_SELECT), &[&owner_id, &input.name])
        .await
        .map_err(Error::internal)?;
    let mut repo = db::Repository::from_row(&row);
    if input.object_format.is_some_and(|requested| requested.as_str() != repo.object_format) {
        return Err(Error(StatusCode::CONFLICT, "repository object format cannot change"));
    }
    auth::finish_tx(tx, &identity, true).await?;
    drop(client);
    if repo.state == "provisioning" && sharding::transport::is_local_primary_for_repo(&state, owner_id, repo.id).await?
    {
        let _slot = state
            .git_slots
            .try_acquire()
            .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))?;
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
                .execute("UPDATE repositories SET state='ready' WHERE id=$1 AND state='provisioning'", &[&repo.id])
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
    Query(query): Query<RepoListQuery>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let identity = auth::authenticate(&state.pool, &headers).await?;
    let limit = query.limit.unwrap_or(1000);
    if !(1..=1000).contains(&limit) {
        return Err(Error::bad_request());
    }
    let scope = format!("repositories:{}", identity.id);
    let cursor = match query.cursor.as_deref() {
        Some(raw) => {
            let (owner, name, id) = decode_repo_cursor(raw, identity.id)?;
            (Some(owner), Some(name), Some(id))
        }
        None => (None, None, None),
    };
    // Group every visibility OR before the keyset predicate so a cursor can
    // never widen the actor's permission filters.
    let sql = format!(
        concat!(
            "{} WHERE (r.owner_id=$1",
            " OR EXISTS (SELECT 1 FROM repository_collaborators c WHERE c.repository_id=r.id AND c.user_id=$1)",
            " OR EXISTS (SELECT 1 FROM repository_teams t JOIN repository_team_members m ON m.team_id=t.id WHERE t.repository_id=r.id AND m.user_id=$1)",
            " OR EXISTS (SELECT 1 FROM organization_memberships m WHERE m.organization_id=r.owner_id AND m.user_id=$1)",
            " OR EXISTS (SELECT 1 FROM organization_team_members m WHERE m.organization_id=r.owner_id AND m.user_id=$1))",
            " AND ($2::text IS NULL OR (ns.slug,r.name,r.id) > ($2::text,$3::text,$4::uuid))",
            " ORDER BY ns.slug,r.name,r.id LIMIT $5"
        ),
        db::REPO_SELECT
    );
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &identity, false).await?;
    // A restricted token sees only repositories with an explicit grant. It
    // must not discover sibling repositories through ownership, organisation
    // membership or collaborator rows, and names are never returned for them.
    let restricted = auth::token_is_restricted(&tx, &identity).await?;
    let rows = if restricted {
        let sql = format!(
            concat!(
                "{} WHERE (r.owner_id=$6",
                " OR EXISTS (SELECT 1 FROM repository_collaborators c WHERE c.repository_id=r.id AND c.user_id=$6)",
                " OR EXISTS (SELECT 1 FROM repository_teams t JOIN repository_team_members m ON m.team_id=t.id WHERE t.repository_id=r.id AND m.user_id=$6)",
                " OR EXISTS (SELECT 1 FROM organization_memberships m WHERE m.organization_id=r.owner_id AND m.user_id=$6)",
                " OR EXISTS (SELECT 1 FROM organization_team_members m WHERE m.organization_id=r.owner_id AND m.user_id=$6))",
                " AND EXISTS (SELECT 1 FROM token_repository_scopes ts ",
                "WHERE ts.token_id=$1 AND ts.repository_id=r.id AND ts.action='repo_read')",
                " AND ($2::text IS NULL OR (ns.slug,r.name,r.id) > ($2::text,$3::text,$4::uuid))",
                " ORDER BY ns.slug,r.name,r.id LIMIT $5"
            ),
            db::REPO_SELECT
        );
        tx.query(&sql, &[&identity.token_id, &cursor.0, &cursor.1, &cursor.2, &(limit + 1), &identity.id])
            .await
            .map_err(Error::internal)?
    } else {
        tx.query(&sql, &[&identity.id, &cursor.0, &cursor.1, &cursor.2, &(limit + 1)]).await.map_err(Error::internal)?
    };
    auth::finish_tx(tx, &identity, false).await?;
    let more = rows.len() > limit as usize;
    let items = rows.iter().take(limit as usize).map(db::Repository::from_row).collect::<Vec<_>>();
    // The cursor names only the last returned (slug, name, id) position.
    // Concurrent inserts after it appear on later pages, inserts before it are
    // not replayed, and deletes simply vanish. A restore that rewinds the
    // catalog can leave a cursor outside the current data set, so clients must
    // restart from the first page after restore.
    let next_cursor = if more {
        items.last().map(|repo| {
            let id = repo.id.to_string();
            pagination::encode(&scope, &[repo.owner.as_str(), repo.name.as_str(), id.as_str()])
        })
    } else {
        None
    };
    let page_mode = query.page.unwrap_or(false);
    let mut response = if page_mode {
        ([(header::CACHE_CONTROL, "no-store")], Json(RepoPage { items, next_cursor: next_cursor.clone() }))
            .into_response()
    } else {
        ([(header::CACHE_CONTROL, "no-store")], Json(items)).into_response()
    };
    if let Some(cursor) = next_cursor {
        response.headers_mut().insert(
            header::HeaderName::from_static("x-next-cursor"),
            header::HeaderValue::from_str(&cursor).map_err(Error::internal)?,
        );
        let link = format!(
            "<{}?cursor={}&limit={}{}>; rel=\"next\"",
            uri.path(),
            pagination::query_value(&cursor),
            limit,
            if page_mode { "&page=true" } else { "" }
        );
        response.headers_mut().insert(header::LINK, header::HeaderValue::from_str(&link).map_err(Error::internal)?);
    }
    Ok(response)
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
        let repo_id: Uuid = tx
            .query_opt("SELECT id FROM repositories WHERE owner_id=$1 AND name=$2", &[&identity.id, &name])
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?
            .get("id");
        // Personal ownership bypasses the member-role lookup, never the token
        // scope gate: a restricted token still needs its exact repo grant.
        auth::authorize_repo_action_by_id(&tx, &identity, repo_id, crate::token_scopes::RepoAction::RepoRead).await?;
        repo_id
    } else {
        auth::authorize_repo_with_role(
            &tx,
            &identity,
            &owner,
            &name,
            Role::Read,
            crate::token_scopes::RepoAction::RepoRead,
        )
        .await?
        .repo_id
    };
    let row =
        tx.query_one(&format!("{} WHERE r.id=$1", db::REPO_SELECT), &[&repo_id]).await.map_err(Error::internal)?;
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
        match state.storage.provision_with_format(&state.config, id, format).await {
            Ok(()) => {
                state
                    .pool
                    .get()
                    .await?
                    .execute("UPDATE repositories SET state='ready' WHERE id=$1 AND state='provisioning'", &[&id])
                    .await?;
                recovered += 1;
            }
            Err(_) => eprintln!("rootyard: repository {id} provisioning requires retry"),
        }
    }
    Ok(recovered)
}
