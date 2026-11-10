//! 5-level Role resolution (`read` < `triage` < `write` < `maintain` < `admin`),
//! Collaborator & Team CRUD handlers, and PR review permission checks.
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish, idempotency_key},
    db::{self, Identity},
    members::{
        audit,
        models::{
            self, COLLABORATOR_FIELDS, Collaborator, CollaboratorInput, EffectivePermission, Page,
            RepoAccess, Role, json, valid_team_slug,
        },
    },
    pulls::models::{creation_replay, record_creation},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use deadpool_postgres::{Object, Transaction};
use tokio_postgres::GenericClient;
use serde_json::{Value, json as sjson};
use std::sync::Arc;
use uuid::Uuid;

pub(super) type App = State<Arc<AppState>>;
pub(super) type RepoPath = Path<(String, String)>;
pub(super) type SubPath = Path<(String, String, String)>;
pub(super) type MemberPath = Path<(String, String, String, String)>;
pub(super) type Res = Result<Response, Error>;

pub async fn rbac_tables_installed<C: GenericClient + Sync>(tx: &C) -> Result<bool, Error> {
    let sql = "SELECT to_regclass('repository_collaborators') IS NOT NULL";
    Ok(tx
        .query_one(sql, &[])
        .await
        .map_err(Error::internal)?
        .get(0))
}

pub async fn resolve_effective_role<C: GenericClient + Sync>(
    tx: &C,
    repo_id: Uuid,
    owner_id: Uuid,
    user_id: Uuid,
) -> Result<Option<(Role, Option<Role>, Option<Role>)>, Error> {
    if user_id == owner_id {
        return Ok(Some((Role::Admin, None, None)));
    }
    if !rbac_tables_installed(tx).await? {
        return Ok(None);
    }
    // Hold the authority rows until the caller commits. A concurrent
    // revocation must serialize after a write admitted under this role.
    let d_sql = "SELECT role FROM repository_collaborators WHERE repository_id=$1 AND user_id=$2 FOR SHARE";
    let direct_role = match tx
        .query_opt(d_sql, &[&repo_id, &user_id])
        .await
        .map_err(Error::internal)?
    {
        Some(r) => Some(Role::parse(r.get::<_, &str>(0))?),
        None => None,
    };
    let org_role = tx
        .query_opt(
            "SELECT role FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 FOR SHARE",
            &[&owner_id, &user_id],
        )
        .await
        .map_err(Error::internal)?
        .map(|r| Role::parse(r.get::<_, &str>(0)))
        .transpose()?;
    let direct_role = match (direct_role, org_role) {
        (Some(d), Some(o)) => Some(d.max(o)),
        (Some(d), None) => Some(d),
        (None, Some(o)) => Some(o),
        (None, None) => None,
    };
    let t_sql = "SELECT t.role FROM repository_teams t JOIN repository_team_members tm ON tm.team_id = t.id WHERE t.repository_id=$1 AND tm.user_id=$2 FOR SHARE OF t,tm";
    let team_rows = tx
        .query(t_sql, &[&repo_id, &user_id])
        .await
        .map_err(Error::internal)?;
    let mut max_team_role: Option<Role> = None;
    for row in team_rows {
        let r = Role::parse(row.get::<_, &str>(0))?;
        max_team_role = Some(max_team_role.map_or(r, |cur| cur.max(r)));
    }
    let org_team_rows = tx.query(
        "SELECT t.role FROM organization_teams t JOIN organization_team_members tm ON tm.team_id=t.id WHERE t.organization_id=$1 AND tm.user_id=$2 FOR SHARE OF t,tm",
        &[&owner_id, &user_id],
    ).await.map_err(Error::internal)?;
    for row in org_team_rows {
        let r = Role::parse(row.get::<_, &str>(0))?;
        max_team_role = Some(max_team_role.map_or(r, |cur| cur.max(r)));
    }
    let effective = match (direct_role, max_team_role) {
        (Some(d), Some(t)) => Some(d.max(t)),
        (Some(d), None) => Some(d),
        (None, Some(t)) => Some(t),
        (None, None) => None,
    };
    Ok(effective.map(|eff| (eff, direct_role, max_team_role)))
}

pub async fn resolve_effective_role_by_id(
    tx: &Transaction<'_>,
    repo_id: Uuid,
    owner_id: Uuid,
    user_id: Uuid,
) -> Result<Option<Role>, Error> {
    Ok(resolve_effective_role(&**tx, repo_id, owner_id, user_id)
        .await?
        .map(|(e, _, _)| e))
}

pub async fn repo_has_collaborators_or_teams<C: GenericClient + Sync>(
    tx: &C,
    repo_id: Uuid,
) -> Result<bool, Error> {
    if !rbac_tables_installed(tx).await? {
        return Ok(false);
    }
    let sql = "SELECT EXISTS(SELECT 1 FROM repository_collaborators WHERE repository_id=$1) OR EXISTS(SELECT 1 FROM repository_teams WHERE repository_id=$1)";
    Ok(tx
        .query_one(sql, &[&repo_id])
        .await
        .map_err(Error::internal)?
        .get(0))
}

pub async fn check_review_permission(
    _tx: &Transaction<'_>,
    access: &RepoAccess,
    actor_id: Uuid,
    pull_author_id: Uuid,
    _base_ref: &str,
    review_state: &str,
    disallow_self_approval: bool,
) -> Result<(), Error> {
    let min_role = if review_state == "commented" {
        Role::Triage
    } else {
        Role::Write
    };
    if access.role < min_role {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient repository role"));
    }
    if review_state == "approved" && actor_id == pull_author_id && disallow_self_approval {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "pull request author cannot approve their own pull request",
        ));
    }
    Ok(())
}

pub(super) async fn open_client(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(Identity, Object), Error> {
    models::ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, headers).await?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    Ok((actor, client))
}

/// Serialize member-policy mutations before acquiring role row locks. This
/// prevents two administrators changing each other's roles from taking
/// reciprocal SHARE→UPDATE upgrades and deadlocking.
pub(super) async fn serialize_member_mutation(
    tx: &Transaction<'_>, actor: &Identity, owner: &str, name: &str,
) -> Result<(), Error> {
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    tx.query_opt(
        "SELECT t.id FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.id=$1 AND t.user_id=$2 AND u.username=$3 FOR SHARE OF t,u",
        &[&actor.token_id, &actor.id, &actor.username],
    ).await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    auth::verify_token(tx, actor, true).await?;
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1 || '/' || $2, 7329))",
        &[&owner, &name],
    ).await.map_err(Error::internal)?;
    Ok(())
}

pub(super) async fn finish_audit(
    tx: Transaction<'_>,
    acc: RepoAccess,
    actor: &Identity,
    act: &str,
    kind: &str,
    target: &str,
    details: Value,
) -> Result<(), Error> {
    audit::insert_audit_event(
        &tx,
        acc.owner_id,
        acc.repo_id,
        actor,
        act,
        kind,
        target,
        details,
    )
    .await?;
    finish(tx, actor, true).await
}

pub(super) async fn lookup_user(
    tx: &Transaction<'_>,
    username: &str,
) -> Result<(Uuid, String), Error> {
    if !db::valid_name(username) {
        return Err(Error::bad_request());
    }
    let sql = "SELECT id, username FROM users WHERE username=$1";
    let r = tx
        .query_opt(sql, &[&username])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    Ok((r.get(0), r.get(1)))
}

pub(super) async fn lookup_team_id(
    tx: &Transaction<'_>,
    repo_id: Uuid,
    slug: &str,
) -> Result<Uuid, Error> {
    if !valid_team_slug(slug) {
        return Err(Error::bad_request());
    }
    let sql = "SELECT id FROM repository_teams WHERE repository_id=$1 AND slug=$2";
    Ok(tx
        .query_opt(sql, &[&repo_id, &slug])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0))
}

pub async fn list_collaborators(
    State(s): App,
    Path((o, n)): RepoPath,
    Query(p): Query<Page>,
    h: HeaderMap,
) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    let (after, limit) = p.bounds()?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Read, crate::token_scopes::RepoAction::MembersRead).await?;
    let q = format!(
        "SELECT {COLLABORATOR_FIELDS} FROM repository_collaborators c JOIN users u ON u.id = c.user_id WHERE c.tenant_id=$1 AND c.repository_id=$2 ORDER BY u.username ASC OFFSET $3 LIMIT $4"
    );
    let rows = tx
        .query(&q, &[&acc.owner_id, &acc.repo_id, &after, &(limit + 1)])
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let mut items = Vec::with_capacity(rows.len().min(limit as usize));
    for r in rows.iter().take(limit as usize) {
        items.push(Collaborator::row(r)?);
    }
    let next_after = if more { Some(after + limit) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "items": items, "next_after": next_after }),
    ))
}

pub async fn upsert_collaborator(
    State(s): App,
    Path((o, n)): RepoPath,
    h: HeaderMap,
    Json(inp): Json<CollaboratorInput>,
) -> Res {
    let u = inp.username.clone().ok_or_else(Error::bad_request)?;
    upsert_collaborator_inner(s, o, n, u, h, inp).await
}

pub async fn put_collaborator(
    State(s): App,
    Path((o, n, u)): SubPath,
    h: HeaderMap,
    Json(inp): Json<CollaboratorInput>,
) -> Res {
    if inp.username.as_ref().is_some_and(|body_u| body_u != &u) {
        return Err(Error::bad_request());
    }
    upsert_collaborator_inner(s, o, n, u, h, inp).await
}

async fn upsert_collaborator_inner(
    s: Arc<AppState>,
    o: String,
    n: String,
    u: String,
    h: HeaderMap,
    inp: CollaboratorInput,
) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    if inp.expected_version.is_some_and(|v| v <= 0) {
        return Err(Error::bad_request());
    }
    let key = idempotency_key(&h)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    serialize_member_mutation(&tx, &actor, &o, &n).await?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Admin, crate::token_scopes::RepoAction::MembersAdmin).await?;
    let (uid, uname) = lookup_user(&tx, &u).await?;
    if uid == acc.owner_id {
        return Err(Error(
            StatusCode::CONFLICT,
            "cannot modify or remove repository owner",
        ));
    }
    let r_str = inp.role.as_str();
    if let Some(key) = key {
        let req = sjson!({"operation":"collaborator_upsert","username":uname,"role":r_str,"expected_version":inp.expected_version});
        if let Some(resp) = creation_replay(&tx, acc.owner_id, acc.repo_id, key, &req).await? {
            finish(tx, &actor, true).await?;
            let code = if inp.expected_version.is_none() {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            return Ok(json(code, resp));
        }
    }
    let lock_q = "SELECT version FROM repository_collaborators WHERE repository_id=$1 AND user_id=$2 FOR UPDATE";
    let existing = tx
        .query_opt(lock_q, &[&acc.repo_id, &uid])
        .await
        .map_err(Error::internal)?;
    let (code, act) = match existing {
        None => {
            if inp.expected_version.is_some() {
                return Err(Error(StatusCode::CONFLICT, "collaborator version conflict"));
            }
            let ins = "INSERT INTO repository_collaborators (repository_id, tenant_id, user_id, role) VALUES ($1, $2, $3, $4)";
            tx.execute(ins, &[&acc.repo_id, &acc.owner_id, &uid, &r_str])
                .await
                .map_err(Error::internal)?;
            (StatusCode::CREATED, "collaborator.added")
        }
        Some(cur) => {
            let cur_v: i64 = cur.get("version");
            if inp.expected_version.is_some_and(|ev| ev != cur_v) {
                return Err(Error(StatusCode::CONFLICT, "collaborator version conflict"));
            }
            let upd = "UPDATE repository_collaborators SET role=$3, version=version+1, updated_at=clock_timestamp() WHERE repository_id=$1 AND user_id=$2";
            tx.execute(upd, &[&acc.repo_id, &uid, &r_str])
                .await
                .map_err(Error::internal)?;
            (StatusCode::OK, "collaborator.updated")
        }
    };
    let sel = format!(
        "SELECT {COLLABORATOR_FIELDS} FROM repository_collaborators c JOIN users u ON u.id = c.user_id WHERE c.repository_id=$1 AND c.user_id=$2"
    );
    let row = tx
        .query_one(&sel, &[&acc.repo_id, &uid])
        .await
        .map_err(Error::internal)?;
    let collab = Collaborator::row(&row)?;
    let val = serde_json::to_value(&collab).map_err(Error::internal)?;
    record_creation(&tx, acc.owner_id, acc.repo_id, key, &val).await?;
    let det = sjson!({ "role": r_str, "version": collab.version });
    finish_audit(tx, acc, &actor, act, "collaborator", &uname, det).await?;
    Ok(json(code, val))
}

pub async fn get_collaborator(State(s): App, Path((o, n, u)): SubPath, h: HeaderMap) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    if !db::valid_name(&u) {
        return Err(Error::bad_request());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Read, crate::token_scopes::RepoAction::MembersRead).await?;
    let q = format!(
        "SELECT {COLLABORATOR_FIELDS} FROM repository_collaborators c JOIN users u ON u.id = c.user_id WHERE c.repository_id=$1 AND u.username=$2"
    );
    let row = tx
        .query_opt(&q, &[&acc.repo_id, &u])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let collab = Collaborator::row(&row)?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, collab))
}

pub async fn remove_collaborator(State(s): App, Path((o, n, u)): SubPath, h: HeaderMap) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    if !db::valid_name(&u) {
        return Err(Error::bad_request());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    serialize_member_mutation(&tx, &actor, &o, &n).await?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Admin, crate::token_scopes::RepoAction::MembersAdmin).await?;
    if u == o {
        return Err(Error(
            StatusCode::CONFLICT,
            "cannot modify or remove repository owner",
        ));
    }
    let (uid, uname) = lookup_user(&tx, &u).await?;
    if uid == acc.owner_id {
        return Err(Error(
            StatusCode::CONFLICT,
            "cannot modify or remove repository owner",
        ));
    }
    let del = "DELETE FROM repository_collaborators WHERE repository_id=$1 AND user_id=$2";
    if tx
        .execute(del, &[&acc.repo_id, &uid])
        .await
        .map_err(Error::internal)?
        == 0
    {
        return Err(Error::not_found());
    }
    let det = sjson!({ "user_id": uid });
    finish_audit(
        tx,
        acc,
        &actor,
        "collaborator.removed",
        "collaborator",
        &uname,
        det,
    )
    .await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "removed": true, "username": uname }),
    ))
}

pub async fn get_effective_permission(
    State(s): App,
    Path((o, n, u)): SubPath,
    h: HeaderMap,
) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Read, crate::token_scopes::RepoAction::MembersRead).await?;
    let (uid, uname) = lookup_user(&tx, &u).await?;
    let resolved = resolve_effective_role(&*tx, acc.repo_id, acc.owner_id, uid).await?;
    let (role, direct_role, team_role) = match resolved {
        Some((eff, d, t)) => (Some(eff), d, t),
        None => (None, None, None),
    };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        EffectivePermission {
            repository_id: acc.repo_id,
            user_id: uid,
            username: uname,
            role,
            direct_role,
            team_role,
            is_owner: uid == acc.owner_id,
        },
    ))
}
