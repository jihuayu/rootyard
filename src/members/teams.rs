//! Repository-scoped team management handlers.
use super::rbac::{
    App, MemberPath, RepoPath, Res, SubPath, finish_audit, lookup_team_id, lookup_user, open_client, serialize_member_mutation,
};
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish, idempotency_key},
    members::models::{
        NewTeam, Page, Role, TEAM_FIELDS, TEAM_MEMBER_FIELDS, Team, TeamMember, TeamMemberInput,
        TeamPatch, json, valid_team_description, valid_team_name, valid_team_slug,
    },
    pulls::models::{creation_replay, positive, record_creation},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::json as sjson;
use std::sync::Arc;
use uuid::Uuid;

pub async fn list_teams(
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
        "SELECT {TEAM_FIELDS} FROM repository_teams WHERE tenant_id=$1 AND repository_id=$2 ORDER BY slug ASC OFFSET $3 LIMIT $4"
    );
    let rows = tx
        .query(&q, &[&acc.owner_id, &acc.repo_id, &after, &(limit + 1)])
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let mut items = Vec::with_capacity(rows.len().min(limit as usize));
    for r in rows.iter().take(limit as usize) {
        items.push(Team::row(r)?);
    }
    let next_after = if more { Some(after + limit) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "items": items, "next_after": next_after }),
    ))
}

pub async fn create_team(
    State(s): App,
    Path((o, n)): RepoPath,
    h: HeaderMap,
    Json(inp): Json<NewTeam>,
) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    let desc = inp.description.as_deref().unwrap_or("");
    if !valid_team_slug(&inp.slug) || !valid_team_name(&inp.name) || !valid_team_description(desc) {
        return Err(Error::bad_request());
    }
    let key = idempotency_key(&h)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    serialize_member_mutation(&tx, &actor, &o, &n).await?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Admin, crate::token_scopes::RepoAction::MembersAdmin).await?;
    let r_str = inp.role.as_str();
    if let Some(key) = key {
        let req = sjson!({"operation":"team_create","slug":inp.slug,"name":inp.name,"description":desc,"role":r_str});
        if let Some(resp) = creation_replay(&tx, acc.owner_id, acc.repo_id, key, &req).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::CREATED, resp));
        }
    }
    let tid = Uuid::new_v4();
    let ins = format!(
        "INSERT INTO repository_teams (id, tenant_id, repository_id, slug, name, description, role) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (repository_id, slug) DO NOTHING RETURNING {TEAM_FIELDS}"
    );
    let row = tx
        .query_opt(
            &ins,
            &[
                &tid,
                &acc.owner_id,
                &acc.repo_id,
                &inp.slug,
                &inp.name,
                &desc,
                &r_str,
            ],
        )
        .await
        .map_err(Error::internal)?
        .ok_or(Error(StatusCode::CONFLICT, "team slug already exists"))?;
    let team = Team::row(&row)?;
    let val = serde_json::to_value(&team).map_err(Error::internal)?;
    record_creation(&tx, acc.owner_id, acc.repo_id, key, &val).await?;
    let det = sjson!({ "role": r_str, "name": team.name });
    finish_audit(tx, acc, &actor, "team.created", "team", &team.slug, det).await?;
    Ok(json(StatusCode::CREATED, val))
}

pub async fn get_team(State(s): App, Path((o, n, slug)): SubPath, h: HeaderMap) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    if !valid_team_slug(&slug) {
        return Err(Error::bad_request());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Read, crate::token_scopes::RepoAction::MembersRead).await?;
    let q = format!(
        "SELECT {TEAM_FIELDS} FROM repository_teams WHERE tenant_id=$1 AND repository_id=$2 AND slug=$3"
    );
    let row = tx
        .query_opt(&q, &[&acc.owner_id, &acc.repo_id, &slug])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let team = Team::row(&row)?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, team))
}

pub async fn update_team(
    State(s): App,
    Path((o, n, slug)): SubPath,
    h: HeaderMap,
    Json(inp): Json<TeamPatch>,
) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    positive(inp.expected_version)?;
    if !valid_team_slug(&slug)
        || inp.name.as_ref().is_some_and(|v| !valid_team_name(v))
        || inp
            .description
            .as_ref()
            .is_some_and(|v| !valid_team_description(v))
        || (inp.name.is_none() && inp.description.is_none() && inp.role.is_none())
    {
        return Err(Error::bad_request());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    serialize_member_mutation(&tx, &actor, &o, &n).await?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Admin, crate::token_scopes::RepoAction::MembersAdmin).await?;
    let _ = lookup_team_id(&tx, acc.repo_id, &slug).await?;
    let r_opt = inp.role.map(|r| r.as_str().to_owned());
    let upd = format!(
        "UPDATE repository_teams SET name=COALESCE($5,name), description=COALESCE($6,description), role=COALESCE($7,role), version=version+1, updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND slug=$3 AND version=$4 RETURNING {TEAM_FIELDS}"
    );
    let row = tx
        .query_opt(
            &upd,
            &[
                &acc.owner_id,
                &acc.repo_id,
                &slug,
                &inp.expected_version,
                &inp.name,
                &inp.description,
                &r_opt,
            ],
        )
        .await
        .map_err(Error::internal)?
        .ok_or(Error(StatusCode::CONFLICT, "team version conflict"))?;
    let team = Team::row(&row)?;
    let det = sjson!({ "role": team.role.as_str(), "version": team.version });
    finish_audit(tx, acc, &actor, "team.updated", "team", &team.slug, det).await?;
    Ok(json(StatusCode::OK, team))
}

pub async fn delete_team(State(s): App, Path((o, n, slug)): SubPath, h: HeaderMap) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    if !valid_team_slug(&slug) {
        return Err(Error::bad_request());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    serialize_member_mutation(&tx, &actor, &o, &n).await?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Admin, crate::token_scopes::RepoAction::MembersAdmin).await?;
    let del = "DELETE FROM repository_teams WHERE tenant_id=$1 AND repository_id=$2 AND slug=$3";
    if tx
        .execute(del, &[&acc.owner_id, &acc.repo_id, &slug])
        .await
        .map_err(Error::internal)?
        == 0
    {
        return Err(Error::not_found());
    }
    let det = sjson!({ "slug": slug });
    finish_audit(tx, acc, &actor, "team.deleted", "team", &slug, det).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "deleted": true, "slug": slug }),
    ))
}

pub async fn list_team_members(
    State(s): App,
    Path((o, n, slug)): SubPath,
    Query(p): Query<Page>,
    h: HeaderMap,
) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    let (after, limit) = p.bounds()?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Read, crate::token_scopes::RepoAction::MembersRead).await?;
    let tid = lookup_team_id(&tx, acc.repo_id, &slug).await?;
    let q = format!(
        "SELECT {TEAM_MEMBER_FIELDS} FROM repository_team_members tm JOIN users u ON u.id = tm.user_id WHERE tm.team_id=$1 ORDER BY u.username ASC OFFSET $2 LIMIT $3"
    );
    let rows = tx
        .query(&q, &[&tid, &after, &(limit + 1)])
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<TeamMember> = rows
        .iter()
        .take(limit as usize)
        .map(TeamMember::row)
        .collect();
    let next_after = if more { Some(after + limit) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "items": items, "next_after": next_after }),
    ))
}

pub async fn add_team_member(
    State(s): App,
    Path((o, n, slug)): SubPath,
    h: HeaderMap,
    Json(inp): Json<TeamMemberInput>,
) -> Res {
    let u = inp.username.ok_or_else(Error::bad_request)?;
    put_team_member_inner(s, o, n, slug, u, h).await
}

pub async fn put_team_member(
    State(s): App,
    Path((o, n, slug, u)): MemberPath,
    h: HeaderMap,
) -> Res {
    put_team_member_inner(s, o, n, slug, u, h).await
}

async fn put_team_member_inner(
    s: Arc<AppState>,
    o: String,
    n: String,
    slug: String,
    u: String,
    h: HeaderMap,
) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    serialize_member_mutation(&tx, &actor, &o, &n).await?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Admin, crate::token_scopes::RepoAction::MembersAdmin).await?;
    let tid = lookup_team_id(&tx, acc.repo_id, &slug).await?;
    let (uid, uname) = lookup_user(&tx, &u).await?;
    if uid == acc.owner_id {
        return Err(Error(
            StatusCode::CONFLICT,
            "cannot modify or remove repository owner",
        ));
    }
    let ins = "INSERT INTO repository_team_members (team_id, repository_id, user_id) VALUES ($1, $2, $3) ON CONFLICT (team_id, user_id) DO NOTHING";
    let inserted = tx
        .execute(ins, &[&tid, &acc.repo_id, &uid])
        .await
        .map_err(Error::internal)?;
    let q = format!(
        "SELECT {TEAM_MEMBER_FIELDS} FROM repository_team_members tm JOIN users u ON u.id = tm.user_id WHERE tm.team_id=$1 AND tm.user_id=$2"
    );
    let row = tx
        .query_one(&q, &[&tid, &uid])
        .await
        .map_err(Error::internal)?;
    let member = TeamMember::row(&row);
    if inserted == 1 {
        let det = sjson!({ "team_slug": slug, "username": uname });
        let target = format!("{slug}:{uname}");
        finish_audit(
            tx,
            acc,
            &actor,
            "team_member.added",
            "team_member",
            &target,
            det,
        )
        .await?;
        Ok(json(StatusCode::CREATED, member))
    } else {
        finish(tx, &actor, true).await?;
        Ok(json(StatusCode::OK, member))
    }
}

pub async fn remove_team_member(
    State(s): App,
    Path((o, n, slug, u)): MemberPath,
    h: HeaderMap,
) -> Res {
    let (actor, mut client) = open_client(&s, &h).await?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    serialize_member_mutation(&tx, &actor, &o, &n).await?;
    let acc = auth::authorize_repo_with_role(&tx, &actor, &o, &n, Role::Admin, crate::token_scopes::RepoAction::MembersAdmin).await?;
    let tid = lookup_team_id(&tx, acc.repo_id, &slug).await?;
    let (uid, uname) = lookup_user(&tx, &u).await?;
    let del = "DELETE FROM repository_team_members WHERE team_id=$1 AND user_id=$2";
    if tx
        .execute(del, &[&tid, &uid])
        .await
        .map_err(Error::internal)?
        == 0
    {
        return Err(Error::not_found());
    }
    let det = sjson!({ "team_slug": slug, "username": uname });
    let target = format!("{slug}:{uname}");
    finish_audit(
        tx,
        acc,
        &actor,
        "team_member.removed",
        "team_member",
        &target,
        det,
    )
    .await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "removed": true, "team_slug": slug, "username": uname }),
    ))
}
