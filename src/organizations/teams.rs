//! Organization team lifecycle and paginated team-member read handlers.
use crate::{
    AppState, Error, auth, db,
    members::models::{Role, json},
    pagination,
    token_scopes::NamespaceAction,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Uri},
};
use serde::Deserialize;
use serde_json::{Value, json as sjson};
use std::sync::Arc;
use uuid::Uuid;

use super::handlers::{
    Res, audit,
    listing::{OrgListQuery, bad_cursor, limit_of, page_response},
    lock_org_for_admin, org_id, require_member,
};

/// Bounded patch payload for updating an existing organization team.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateOrgTeamInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub role: Option<Role>,
    pub expected_version: i64,
}

fn team_member_scope(actor: Uuid, org: Uuid, team: Uuid) -> String {
    format!("organization-team-members:{actor}:{org}:{team}")
}

fn decode_team_member_cursor(raw: &str, actor: Uuid, org: Uuid, team: Uuid) -> Result<(String, Uuid), Error> {
    let fields = pagination::decode(raw, &team_member_scope(actor, org, team), 2)?;
    let [username, user_id] = fields.as_slice() else {
        return Err(bad_cursor());
    };
    let user_id = Uuid::parse_str(user_id).map_err(|_| bad_cursor())?;
    if user_id.is_nil() || !db::valid_name(username) {
        return Err(bad_cursor());
    }
    Ok((username.clone(), user_id))
}

fn validate_team_patch(input: &UpdateOrgTeamInput) -> Result<(), Error> {
    if input.expected_version <= 0 || (input.name.is_none() && input.role.is_none()) {
        return Err(Error::bad_request());
    }
    if input.name.as_deref().is_some_and(|name| name.trim().is_empty() || name.len() > 128 || name.contains('\0')) {
        return Err(Error::bad_request());
    }
    Ok(())
}

/// Fetch one organization team and its current member count.
pub async fn get_team(
    State(state): State<Arc<AppState>>,
    Path((slug, team_slug)): Path<(String, String)>,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgRead).await?;
    require_member(&tx, org, actor.id, Role::Read).await?;
    if !db::valid_name(&team_slug) {
        return Err(Error::not_found());
    }
    let row = tx
        .query_opt(
            "SELECT t.id, t.slug, t.name, t.role, t.version, t.created_at::text, \
             (SELECT count(*) FROM organization_team_members tm WHERE tm.team_id = t.id) AS member_count \
             FROM organization_teams t WHERE t.organization_id = $1 AND t.slug = $2",
            &[&org, &team_slug],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    auth::finish_tx(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({
            "id": row.get::<_, Uuid>(0),
            "slug": row.get::<_, &str>(1),
            "name": row.get::<_, &str>(2),
            "role": row.get::<_, &str>(3),
            "version": row.get::<_, i64>(4),
            "created_at": row.get::<_, String>(5),
            "member_count": row.get::<_, i64>(6),
        }),
    ))
}

/// Update an organization team's display name and/or baseline role using CAS versioning.
pub async fn patch_team(
    State(state): State<Arc<AppState>>,
    Path((slug, team_slug)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<UpdateOrgTeamInput>,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    validate_team_patch(&input)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgTeamsWrite).await?;
    lock_org_for_admin(&tx, org, actor.id).await?;
    if !db::valid_name(&team_slug) {
        return Err(Error::not_found());
    }
    let existing = tx
        .query_opt(
            "SELECT id, name, role, version FROM organization_teams \
             WHERE organization_id = $1 AND slug = $2 FOR UPDATE",
            &[&org, &team_slug],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let version: i64 = existing.get(3);
    if version != input.expected_version {
        return Err(Error(StatusCode::CONFLICT, "team version conflict"));
    }
    let team_id: Uuid = existing.get(0);
    let current_role = Role::parse(existing.get::<_, &str>(2))?;
    let next_name = input.name.unwrap_or_else(|| existing.get::<_, String>(1));
    let next_role = input.role.unwrap_or(current_role);
    let updated_version: i64 = tx
        .query_one(
            "UPDATE organization_teams SET name = $3, role = $4, version = version + 1 \
             WHERE id = $1 AND organization_id = $2 RETURNING version",
            &[&team_id, &org, &next_name, &next_role.as_str()],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    audit(
        &tx,
        org,
        actor.id,
        "organization.team.updated",
        &team_slug,
        sjson!({"name": next_name, "role": next_role.as_str(), "version": updated_version}),
    )
    .await?;
    auth::finish_tx(tx, &actor, true).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({
            "id": team_id,
            "slug": team_slug,
            "name": next_name,
            "role": next_role.as_str(),
            "version": updated_version,
        }),
    ))
}

/// Delete an organization team and cascade-remove all its team memberships.
pub async fn delete_team(
    State(state): State<Arc<AppState>>,
    Path((slug, team_slug)): Path<(String, String)>,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgTeamsWrite).await?;
    lock_org_for_admin(&tx, org, actor.id).await?;
    if !db::valid_name(&team_slug) {
        return Err(Error::not_found());
    }
    tx.query_opt(
        "DELETE FROM organization_teams WHERE organization_id = $1 AND slug = $2 RETURNING id",
        &[&org, &team_slug],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::not_found)?;
    audit(&tx, org, actor.id, "organization.team.deleted", &team_slug, sjson!({})).await?;
    auth::finish_tx(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sjson!({"deleted": true, "slug": team_slug})))
}

/// Keyset-paginated list of members belonging to one organization team.
pub async fn list_team_members(
    State(state): State<Arc<AppState>>,
    Path((slug, team_slug)): Path<(String, String)>,
    Query(query): Query<OrgListQuery>,
    uri: Uri,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let limit = limit_of(&query)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgRead).await?;
    require_member(&tx, org, actor.id, Role::Read).await?;
    if !db::valid_name(&team_slug) {
        return Err(Error::not_found());
    }
    let team_id: Uuid = tx
        .query_opt(
            "SELECT id FROM organization_teams WHERE organization_id = $1 AND slug = $2 FOR SHARE",
            &[&org, &team_slug],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    let cursor = match query.cursor.as_deref() {
        Some(raw) => Some(decode_team_member_cursor(raw, actor.id, org, team_id)?),
        None => None,
    };
    let rows = match &cursor {
        None => {
            tx.query(
                "SELECT u.username, tm.user_id, m.role, tm.created_at::text \
                 FROM organization_team_members tm \
                 JOIN users u ON u.id = tm.user_id \
                 LEFT JOIN organization_memberships m \
                   ON m.organization_id = tm.organization_id AND m.user_id = tm.user_id \
                 WHERE tm.team_id = $1 AND tm.organization_id = $2 \
                 ORDER BY u.username, tm.user_id LIMIT $3",
                &[&team_id, &org, &(limit + 1)],
            )
            .await
        }
        Some((username, user_id)) => {
            tx.query(
                "SELECT u.username, tm.user_id, m.role, tm.created_at::text \
                 FROM organization_team_members tm \
                 JOIN users u ON u.id = tm.user_id \
                 LEFT JOIN organization_memberships m \
                   ON m.organization_id = tm.organization_id AND m.user_id = tm.user_id \
                 WHERE tm.team_id = $1 AND tm.organization_id = $2 \
                   AND (u.username, tm.user_id) > ($3, $4) \
                 ORDER BY u.username, tm.user_id LIMIT $5",
                &[&team_id, &org, username, user_id, &(limit + 1)],
            )
            .await
        }
    }
    .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let kept: Vec<_> = rows.iter().take(limit as usize).collect();
    let next_cursor = if more {
        kept.last().map(|r| {
            let user_id = r.get::<_, Uuid>(1).to_string();
            pagination::encode(&team_member_scope(actor.id, org, team_id), &[r.get::<_, &str>(0), user_id.as_str()])
        })
    } else {
        None
    };
    let items: Vec<Value> = kept
        .iter()
        .map(|r| {
            sjson!({
                "username": r.get::<_, &str>(0),
                "organization_role": r.get::<_, Option<&str>>(2),
                "created_at": r.get::<_, String>(3),
            })
        })
        .collect();
    auth::finish_tx(tx, &actor, false).await?;
    page_response(items, more, next_cursor, &uri, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_team_rejects_unknown_fields_and_bad_values() {
        assert!(serde_json::from_str::<UpdateOrgTeamInput>(r#"{"expected_version":1,"extra":true}"#).is_err());
        let empty = UpdateOrgTeamInput { name: None, role: None, expected_version: 1 };
        assert!(validate_team_patch(&empty).is_err());
        let zero_version = UpdateOrgTeamInput { name: Some("Core".into()), role: None, expected_version: 0 };
        assert!(validate_team_patch(&zero_version).is_err());
        let blank_name = UpdateOrgTeamInput { name: Some("   ".into()), role: None, expected_version: 1 };
        assert!(validate_team_patch(&blank_name).is_err());
        let valid = UpdateOrgTeamInput { name: Some("Core".into()), role: Some(Role::Maintain), expected_version: 2 };
        assert!(validate_team_patch(&valid).is_ok());
    }

    #[test]
    fn team_member_cursor_is_bound_to_actor_org_and_team() {
        let (actor, org, team_a, team_b) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let user_id = Uuid::new_v4();
        let uid_str = user_id.to_string();
        let raw = pagination::encode(&team_member_scope(actor, org, team_a), &["bob", uid_str.as_str()]);
        assert!(decode_team_member_cursor(&raw, actor, org, team_a).is_ok());
        assert!(decode_team_member_cursor(&raw, actor, org, team_b).is_err());
        assert!(decode_team_member_cursor(&raw, Uuid::new_v4(), org, team_a).is_err());
        assert!(decode_team_member_cursor(&raw, actor, Uuid::new_v4(), team_a).is_err());
    }
}
