//! Mutating organization-admin web actions.
//!
//! Each handler normalizes the browser credential with the shared web helper
//! and then calls the existing organization API handler. Authorization, the
//! read-only fence, restricted-token scopes, optimistic concurrency and audit
//! logging all stay in that single backend implementation. Cookie sessions
//! have already passed the `/web` Origin + CSRF middleware before this code
//! runs; no credential or CSRF value is echoed into a redirect or page.

use crate::{
    AppState, Error, auth,
    db,
    members::models::Role,
    organizations::handlers::{self as org_handlers, MembershipInput, TeamInput},
    token_scopes::NamespaceAction,
    web::handlers::{authenticate_web, normalize_web_headers},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use std::sync::Arc;

type App = State<Arc<AppState>>;
type Res = Result<Response, Error>;

/// Reject any credential that can read but must never mutate: read-only tokens
/// fail here *and* in `verify_token` inside the API handler.
fn see_other(location: &str) -> Response {
    let mut response = Redirect::to(location).into_response();
    *response.status_mut() = StatusCode::SEE_OTHER;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberSetForm {
    pub username: String,
    pub role: Role,
    /// The current membership version, rendered as a hidden field. Kept as a
    /// string so `app.js` can submit the plain form object unchanged; it is
    /// parsed strictly here and an invalid value is a `400`, never a silent
    /// "no version" update.
    #[serde(default)]
    pub expected_version: Option<String>,
}

impl MemberSetForm {
    fn version(&self) -> Result<Option<i64>, Error> {
        match self.expected_version.as_deref() {
            None | Some("") => Ok(None),
            Some(raw) => match raw.parse::<i64>() {
                Ok(version) if version > 0 => Ok(Some(version)),
                _ => Err(Error::bad_request()),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamMemberForm {
    pub username: String,
}

/// Add a member, or update a role when the current version is supplied.
///
/// The create path refuses to overwrite an existing membership silently: the
/// admin must reload and use that row's versioned form. The check runs in its
/// own transaction before the API call; the API remains the authority for the
/// write itself.
pub async fn member_set(
    State(state): App,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(form): Json<MemberSetForm>,
) -> Res {
    let actor = authenticate_web(&state.pool, &headers).await?;
    if !db::valid_name(&form.username) {
        return Err(Error::not_found());
    }
    let expected_version = form.version()?;
    auth::writable(&actor)?;
    if expected_version.is_none() {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let org = org_handlers::org_id(&tx, &slug).await?;
        auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgMembersWrite).await?;
        let existing = tx
            .query_opt(
                "SELECT 1 FROM organization_memberships m JOIN users u ON u.id=m.user_id \
                 WHERE m.organization_id=$1 AND u.username=$2",
                &[&org, &form.username],
            )
            .await
            .map_err(Error::internal)?;
        if existing.is_some() {
            return Err(Error(
                StatusCode::CONFLICT,
                "membership already exists; reload and submit its current version",
            ));
        }
        auth::finish_tx(tx, &actor, false).await?;
    }
    let normalized = normalize_web_headers(&headers);
    org_handlers::put_member(
        State(state),
        Path((slug.clone(), form.username)),
        normalized,
        Json(MembershipInput { role: form.role, expected_version }),
    )
    .await?;
    Ok(see_other(&format!("/web/organizations/{slug}/members")))
}

pub async fn member_remove(
    State(state): App,
    Path((slug, username)): Path<(String, String)>,
    headers: HeaderMap,
) -> Res {
    if !db::valid_name(&username) {
        return Err(Error::not_found());
    }
    org_handlers::delete_member(
        State(state),
        Path((slug.clone(), username)),
        normalize_web_headers(&headers),
    )
    .await?;
    Ok(see_other(&format!("/web/organizations/{slug}/members")))
}

pub async fn team_create(
    State(state): App,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(input): Json<TeamInput>,
) -> Res {
    org_handlers::create_team(
        State(state),
        Path(slug.clone()),
        normalize_web_headers(&headers),
        Json(input),
    )
    .await?;
    Ok(see_other(&format!("/web/organizations/{slug}/teams")))
}

/// Add an organization member to a team. The pre-check only produces a clear
/// `409` for a username that cannot be a team member; the API handler still
/// performs the authorization and the write in its own transaction.
pub async fn team_member_add(
    State(state): App,
    Path((slug, team_slug)): Path<(String, String)>,
    headers: HeaderMap,
    Json(form): Json<TeamMemberForm>,
) -> Res {
    let actor = authenticate_web(&state.pool, &headers).await?;
    if !db::valid_name(&form.username) || !db::valid_name(&team_slug) {
        return Err(Error::not_found());
    }
    {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let org = org_handlers::org_id(&tx, &slug).await?;
        auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgTeamsWrite).await?;
        tx.query_opt(
            "SELECT 1 FROM organization_teams WHERE organization_id=$1 AND slug=$2",
            &[&org, &team_slug],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
        let target = tx
            .query_opt(
                "SELECT u.id FROM users u JOIN organization_memberships m \
                   ON m.user_id=u.id AND m.organization_id=$2 WHERE u.username=$1",
                &[&form.username, &org],
            )
            .await
            .map_err(Error::internal)?;
        if target.is_none() {
            return Err(Error(StatusCode::CONFLICT, "user is not an organization member"));
        }
        auth::finish_tx(tx, &actor, false).await?;
    }
    org_handlers::put_team_member(
        State(state),
        Path((slug.clone(), team_slug.clone(), form.username)),
        normalize_web_headers(&headers),
    )
    .await?;
    Ok(see_other(&format!("/web/organizations/{slug}/teams/{team_slug}")))
}

pub async fn team_member_remove(
    State(state): App,
    Path((slug, team_slug, username)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Res {
    if !db::valid_name(&team_slug) || !db::valid_name(&username) {
        return Err(Error::not_found());
    }
    org_handlers::delete_team_member(
        State(state),
        Path((slug.clone(), team_slug.clone(), username)),
        normalize_web_headers(&headers),
    )
    .await?;
    Ok(see_other(&format!("/web/organizations/{slug}/teams/{team_slug}")))
}
