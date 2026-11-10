//! Mutating organization-admin web actions.
//!
//! Each handler normalizes the browser credential with the shared web helper
//! and then calls the existing organization API implementation. Authorization,
//! the read-only fence, restricted-token scopes, organization admin role,
//! optimistic concurrency and audit logging all stay in that single backend
//! implementation. Cookie sessions have already passed the `/web` Origin +
//! CSRF middleware before this code runs; no credential or CSRF value is
//! echoed into a redirect or page.
//!
//! No preflight in this module reads organization-private state. The web layer
//! only validates request syntax (names and the version string) and then hands
//! the operation to the shared backend, so a caller without the organization
//! admin role gets the same response whether a target user, membership or team
//! exists or not.

use crate::{
    AppState, Error, auth,
    db,
    members::models::Role,
    organizations::handlers::{self as org_handlers, MembershipInput, TeamInput},
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
    /// string so `app.js` can submit the plain form object unchanged. Only a
    /// completely absent field means "new membership"; an explicitly empty or
    /// non-numeric value is a `400`, never a silent unversioned update that
    /// could recreate a removed membership from a stale page.
    #[serde(default)]
    pub expected_version: Option<String>,
}

impl MemberSetForm {
    fn version(&self) -> Result<Option<i64>, Error> {
        match self.expected_version.as_deref() {
            None => Ok(None),
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
/// The create path is passed to the shared backend as `create_only`, so the
/// "does this membership already exist" decision and the write happen in the
/// same transaction after the organization admin authorization. A stale form
/// carrying a version for a removed membership is a `409`, not a recreation.
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
    // Fast read-only fence; the backend re-checks it inside the write.
    auth::writable(&actor)?;
    let create_only = expected_version.is_none();
    org_handlers::put_member_atomic(
        state,
        slug.clone(),
        form.username,
        normalize_web_headers(&headers),
        MembershipInput { role: form.role, expected_version },
        create_only,
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

/// Add an organization member to a team. The team, target-user and
/// organization-membership checks all run inside the shared backend after the
/// organization admin authorization, so this layer cannot leak their existence
/// to a non-admin caller.
pub async fn team_member_add(
    State(state): App,
    Path((slug, team_slug)): Path<(String, String)>,
    headers: HeaderMap,
    Json(form): Json<TeamMemberForm>,
) -> Res {
    // Preserve the 401-before-404 precedence of the JSON API; this performs no
    // organization lookup.
    authenticate_web(&state.pool, &headers).await?;
    if !db::valid_name(&form.username) || !db::valid_name(&team_slug) {
        return Err(Error::not_found());
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
