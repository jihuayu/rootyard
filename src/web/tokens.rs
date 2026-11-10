//! Browser settings pages for personal access tokens and browser sessions.
//!
//! Authentication and every mutation go through the existing web middleware:
//! the HttpOnly session cookie is bound to an active, unrestricted API parent,
//! the Origin must match the service, and mutations must carry the CSRF header
//! from `rootyard_csrf`. These handlers then call the shared
//! `token_management::service`, exactly like the JSON API.
//!
//! Product pages show only safe metadata (name, expiry, created time,
//! read-only flag, explicit grants). The plaintext secret is returned once by
//! create/rotate in a `no-store` response and is never rendered into a later
//! page, list, URL, or log.

use crate::{
    AppState, Error,
    db::Identity,
    token_management::{
        json_response,
        models::{CreateTokenInput, PageQuery, UpdateTokenInput},
        service,
    },
    token_scopes::{NamespaceAction, RepoAction},
    web::{handlers::authenticate_web, sanitize::escape_html, templates::html_response},
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

type App = Arc<AppState>;
type Res = Result<Response, Error>;

/// Re-check that a cookie session's parent API token is still active and
/// unrestricted. Browser children of a restricted/revoked parent must not be
/// able to manage anything, even if the child token row itself looks live.
pub async fn verify_browser_parent(state: &AppState, headers: &HeaderMap) -> Result<(), Error> {
    if headers.contains_key(header::AUTHORIZATION) {
        return Ok(());
    }
    let Some(secret) = super::session::session_token(headers) else {
        return Ok(());
    };
    let Some(parent) = crate::token_management::models::session_parent(&secret) else {
        return Err(Error::unauthorized());
    };
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT 1 FROM tokens p WHERE p.id = $1 AND p.kind = 'api' \
               AND p.is_restricted = false AND NOT p.revoked \
               AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp())",
            &[&parent],
        )
        .await
        .map_err(Error::internal)?;
    row.map(|_| ()).ok_or_else(Error::unauthorized)
}

async fn visible_repositories(state: &AppState, actor: &Identity) -> Result<Vec<(Uuid, String, String)>, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT r.id, ns.slug, r.name FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id \
              WHERE r.state = 'ready' AND (ns.user_id = $1 \
                OR EXISTS (SELECT 1 FROM organization_memberships m WHERE m.organization_id = r.owner_id AND m.user_id = $1) \
                OR EXISTS (SELECT 1 FROM repository_collaborators c WHERE c.repository_id = r.id AND c.user_id = $1) \
                OR EXISTS (SELECT 1 FROM repository_team_members tm WHERE tm.repository_id = r.id AND tm.user_id = $1) \
                OR EXISTS (SELECT 1 FROM organization_team_members tm WHERE tm.organization_id = r.owner_id AND tm.user_id = $1)) \
              ORDER BY ns.slug, r.name LIMIT 101",
            &[&actor.id],
        )
        .await
        .map_err(Error::internal)?;
    Ok(rows.iter().take(100).map(|row| (row.get(0), row.get(1), row.get(2))).collect())
}

async fn member_organizations(state: &AppState, actor: &Identity) -> Result<Vec<(Uuid, String)>, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT o.id, ns.slug FROM organizations o \
               JOIN namespaces ns ON ns.organization_id = o.id AND ns.kind = 'organization' \
               JOIN organization_memberships m ON m.organization_id = o.id \
              WHERE m.user_id = $1 ORDER BY ns.slug LIMIT 101",
            &[&actor.id],
        )
        .await
        .map_err(Error::internal)?;
    Ok(rows.iter().take(100).map(|row| (row.get(0), row.get(1))).collect())
}

fn action_checkboxes(name: &str, prefix: &str) -> String {
    let mut html = String::new();
    for action in RepoAction::ALL {
        let value = format!("{prefix}{}", action.as_str());
        let label = escape_html(action.as_str());
        html.push_str(&format!(
            "<label><input type=\"checkbox\" name=\"{name}\" value=\"{value}\"> {label}</label>"
        ));
    }
    html
}

fn namespace_checkboxes() -> String {
    let mut html = String::new();
    for action in NamespaceAction::ALL {
        let value = format!("org:{}", action.as_str());
        let label = escape_html(action.as_str());
        html.push_str(&format!(
            "<label><input type=\"checkbox\" name=\"org_action\" value=\"{value}\"> {label}</label>"
        ));
    }
    html
}

fn repository_options(repositories: &[(Uuid, String, String)]) -> String {
    let mut html = String::new();
    for (id, owner, name) in repositories {
        let label = escape_html(&format!("{owner}/{name}"));
        html.push_str(&format!("<option value=\"{id}\">{label}</option>"));
    }
    if html.is_empty() {
        html.push_str("<option value=\"\">No repositories available</option>");
    }
    html
}

fn organization_options(organizations: &[(Uuid, String)]) -> String {
    let mut html = String::new();
    for (id, slug) in organizations {
        let label = escape_html(slug);
        html.push_str(&format!("<option value=\"{id}\">{label}</option>"));
    }
    if html.is_empty() {
        html.push_str("<option value=\"\">No organisations available</option>");
    }
    html
}

fn page_shell(title: &str, inner: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title></head><body>\
         <nav><a href=\"/web/repos\">Repositories</a> &middot; <a href=\"/web/settings/tokens\">Tokens</a> \
         &middot; <a href=\"/web/settings/sessions\">Sessions</a></nav><main>{inner}</main>\
         <script src=\"/web/app.js\" defer></script></body></html>"
    )
}

fn secret_box() -> &'static str {
    "<section id=\"token-secret\" hidden><h2>New token secret</h2>\
     <p>Copy this secret now. It is shown once and cannot be retrieved again.</p>\
     <pre><code></code></pre></section>"
}

fn grant_summary(view: &crate::token_management::models::TokenView) -> String {
    let mut parts = Vec::new();
    for grant in &view.repository_grants {
        parts.push(escape_html(&format!(
            "{}/{}: {}",
            grant.owner,
            grant.name,
            grant.actions.join(", ")
        )));
    }
    for grant in &view.namespace_grants {
        parts.push(escape_html(&format!("{}: {}", grant.slug, grant.actions.join(", "))));
    }
    if parts.is_empty() {
        "No grants (this token is denied everything).".to_owned()
    } else {
        parts.join("; ")
    }
}

fn scope_form(view: &crate::token_management::models::TokenView) -> String {
    let mut inputs = String::new();
    for grant in &view.repository_grants {
        for action in &grant.actions {
            let value = format!("repo:{}:{}", grant.repository_id, action);
            let label = escape_html(&format!("{}/{} {}", grant.owner, grant.name, action));
            inputs.push_str(&format!(
                "<label><input type=\"checkbox\" name=\"grant\" value=\"{value}\" checked> {label}</label>"
            ));
        }
    }
    for grant in &view.namespace_grants {
        for action in &grant.actions {
            let value = format!("org:{}:{}", grant.organization_id, action);
            let label = escape_html(&format!("{} {}", grant.slug, action));
            inputs.push_str(&format!(
                "<label><input type=\"checkbox\" name=\"grant\" value=\"{value}\" checked> {label}</label>"
            ));
        }
    }
    if inputs.is_empty() {
        inputs.push_str("<p>This token has no grants. Saving keeps it denied everything.</p>");
    }
    format!(
        "<form action=\"/web/settings/tokens/{}/scope\" data-web-action=\"token-scope\">\
         <input type=\"hidden\" name=\"expected_scope_version\" value=\"{}\">\
         <input type=\"hidden\" name=\"token_id\" value=\"{}\">{inputs}\
         <button>Save narrowed scope</button><p class=\"form-result\" role=\"status\"></p></form>",
        view.id, view.scope_version, view.id
    )
}

fn token_row(view: &crate::token_management::models::TokenView) -> String {
    let name = view.display_name.clone().unwrap_or_else(|| "(unnamed)".to_owned());
    let expires = view.expires_at.clone().unwrap_or_else(|| "never".to_owned());
    let read_only = if view.read_only { "read-only" } else { "read-write" };
    let restricted = if view.is_restricted { "restricted" } else { "legacy account-wide" };
    format!(
        "<li><h2>{}</h2><p>id {}</p>\
         <p>expires {} &middot; created {} &middot; {} &middot; {} &middot; scope version {}</p>\
         <p>{}</p>\
         <form action=\"/web/settings/tokens/{}/rotate\" data-web-action=\"token-rotate\" data-secret-output=\"token-secret\">\
         <button>Rotate</button><p class=\"form-result\" role=\"status\"></p></form>\
         <form action=\"/web/settings/tokens/{}/revoke\" data-web-action=\"token-revoke\">\
         <button>Revoke</button><p class=\"form-result\" role=\"status\"></p></form>\
         {}</li>",
        escape_html(&name),
        view.id,
        escape_html(&expires),
        escape_html(&view.created_at),
        read_only,
        restricted,
        view.scope_version,
        grant_summary(view),
        view.id,
        view.id,
        scope_form(view)
    )
}

pub async fn tokens_page(State(state): State<App>, headers: HeaderMap, Query(query): Query<PageQuery>) -> Res {
    let (after, limit) = query.validate()?;
    verify_browser_parent(&state, &headers).await?;
    let actor = authenticate_web(&state.pool, &headers).await?;
    let page = service::list_tokens(&state.pool, &actor, after, limit).await?;
    let repositories = visible_repositories(&state, &actor).await?;
    let organizations = member_organizations(&state, &actor).await?;
    let mut rows = String::new();
    for view in &page.items {
        rows.push_str(&token_row(view));
    }
    if rows.is_empty() {
        rows.push_str("<li>No personal access tokens yet.</li>");
    }
    let more = page
        .next_after
        .as_ref()
        .map(|after| {
            format!(
                "<p><a href=\"/web/settings/tokens?after={}\">Older tokens</a></p>",
                escape_html(&crate::pagination::query_value(after))
            )
        })
        .unwrap_or_default();
    let inner = format!(
        "<h1>Personal access tokens</h1>\
         <p>Only API tokens you own are listed. Browser sessions, CI credentials and integration tokens are not shown.</p>\
         {}\
         <h2>Create token</h2>\
         <form action=\"/web/settings/tokens\" data-web-action=\"token-create\" data-secret-output=\"token-secret\">\
         <label>Name <input name=\"display_name\" maxlength=\"80\" required></label>\
         <label>Expires in days <input name=\"expires_in_days\" type=\"number\" min=\"1\" max=\"365\" value=\"30\" required></label>\
         <label><input type=\"checkbox\" name=\"read_only\" value=\"true\"> Read-only</label>\
         <label>Repository <select name=\"repository_id\">{}</select></label>\
         <fieldset><legend>Repository actions (none = deny all)</legend>{}</fieldset>\
         <label>Organisation <select name=\"organization_id\">{}</select></label>\
         <fieldset><legend>Organisation actions (none = none)</legend>{}</fieldset>\
         <button>Create restricted token</button><p class=\"form-result\" role=\"status\"></p></form>\
         <h2>Your tokens</h2><ul>{rows}</ul>{more}",
        secret_box(),
        repository_options(&repositories),
        action_checkboxes("repo_action", ""),
        organization_options(&organizations),
        namespace_checkboxes()
    );
    Ok(html_response(StatusCode::OK, page_shell("Personal access tokens", &inner)))
}

pub async fn create_token_web(State(state): State<App>, headers: HeaderMap, Json(input): Json<CreateTokenInput>) -> Res {
    verify_browser_parent(&state, &headers).await?;
    let actor = authenticate_web(&state.pool, &headers).await?;
    let issued = service::create_token(&state.pool, &actor, input).await?;
    Ok(json_response(StatusCode::CREATED, issued))
}

pub async fn rotate_token_web(State(state): State<App>, headers: HeaderMap, Path(token_id): Path<Uuid>) -> Res {
    verify_browser_parent(&state, &headers).await?;
    let actor = authenticate_web(&state.pool, &headers).await?;
    let issued = service::rotate_token(&state.pool, &actor, token_id).await?;
    Ok(json_response(StatusCode::OK, issued))
}

pub async fn revoke_token_web(State(state): State<App>, headers: HeaderMap, Path(token_id): Path<Uuid>) -> Res {
    verify_browser_parent(&state, &headers).await?;
    let actor = authenticate_web(&state.pool, &headers).await?;
    service::revoke_token(&state.pool, &actor, token_id).await?;
    Ok(json_response(StatusCode::OK, serde_json::json!({"revoked": true})))
}

pub async fn update_token_web(
    State(state): State<App>,
    headers: HeaderMap,
    Path(token_id): Path<Uuid>,
    Json(input): Json<UpdateTokenInput>,
) -> Res {
    verify_browser_parent(&state, &headers).await?;
    let actor = authenticate_web(&state.pool, &headers).await?;
    let view = service::update_token(&state.pool, &actor, token_id, input).await?;
    Ok(json_response(StatusCode::OK, view))
}

pub async fn sessions_page(State(state): State<App>, headers: HeaderMap, Query(query): Query<PageQuery>) -> Res {
    let (after, limit) = query.validate()?;
    verify_browser_parent(&state, &headers).await?;
    let actor = authenticate_web(&state.pool, &headers).await?;
    let page = service::list_sessions(&state.pool, &actor, after, limit).await?;
    let mut rows = String::new();
    for session in &page.items {
        rows.push_str(&format!(
            "<li><p>session {}</p><p>created {} &middot; expires {}</p>\
             <form action=\"/web/settings/sessions/{}/revoke\" data-web-action=\"session-revoke\">\
             <button>Revoke session</button><p class=\"form-result\" role=\"status\"></p></form></li>",
            session.token_id,
            escape_html(&session.created_at),
            escape_html(&session.expires_at),
            session.token_id
        ));
    }
    if rows.is_empty() {
        rows.push_str("<li>No live browser sessions.</li>");
    }
    let more = page
        .next_after
        .as_ref()
        .map(|after| {
            format!(
                "<p><a href=\"/web/settings/sessions?after={}\">Older sessions</a></p>",
                escape_html(&crate::pagination::query_value(after))
            )
        })
        .unwrap_or_default();
    let inner = format!(
        "<h1>Browser sessions</h1>\
         <p>These are sessions signed in from this account. Revoking a session signs that browser out.</p>\
         <ul>{rows}</ul>{more}"
    );
    Ok(html_response(StatusCode::OK, page_shell("Browser sessions", &inner)))
}

pub async fn revoke_session_web(
    State(state): State<App>,
    headers: HeaderMap,
    Path(session_token_id): Path<Uuid>,
) -> Res {
    verify_browser_parent(&state, &headers).await?;
    let actor = authenticate_web(&state.pool, &headers).await?;
    service::revoke_session(&state.pool, &actor, session_token_id).await?;
    Ok(json_response(StatusCode::OK, serde_json::json!({"revoked": true})))
}
