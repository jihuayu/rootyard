//! Bounded, keyset-paginated browser repository discovery (`GET /web/repos`).
//!
//! The old handler used a fixed `LIMIT 101` and silently dropped every row
//! after the first 100. This module serves the complete list in stable
//! ascending `(namespace.slug, repository.name, repository.id)` order with an
//! opaque cursor bound to one actor and one list kind.
//!
//! Every request authenticates again, takes the live token lock in a
//! transaction, resolves the actor's *current* RBAC visibility and, for a
//! restricted PAT, requires the exact `repo_read` grant. Those checks are
//! applied in SQL before the keyset predicate, so a cursor can only move the
//! position inside the authorised set; it can never widen it. Only `ready`
//! repositories are visible. `auth::finish_tx` re-verifies the token and commits
//! at the end, exactly like the rest of the web handlers.
use crate::{
    AppState, Error, auth, db, pagination,
    web::{handlers::authenticate_web, sanitize::escape_html, templates::html_response},
};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Fixed page size. The SQL asks for `PAGE_LIMIT + 1` rows so a full page can
/// advertise a bounded next position without a second query.
const PAGE_LIMIT: usize = 100;
/// Stable list identity mixed into the cursor scope.
const LIST_KIND: &str = "discover";
const LIST_VERSION: &str = "v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverQuery {
    /// Opaque keyset position returned by the previous page.
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Audience {
    /// Unrestricted legacy token: current RBAC visibility only.
    Full,
    /// Restricted PAT: current RBAC visibility *and* the exact `repo_read`
    /// token grant preserved from the PAT foundation.
    Restricted,
}

impl Audience {
    fn label(self) -> &'static str {
        match self {
            Audience::Full => "all",
            Audience::Restricted => "restricted",
        }
    }
}

/// Cursor scope binds the actor, the list kind, the audience and a format
/// version. A cursor from another actor or a different list kind is rejected
/// as a malformed request instead of being applied to a wider list.
fn cursor_scope(audience: Audience, actor_id: Uuid) -> String {
    format!("web-repos:{LIST_KIND}:{LIST_VERSION}:{}:{actor_id}", audience.label())
}

/// Strictly decode one cursor position. Wrong field count, foreign scope,
/// malformed base64/UTF-8, invalid slug/name or invalid UUID all fail with
/// `400`, never with a silent fallback to page one.
fn decode_cursor(raw: &str, audience: Audience, actor_id: Uuid) -> Result<(String, String, Uuid), Error> {
    let fields = pagination::decode(raw, &cursor_scope(audience, actor_id), 3)?;
    let slug = fields[0].clone();
    let name = fields[1].clone();
    if !db::valid_name(&slug) || !db::valid_name(&name) {
        return Err(Error::bad_request());
    }
    let repository_id = Uuid::parse_str(&fields[2]).map_err(|_| Error::bad_request())?;
    Ok((slug, name, repository_id))
}

/// Keyset SQL shared by both audiences. The visibility union is grouped before
/// the cursor predicate so a cursor is always a position, not a permission.
fn page_sql(restricted: bool) -> &'static str {
    if restricted {
        concat!(
            "SELECT ns.slug,r.name,r.id FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id ",
            "WHERE r.state='ready' AND (ns.user_id=$6",
            " OR EXISTS (SELECT 1 FROM organization_memberships m WHERE m.organization_id=r.owner_id AND m.user_id=$6)",
            " OR EXISTS (SELECT 1 FROM organization_team_members tm WHERE tm.organization_id=r.owner_id AND tm.user_id=$6)",
            " OR EXISTS (SELECT 1 FROM repository_collaborators c WHERE c.repository_id=r.id AND c.user_id=$6)",
            " OR EXISTS (SELECT 1 FROM repository_team_members tm WHERE tm.repository_id=r.id AND tm.user_id=$6))",
            " AND EXISTS (SELECT 1 FROM token_repository_scopes ts ",
            "WHERE ts.token_id=$1 AND ts.repository_id=r.id AND ts.action='repo_read')",
            " AND ($2::text IS NULL OR (ns.slug,r.name,r.id) > ($2::text,$3::text,$4::uuid))",
            " ORDER BY ns.slug,r.name,r.id LIMIT $5"
        )
    } else {
        concat!(
            "SELECT ns.slug,r.name,r.id FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id ",
            "WHERE r.state='ready' AND (ns.user_id=$1",
            " OR EXISTS (SELECT 1 FROM organization_memberships m WHERE m.organization_id=r.owner_id AND m.user_id=$1)",
            " OR EXISTS (SELECT 1 FROM organization_team_members tm WHERE tm.organization_id=r.owner_id AND tm.user_id=$1)",
            " OR EXISTS (SELECT 1 FROM repository_collaborators c WHERE c.repository_id=r.id AND c.user_id=$1)",
            " OR EXISTS (SELECT 1 FROM repository_team_members tm WHERE tm.repository_id=r.id AND tm.user_id=$1))",
            " AND ($2::text IS NULL OR (ns.slug,r.name,r.id) > ($2::text,$3::text,$4::uuid))",
            " ORDER BY ns.slug,r.name,r.id LIMIT $5"
        )
    }
}

fn render_page(items: &[(String, String)], next_cursor: Option<&str>) -> String {
    let mut html = String::from(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Repositories</title><h1>Repositories</h1><form method=\"post\" action=\"/web/logout\"><button>Sign out</button></form>",
    );
    if items.is_empty() {
        html.push_str("<p>No repositories are available to your account. Ask an owner for access.</p>");
    } else {
        html.push_str("<ul>");
        for (owner, name) in items {
            let owner = escape_html(owner);
            let name = escape_html(name);
            html.push_str(&format!("<li><a href=\"/web/repos/{owner}/{name}\">{owner}/{name}</a></li>"));
        }
        html.push_str("</ul>");
    }
    if let Some(cursor) = next_cursor {
        // Relative link: the cursor is percent-encoded for the query value and
        // the whole href is HTML-escaped before interpolation. The last page
        // emits no link at all.
        let href = escape_html(&format!("?cursor={}", pagination::query_value(cursor)));
        html.push_str(&format!("<p class=\"pagination\"><a rel=\"next\" href=\"{href}\">Next page</a></p>"));
    }
    html.push_str("</html>");
    html
}

pub async fn discover(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DiscoverQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    // Re-authenticate on every page from the browser cookie/API header. The
    // middleware has already enforced the session/CSRF contract for mutations
    // and navigation; this handler still needs the current identity.
    let actor = authenticate_web(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    // Live token lock + real-clock expiry check; restricted grants are read in
    // this same transaction below.
    auth::verify_token(&tx, &actor, false).await?;
    let restricted = auth::token_is_restricted(&tx, &actor).await?;
    let audience = if restricted { Audience::Restricted } else { Audience::Full };
    // No cursor means the first page has no keyset predicate.
    let (cursor_slug, cursor_name, cursor_id) = match query.cursor.as_deref() {
        Some(raw) => {
            let (slug, name, id) = decode_cursor(raw, audience, actor.id)?;
            (Some(slug), Some(name), Some(id))
        }
        None => (None, None, None),
    };
    let limit = (PAGE_LIMIT + 1) as i64;
    let rows = if restricted {
        tx.query(
            page_sql(true),
            &[
                &actor.token_id,
                &cursor_slug,
                &cursor_name,
                &cursor_id,
                &limit,
                &actor.id,
            ],
        )
        .await
        .map_err(Error::internal)?
    } else {
        tx.query(page_sql(false), &[&actor.id, &cursor_slug, &cursor_name, &cursor_id, &limit])
            .await
            .map_err(Error::internal)?
    };
    let more = rows.len() > PAGE_LIMIT;
    let mut items = Vec::with_capacity(rows.len().min(PAGE_LIMIT));
    for row in rows.iter().take(PAGE_LIMIT) {
        items.push((row.get::<_, String>(0), row.get::<_, String>(1)));
    }
    let next_cursor = if more {
        rows.get(PAGE_LIMIT - 1).map(|row| {
            let slug: String = row.get(0);
            let name: String = row.get(1);
            let id: Uuid = row.get(2);
            let id = id.to_string();
            pagination::encode(&cursor_scope(audience, actor.id), &[slug.as_str(), name.as_str(), id.as_str()])
        })
    } else {
        None
    };
    // Re-verify the token with the real database clock before committing, so a
    // revocation during a slow page read fails closed.
    auth::finish_tx(tx, &actor, false).await?;
    Ok(html_response(StatusCode::OK, render_page(&items, next_cursor.as_deref())))
}
