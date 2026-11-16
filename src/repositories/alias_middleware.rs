//! Authz-before-redirect HTTP middleware resolving `repository_aliases` across Git,
//! CI-pinned Git, LFS, REST API, and Web UI surfaces with `308 Permanent Redirect`.
use super::alias::{ParsedRepoPath, RepoRouteKind, parse_repo_scoped_path, permanent_redirect_response};
use super::alias_policy::{AliasRequestInspect, body_inspect_limit, inspect_alias_request, surface_role_and_action};
use crate::{AppState, Error, application::MetadataState, auth, members::models::Role, web};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Method, Request, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use deadpool_postgres::Pool;
use std::sync::Arc;
use uuid::Uuid;

struct AliasTarget {
    repository_id: Uuid,
    owner: String,
    name: String,
    is_deleted: bool,
}

async fn lookup_alias(pool: &Pool, alias_owner: &str, alias_name: &str) -> Result<Option<AliasTarget>, Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT a.repository_id, tn.slug, r.name, (r.deleted_at IS NOT NULL) \
             FROM repository_aliases a \
             JOIN namespaces an ON an.id = a.alias_owner_id \
             JOIN repositories r ON r.id = a.repository_id \
             JOIN namespaces tn ON tn.id = r.owner_id \
             WHERE an.slug = $1 AND a.alias_name = $2",
            &[&alias_owner, &alias_name],
        )
        .await
        .map_err(Error::internal)?;
    Ok(row.map(|r| AliasTarget { repository_id: r.get(0), owner: r.get(1), name: r.get(2), is_deleted: r.get(3) }))
}

fn rewrite_ci_basic_owner(headers: &HeaderMap, alias_owner: &str, target_owner: &str) -> HeaderMap {
    if alias_owner == target_owner {
        return headers.clone();
    }
    let mut auth_values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(first) = auth_values.next() else {
        return headers.clone();
    };
    if auth_values.next().is_some() {
        return headers.clone();
    }
    let Ok(raw) = first.to_str() else {
        return headers.clone();
    };
    let Some((scheme, encoded)) = raw.trim().split_once(' ') else {
        return headers.clone();
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return headers.clone();
    }
    let Ok(decoded) = STANDARD.decode(encoded.trim()) else {
        return headers.clone();
    };
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return headers.clone();
    };
    let Some((user, secret)) = text.split_once(':') else {
        return headers.clone();
    };
    if user != alias_owner {
        return headers.clone();
    }
    let mut cloned = headers.clone();
    let replacement = format!("Basic {}", STANDARD.encode(format!("{target_owner}:{secret}")));
    if let Ok(value) = HeaderValue::from_str(&replacement) {
        cloned.insert(header::AUTHORIZATION, value);
    }
    cloned
}

async fn authorize_alias(
    state: &Arc<AppState>,
    method: &Method,
    headers: &HeaderMap,
    body: Option<Body>,
    parsed: &ParsedRepoPath<'_>,
    query: Option<&str>,
    target: &AliasTarget,
) -> Result<(), Error> {
    if let Some(pin) = parsed.ci_pin() {
        let rewritten = rewrite_ci_basic_owner(headers, parsed.owner, &target.owner);
        crate::ci_checkouts::authority::authenticate_principal(state, &rewritten, &target.owner, &target.name, pin)
            .await?;
        if target.is_deleted {
            return Err(Error::not_found());
        }
        return Ok(());
    }

    let actor = auth::authenticate(&state.pool, headers).await?;
    if target.is_deleted {
        return Err(Error::not_found());
    }
    let inspect = inspect_alias_request(method, parsed, body).await?;
    authorize_target_access(&state.pool, &actor, method, parsed, query, &inspect, target).await
}

async fn authorize_target_access(
    pool: &Pool,
    actor: &crate::db::Identity,
    method: &Method,
    parsed: &ParsedRepoPath<'_>,
    query: Option<&str>,
    inspect: &AliasRequestInspect,
    target: &AliasTarget,
) -> Result<(), Error> {
    if target.is_deleted {
        return Err(Error::not_found());
    }

    let (min_role, action) = surface_role_and_action(method, parsed, query, inspect)?;
    if parsed.kind == RepoRouteKind::Lfs && min_role >= Role::Write {
        auth::writable(actor)?;
    }
    let tail = parsed.tail();
    let is_lifecycle_endpoint = parsed.kind == RepoRouteKind::Api
        && ((*method == Method::DELETE && tail.is_empty())
            || matches!(tail, "/archive" | "/unarchive" | "/rename" | "/restore" | "/purge" | "/transfer"));
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = if is_lifecycle_endpoint {
        auth::authorize_repo_lifecycle(&tx, actor, &target.owner, &target.name, min_role, action, false).await?
    } else {
        auth::authorize_repo_with_role(&tx, actor, &target.owner, &target.name, min_role, action).await?
    };
    if access.repo_id != target.repository_id {
        return Err(Error::not_found());
    }
    auth::finish_tx(tx, actor, false).await
}

pub async fn middleware(State(state): State<Arc<AppState>>, request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let Some(parsed) = parse_repo_scoped_path(&path) else {
        return next.run(request).await;
    };
    if parsed.kind == RepoRouteKind::Web {
        // Web routes pass through `web::session::middleware` first (Origin/CSRF/navigation).
        return next.run(request).await;
    }
    let query = request.uri().query().map(str::to_owned);
    let target = match lookup_alias(&state.pool, parsed.owner, parsed.name).await {
        Ok(Some(target)) => target,
        Ok(None) => return next.run(request).await,
        Err(err) => return err.into_response(),
    };
    let (parts, body) = request.into_parts();
    let inspect_body = body_inspect_limit(&parts.method, &parsed).is_some().then_some(body);
    if let Err(err) =
        authorize_alias(&state, &parts.method, &parts.headers, inspect_body, &parsed, query.as_deref(), &target).await
    {
        return err.into_response();
    }
    match parsed
        .rewrite_to(query.as_deref(), &target.owner, &target.name)
        .and_then(|loc| permanent_redirect_response(&loc))
    {
        Ok(resp) => resp,
        Err(err) => err.into_response(),
    }
}

pub async fn web_middleware(State(state): State<MetadataState>, request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let Some(parsed) = parse_repo_scoped_path(&path) else {
        return next.run(request).await;
    };
    if parsed.kind != RepoRouteKind::Web {
        return next.run(request).await;
    }
    let query = request.uri().query().map(str::to_owned);
    let target = match lookup_alias(&state.pool, parsed.owner, parsed.name).await {
        Ok(Some(target)) => target,
        Ok(None) => return next.run(request).await,
        Err(err) => return err.into_response(),
    };
    let (parts, body) = request.into_parts();
    let inspect_body = body_inspect_limit(&parts.method, &parsed).is_some().then_some(body);
    if let Err(err) = authorize_web_alias(
        &state.pool,
        &parts.method,
        &parts.headers,
        inspect_body,
        &parsed,
        query.as_deref(),
        &target,
    )
    .await
    {
        return err.into_response();
    }
    match parsed
        .rewrite_to(query.as_deref(), &target.owner, &target.name)
        .and_then(|loc| permanent_redirect_response(&loc))
    {
        Ok(resp) => resp,
        Err(err) => err.into_response(),
    }
}

async fn authorize_web_alias(
    pool: &Pool,
    method: &Method,
    headers: &HeaderMap,
    body: Option<Body>,
    parsed: &ParsedRepoPath<'_>,
    query: Option<&str>,
    target: &AliasTarget,
) -> Result<(), Error> {
    let actor = web::handlers::authenticate_web(pool, headers).await?;
    if target.is_deleted {
        return Err(Error::not_found());
    }
    let inspect = inspect_alias_request(method, parsed, body).await?;
    authorize_target_access(pool, &actor, method, parsed, query, &inspect, target).await
}
