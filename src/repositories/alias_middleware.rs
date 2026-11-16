//! Authz-before-redirect HTTP middleware resolving `repository_aliases` across Git,
//! CI-pinned Git, LFS, REST API, and Web UI surfaces with `308 Permanent Redirect`.
use super::alias::{ParsedRepoPath, RepoRouteKind, parse_repo_scoped_path, permanent_redirect_response};
use crate::{AppState, Error, application::MetadataState, auth, members::models::Role, token_scopes::RepoAction, web};
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

fn query_has_service_receive_pack(query: Option<&str>) -> bool {
    query.is_some_and(|raw| {
        raw.split('&').any(|pair| pair.split_once('=').is_some_and(|(k, v)| k == "service" && v == "git-receive-pack"))
    })
}

fn surface_role_and_action(method: &Method, parsed: &ParsedRepoPath<'_>, query: Option<&str>) -> (Role, RepoAction) {
    let tail = parsed.tail();
    let is_mutation = matches!(*method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE);
    match parsed.kind {
        RepoRouteKind::Git => {
            if (*method == Method::POST && tail == "/git-receive-pack")
                || (*method == Method::GET && tail == "/info/refs" && query_has_service_receive_pack(query))
            {
                (Role::Write, RepoAction::ContentsWrite)
            } else {
                (Role::Read, RepoAction::ContentsRead)
            }
        }
        RepoRouteKind::Lfs => {
            if is_mutation
                && (tail.starts_with("/info/lfs/locks") || tail.starts_with("/info/lfs/objects/"))
                && !tail.starts_with("/info/lfs/objects/batch")
            {
                (Role::Write, RepoAction::ContentsWrite)
            } else {
                (Role::Read, RepoAction::ContentsRead)
            }
        }
        RepoRouteKind::Web => (Role::Read, RepoAction::RepoRead),
        RepoRouteKind::PinnedCiGit => (Role::Read, RepoAction::ContentsRead),
        RepoRouteKind::Api => api_role_and_action(method, is_mutation, tail),
    }
}

fn api_role_and_action(method: &Method, is_mutation: bool, tail: &str) -> (Role, RepoAction) {
    if !is_mutation {
        let action = if tail.starts_with("/issues") {
            RepoAction::IssuesRead
        } else if tail.starts_with("/pulls") {
            RepoAction::PullsRead
        } else if tail.starts_with("/checks") || tail.starts_with("/check-runs") {
            RepoAction::ChecksRead
        } else if tail.starts_with("/webhooks") || tail.starts_with("/hooks") {
            RepoAction::HooksRead
        } else if tail.starts_with("/collaborators") || tail.starts_with("/teams") || tail.starts_with("/audit") {
            RepoAction::MembersRead
        } else if tail.starts_with("/workspaces") {
            RepoAction::WorkspacesRead
        } else if tail.starts_with("/tree")
            || tail.starts_with("/blob")
            || tail.starts_with("/commits")
            || tail.starts_with("/branches")
            || tail.starts_with("/tags")
            || tail.starts_with("/compare")
            || tail.starts_with("/archive")
        {
            RepoAction::ContentsRead
        } else {
            RepoAction::RepoRead
        };
        return (Role::Read, action);
    }

    if (*method == Method::DELETE && tail.is_empty())
        || matches!(tail, "/archive" | "/unarchive" | "/rename" | "/restore" | "/purge" | "/transfer")
        || tail.starts_with("/aliases")
        || tail.starts_with("/storage-backend")
    {
        return (Role::Admin, RepoAction::RepoAdmin);
    }
    if tail.starts_with("/issues") {
        (Role::Triage, RepoAction::IssuesWrite)
    } else if tail.starts_with("/pulls") {
        (Role::Write, RepoAction::PullsWrite)
    } else if tail.starts_with("/checks") || tail.starts_with("/check-runs") {
        (Role::Write, RepoAction::ChecksWrite)
    } else if tail.starts_with("/webhooks") || tail.starts_with("/hooks") {
        (Role::Write, RepoAction::HooksAdmin)
    } else if tail.starts_with("/collaborators") || tail.starts_with("/teams") {
        (Role::Admin, RepoAction::MembersAdmin)
    } else if tail.starts_with("/workspaces") {
        (Role::Write, RepoAction::WorkspacesWrite)
    } else if tail.starts_with("/commits") || tail.starts_with("/branches") || tail.starts_with("/files") {
        (Role::Write, RepoAction::ContentsWrite)
    } else {
        (Role::Admin, RepoAction::RepoAdmin)
    }
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
    authorize_target_access(&state.pool, &actor, method, parsed, query, target).await
}

async fn authorize_target_access(
    pool: &Pool,
    actor: &crate::db::Identity,
    method: &Method,
    parsed: &ParsedRepoPath<'_>,
    query: Option<&str>,
    target: &AliasTarget,
) -> Result<(), Error> {
    if target.is_deleted {
        return Err(Error::not_found());
    }

    let (min_role, action) = surface_role_and_action(method, parsed, query);
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, actor, &target.owner, &target.name, min_role, action).await?;
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
    if let Err(err) =
        authorize_alias(&state, request.method(), request.headers(), &parsed, query.as_deref(), &target).await
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
    if let Err(err) =
        authorize_web_alias(&state.pool, request.method(), request.headers(), &parsed, query.as_deref(), &target).await
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
    parsed: &ParsedRepoPath<'_>,
    query: Option<&str>,
    target: &AliasTarget,
) -> Result<(), Error> {
    let actor = web::handlers::authenticate_web(pool, headers).await?;
    authorize_target_access(pool, &actor, method, parsed, query, target).await
}
