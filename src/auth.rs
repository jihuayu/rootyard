pub use crate::members::models::{RepoAccess, Role};
use crate::{
    Error,
    db::{self, Identity},
};
use axum::http::{HeaderMap, StatusCode, header};
use base64::Engine;
use deadpool_postgres::{Pool, Transaction};
use tokio_postgres::GenericClient;
use uuid::Uuid;

tokio::task_local! { static WEB_AUTH_SCOPE: bool; }
pub async fn web_scope<F: std::future::Future>(future: F) -> F::Output {
    WEB_AUTH_SCOPE.scope(true, future).await
}
fn browser_credentials_allowed() -> bool {
    WEB_AUTH_SCOPE.try_with(|allowed| *allowed).unwrap_or(false)
}
pub fn web_scope_enabled() -> bool {
    browser_credentials_allowed()
}
pub async fn inherit_web_scope<F: std::future::Future>(enabled: bool, future: F) -> F::Output {
    WEB_AUTH_SCOPE.scope(enabled, future).await
}

pub async fn authenticate(pool: &Pool, headers: &HeaderMap) -> Result<Identity, Error> {
    let (user, token) = credentials(headers)?;
    let client = pool.get().await.map_err(Error::internal)?;
    let row = client.query_opt(
        "SELECT u.id, u.username, t.read_only, t.id FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.digest=$1 AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) AND (t.kind='api' OR ($2 AND t.kind='browser' AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id=t.id AND NOT s.revoked AND s.expires_at>clock_timestamp())))", &[&db::digest(&token), &browser_credentials_allowed()])
        .await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    let identity = Identity {
        id: row.get(0),
        username: row.get(1),
        read_only: row.get(2),
        token_id: row.get(3),
        token_digest: db::digest(&token),
    };
    if user.as_ref().is_some_and(|u| u != &identity.username) {
        return Err(Error::unauthorized());
    }
    Ok(identity)
}

fn credentials(headers: &HeaderMap) -> Result<(Option<String>, String), Error> {
    credentials_for(headers, "ryt_")
}

pub(crate) fn credentials_for(
    headers: &HeaderMap,
    prefix: &str,
) -> Result<(Option<String>, String), Error> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(Error::unauthorized());
    }
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(Error::unauthorized)?;
    if raw.len() > 512 {
        return Err(Error::unauthorized());
    }
    let (scheme, value) = raw.split_once(' ').ok_or_else(Error::unauthorized)?;
    let (user, token) = if scheme.eq_ignore_ascii_case("bearer") {
        (None, value.to_owned())
    } else if scheme.eq_ignore_ascii_case("basic") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| Error::unauthorized())?;
        let pair = String::from_utf8(bytes).map_err(|_| Error::unauthorized())?;
        let (user, token) = pair.split_once(':').ok_or_else(Error::unauthorized)?;
        (Some(user.to_owned()), token.to_owned())
    } else {
        return Err(Error::unauthorized());
    };
    if token.len() != 68
        || !token.starts_with(prefix)
        || !token[4..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::unauthorized());
    }
    Ok((user, token))
}

pub fn writable(identity: &Identity) -> Result<(), Error> {
    if identity.read_only {
        Err(Error(StatusCode::FORBIDDEN, "write permission required"))
    } else {
        Ok(())
    }
}

// Keys are opaque client operation identifiers, never authentication credentials.
// A repository-local namespace also prevents a key from silently changing targets.
pub fn idempotency_key(headers: &HeaderMap) -> Result<Option<&str>, Error> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::bad_request());
    }
    let key = value.to_str().map_err(|_| Error::bad_request())?;
    if !(1..=128).contains(&key.len())
        || !key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
    {
        return Err(Error::bad_request());
    }
    Ok(Some(key))
}

pub async fn authorize_repo_with_role(
    tx: &Transaction<'_>,
    actor: &Identity,
    owner: &str,
    name: &str,
    min_role: Role,
    action: crate::token_scopes::RepoAction,
) -> Result<RepoAccess, Error> {
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    // Keep lock order token/user -> repository -> creation key -> counter/issue/comment.
    // Revoke and read_only updates must wait for these transaction-scoped locks.
    tx.query_opt(
        "SELECT t.id FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.id=$1 AND t.user_id=$2 AND u.username=$3 FOR SHARE OF t,u",
        &[&actor.token_id, &actor.id, &actor.username],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::unauthorized)?;
    // read_only follows the resolved action, never the route's minimum role:
    // an admin may legitimately perform a read with a read-only token.
    verify_token(tx, actor, action.is_mutating()).await?;

    let row = tx
        .query_opt(
            "SELECT r.id, r.owner_id, r.state FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id WHERE ns.slug = $1 AND r.name = $2 FOR SHARE OF r",
            &[&owner, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let repo_id: Uuid = row.get("id");
    let owner_id: Uuid = row.get("owner_id");
    let state: String = row.get("state");

    let Some((effective_role, _, _)) =
        crate::members::rbac::resolve_effective_role(&**tx, repo_id, owner_id, actor.id).await?
    else {
        return Err(Error::not_found());
    };

    if effective_role < min_role {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient repository role"));
    }
    if state != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }
    // Scopes only narrow the RBAC result above and are read in the same
    // transaction, so a token narrowing cannot race this authorisation.
    crate::token_scopes::authorize_repository_for_request(
        &**tx,
        actor.token_id,
        actor.id,
        repo_id,
        action,
        browser_credentials_allowed(),
    )
    .await
    .map_err(scope_error)?;
    Ok(RepoAccess {
        repo_id,
        owner_id,
        role: effective_role,
    })
}

fn scope_error(denial: crate::token_scopes::ScopeDenial) -> Error {
    match denial {
        crate::token_scopes::ScopeDenial::InvalidToken => Error::unauthorized(),
        crate::token_scopes::ScopeDenial::Forbidden => {
            Error(StatusCode::FORBIDDEN, "token scope does not permit this action")
        }
        crate::token_scopes::ScopeDenial::Unavailable => {
            Error::internal("token scope store unavailable")
        }
    }
}

/// Apply the token scope gate to an already-resolved repository.
///
/// Used by the personal-owner metadata fast path in `repositories::get_repo`,
/// which bypasses the member-role lookup but must not bypass a restricted
/// token's exact repository grants.
pub async fn authorize_repo_action_by_id(
    tx: &Transaction<'_>,
    actor: &Identity,
    repo_id: Uuid,
    action: crate::token_scopes::RepoAction,
) -> Result<(), Error> {
    verify_token(tx, actor, action.is_mutating()).await?;
    crate::token_scopes::authorize_repository_for_request(
        &**tx,
        actor.token_id,
        actor.id,
        repo_id,
        action,
        browser_credentials_allowed(),
    )
    .await
    .map_err(scope_error)
}

/// Enforce one organisation namespace action. The organisation role check stays
/// with the caller: scopes can only narrow membership, never replace it.
pub async fn authorize_namespace_action(
    tx: &Transaction<'_>,
    actor: &Identity,
    organization_id: Uuid,
    action: crate::token_scopes::NamespaceAction,
) -> Result<(), Error> {
    verify_token(tx, actor, action.is_mutating()).await?;
    crate::token_scopes::authorize_namespace_for_request(
        &**tx,
        actor.token_id,
        actor.id,
        organization_id,
        action,
        browser_credentials_allowed(),
    )
    .await
    .map_err(scope_error)
}

/// Refuse repository/organisation creation for restricted tokens until an
/// explicit create scope exists. Legacy unrestricted tokens keep their
/// historical behaviour; no other repository grant is treated as create.
pub async fn reject_restricted_create(
    tx: &Transaction<'_>,
    actor: &Identity,
) -> Result<(), Error> {
    let restricted = token_is_restricted(tx, actor).await?;
    if restricted {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "restricted token has no scope for repository or organisation creation",
        ));
    }
    Ok(())
}

/// True when the acting token carries an explicit restricted grant set.
pub async fn token_is_restricted(tx: &Transaction<'_>, actor: &Identity) -> Result<bool, Error> {
    let row = tx
        .query_opt(
            "SELECT t.is_restricted FROM tokens t WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 \
             AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
             AND (t.kind='api' OR ($4 AND t.kind='browser' AND t.is_restricted = false AND EXISTS \
                 (SELECT 1 FROM web_sessions s WHERE s.token_id=t.id AND NOT s.revoked AND s.expires_at>clock_timestamp()))) FOR SHARE OF t",
            &[&actor.token_id, &actor.id, &actor.token_digest, &browser_credentials_allowed()],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    Ok(row.get(0))
}

pub async fn verify_token(
    tx: &Transaction<'_>,
    actor: &Identity,
    write: bool,
) -> Result<(), Error> {
    // A separate statement observes the real database clock *after* lock waits.
    let row = tx.query_opt(
        "SELECT t.read_only FROM tokens t WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) AND (t.kind='api' OR ($4 AND t.kind='browser' AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id=t.id AND NOT s.revoked AND s.expires_at>clock_timestamp())))",
        &[&actor.token_id, &actor.id, &actor.token_digest, &browser_credentials_allowed()],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::unauthorized)?;
    if write && row.get::<_, bool>(0) {
        return Err(Error(StatusCode::FORBIDDEN, "write permission required"));
    }
    Ok(())
}

pub async fn verify_active(
    pool: &Pool,
    actor: &Identity,
    repo_id: Uuid,
    action: crate::token_scopes::RepoAction,
    min_role: Role,
) -> Result<(), Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    verify_token(&tx, actor, action.is_mutating()).await?;
    let row = tx
        .query_opt(
            "SELECT owner_id, state FROM repositories WHERE id=$1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let owner_id: Uuid = row.get("owner_id");
    let state: String = row.get("state");
    if state != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }
    let Some((eff, _, _)) =
        crate::members::rbac::resolve_effective_role(&*tx, repo_id, owner_id, actor.id).await?
    else {
        return Err(Error::not_found());
    };
    if eff < min_role {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient repository role"));
    }
    crate::token_scopes::authorize_repository_for_request(
        &tx,
        actor.token_id,
        actor.id,
        repo_id,
        action,
        browser_credentials_allowed(),
    )
    .await
    .map_err(scope_error)?;
    Ok(())
}

pub async fn finish_tx(tx: Transaction<'_>, actor: &Identity, write: bool) -> Result<(), Error> {
    // Allocation/row waits must not turn an expired token into a successful write.
    verify_token(&tx, actor, write).await?;
    tx.commit().await.map_err(Error::internal)
}


/// Re-verify the exact token, repository generation/state and effective write
/// role for an already authenticated identity. Native receive hooks and the
/// server-side exact-ref CAS transaction call this immediately before their SQL
/// commit so a revocation during a long transfer cannot publish refs.
pub async fn verify_repo_write_access<C: GenericClient + Sync>(
    client: &C,
    actor_id: Uuid,
    token_id: Uuid,
    repo_id: Uuid,
    browser: bool,
    action: crate::token_scopes::RepoAction,
) -> Result<(), Error> {
    let token = client
        .query_opt(
            "SELECT t.read_only FROM tokens t WHERE t.id=$1 AND t.user_id=$2 \
             AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
             AND (t.kind='api' OR ($3 AND t.kind='browser' AND EXISTS \
                 (SELECT 1 FROM web_sessions s WHERE s.token_id=t.id AND NOT s.revoked \
                  AND s.expires_at>clock_timestamp())))",
            &[&token_id, &actor_id, &browser],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    if action.is_mutating() && token.get::<_, bool>(0) {
        return Err(Error(StatusCode::FORBIDDEN, "write permission required"));
    }
    let repo = client
        .query_opt(
            "SELECT owner_id,state FROM repositories WHERE id=$1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let owner_id: Uuid = repo.get(0);
    if repo.get::<_, String>(1) != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }
    let Some((effective, _, _)) =
        crate::members::rbac::resolve_effective_role(client, repo_id, owner_id, actor_id).await?
    else {
        return Err(Error::not_found());
    };
    if effective < Role::Write {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient repository role"));
    }
    // Late, non-locking scope check. A bare `GenericClient` cannot keep the
    // token row `FOR SHARE` until publication, so this only closes the window
    // at the moment of this statement; the fixed publication lock is tracked
    // as remaining Git work and is not claimed here.
    crate::token_scopes::authorize_repository_late(client, token_id, actor_id, repo_id, action, browser)
        .await
        .map_err(scope_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_malformed() {
        for value in ["", "Bearer ", "Basic ###", "Basic YTpi", "Token abc"] {
            let mut h = HeaderMap::new();
            h.insert(header::AUTHORIZATION, value.parse().unwrap());
            assert!(credentials(&h).is_err());
        }
    }
}
