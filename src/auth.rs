pub use crate::members::models::{RepoAccess, Role};
use crate::{Error, db::Identity};
use axum::http::{HeaderMap, StatusCode, header};
use base64::Engine;
use deadpool_postgres::{Pool, Transaction};
use tokio_postgres::GenericClient;
use uuid::Uuid;

#[path = "auth/browser_parent.rs"]
mod browser_parent;
#[path = "auth/lifecycle.rs"]
pub(crate) mod lifecycle;

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
    browser_parent::authenticate_identity(pool, user, &token, browser_credentials_allowed()).await
}

fn credentials(headers: &HeaderMap) -> Result<(Option<String>, String), Error> {
    credentials_for(headers, "ryt_")
}

pub(crate) fn credentials_for(headers: &HeaderMap, prefix: &str) -> Result<(Option<String>, String), Error> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(Error::unauthorized());
    }
    let raw = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).ok_or_else(Error::unauthorized)?;
    if raw.len() > 512 {
        return Err(Error::unauthorized());
    }
    let (scheme, value) = raw.split_once(' ').ok_or_else(Error::unauthorized)?;
    let (user, token) = if scheme.eq_ignore_ascii_case("bearer") {
        (None, value.to_owned())
    } else if scheme.eq_ignore_ascii_case("basic") {
        let bytes = base64::engine::general_purpose::STANDARD.decode(value).map_err(|_| Error::unauthorized())?;
        let pair = String::from_utf8(bytes).map_err(|_| Error::unauthorized())?;
        let (user, token) = pair.split_once(':').ok_or_else(Error::unauthorized)?;
        (Some(user.to_owned()), token.to_owned())
    } else {
        return Err(Error::unauthorized());
    };
    if token.len() != 68 || !token.starts_with(prefix) || !token[4..].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::unauthorized());
    }
    Ok((user, token))
}

pub fn writable(identity: &Identity) -> Result<(), Error> {
    if identity.read_only { Err(Error(StatusCode::FORBIDDEN, "write permission required")) } else { Ok(()) }
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
        || !key.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
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
    lifecycle::authorize_repo_lifecycle_inner(tx, actor, owner, name, min_role, action, false, true).await
}

pub async fn authorize_repo_lifecycle(
    tx: &Transaction<'_>,
    actor: &Identity,
    owner: &str,
    name: &str,
    min_role: Role,
    action: crate::token_scopes::RepoAction,
    allow_deleted: bool,
) -> Result<RepoAccess, Error> {
    lifecycle::authorize_repo_lifecycle_inner(tx, actor, owner, name, min_role, action, allow_deleted, false).await
}

pub(super) async fn authorize_repo_scope(
    tx: &Transaction<'_>,
    actor: &Identity,
    repo_id: Uuid,
    action: crate::token_scopes::RepoAction,
) -> Result<(), Error> {
    let browser = browser_credentials_allowed();
    match actor.parent_token_id {
        Some(parent_id) => crate::token_scopes::authorize_repository_for_request_with_parent(
            tx,
            actor.token_id,
            actor.id,
            Some(parent_id),
            repo_id,
            action,
            browser,
        )
        .await
        .map_err(scope_error),
        None => crate::token_scopes::authorize_repository_for_request(
            tx,
            actor.token_id,
            actor.id,
            repo_id,
            action,
            browser,
        )
        .await
        .map_err(scope_error),
    }
}

fn scope_error(denial: crate::token_scopes::ScopeDenial) -> Error {
    match denial {
        crate::token_scopes::ScopeDenial::InvalidToken => Error::unauthorized(),
        crate::token_scopes::ScopeDenial::Forbidden => {
            Error(StatusCode::FORBIDDEN, "token scope does not permit this action")
        }
        crate::token_scopes::ScopeDenial::Unavailable => Error::internal("token scope store unavailable"),
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
    lifecycle::check_repo_availability_by_id(&**tx, repo_id, action.is_mutating()).await?;
    authorize_repo_scope(tx, actor, repo_id, action).await
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
    crate::token_scopes::authorize_namespace_for_request_with_parent(
        tx,
        actor.token_id,
        actor.id,
        actor.parent_token_id,
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
pub async fn reject_restricted_create(tx: &Transaction<'_>, actor: &Identity) -> Result<(), Error> {
    let restricted = token_is_restricted(tx, actor).await?;
    if restricted {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "restricted token has no scope for repository or organisation creation",
        ));
    }
    Ok(())
}

/// True when the acting token (or its bound browser parent) carries an explicit
/// restricted grant set.
pub async fn token_is_restricted(tx: &Transaction<'_>, actor: &Identity) -> Result<bool, Error> {
    browser_parent::token_is_restricted(tx, actor, browser_credentials_allowed()).await
}

pub async fn verify_token(tx: &Transaction<'_>, actor: &Identity, write: bool) -> Result<(), Error> {
    // A separate statement observes the real database clock *after* lock waits.
    let read_only = browser_parent::token_read_only(tx, actor, browser_credentials_allowed()).await?;
    if write && read_only {
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
    verify_active_inner(pool, actor, repo_id, None, action, min_role).await
}

pub async fn verify_active_transfer(
    pool: &Pool,
    actor: &Identity,
    repo_id: Uuid,
    expected_generation: i64,
    action: crate::token_scopes::RepoAction,
    min_role: Role,
) -> Result<(), Error> {
    verify_active_inner(pool, actor, repo_id, Some(expected_generation), action, min_role).await
}

async fn verify_active_inner(
    pool: &Pool,
    actor: &Identity,
    repo_id: Uuid,
    expected_generation: Option<i64>,
    action: crate::token_scopes::RepoAction,
    min_role: Role,
) -> Result<(), Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    verify_token(&tx, actor, action.is_mutating()).await?;
    let row = tx
        .query_opt(
            "SELECT owner_id, state, storage_generation, deleted_at IS NOT NULL AS deleted, \
                    archived_at IS NOT NULL AS archived, transition_state FROM repositories WHERE id=$1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let owner_id: Uuid = row.get("owner_id");
    let state: String = row.get("state");
    let storage_generation: i64 = row.get("storage_generation");
    let deleted: bool = row.get("deleted");
    let archived: bool = row.get("archived");
    let transition_state: String = row.get("transition_state");
    if deleted {
        return Err(Error::not_found());
    }
    if state != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }
    if expected_generation.is_some_and(|expected| expected != storage_generation) {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    let Some((eff, _, _)) = crate::members::rbac::resolve_effective_role(&*tx, repo_id, owner_id, actor.id).await?
    else {
        return Err(Error::not_found());
    };
    if eff < min_role {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient repository role"));
    }
    lifecycle::enforce_availability(&*tx, repo_id, deleted, archived, &transition_state, action.is_mutating()).await?;
    authorize_repo_scope(&tx, actor, repo_id, action).await?;
    Ok(())
}

pub async fn finish_tx(tx: Transaction<'_>, actor: &Identity, write: bool) -> Result<(), Error> {
    // Allocation/row waits must not turn an expired token into a successful write.
    verify_token(&tx, actor, write).await?;
    tx.commit().await.map_err(Error::internal)
}

/// Re-verify the exact token, repository generation/state and effective write
/// role for an already authenticated identity. Direct API callers pass
/// `parent_token_id = None` via [`verify_repo_write_access`]; browser-bound
/// callers pass `actor.parent_token_id` via [`verify_repo_write_access_with_parent`].
pub async fn verify_repo_write_access<C: GenericClient + Sync>(
    client: &C,
    actor_id: Uuid,
    token_id: Uuid,
    repo_id: Uuid,
    browser: bool,
    action: crate::token_scopes::RepoAction,
) -> Result<(), Error> {
    verify_repo_write_access_with_parent(client, actor_id, token_id, None, repo_id, browser, action).await
}

/// Parent-aware variant of [`verify_repo_write_access`].
pub async fn verify_repo_write_access_with_parent<C: GenericClient + Sync>(
    client: &C,
    actor_id: Uuid,
    token_id: Uuid,
    parent_token_id: Option<Uuid>,
    repo_id: Uuid,
    browser: bool,
    action: crate::token_scopes::RepoAction,
) -> Result<(), Error> {
    let read_only =
        browser_parent::write_token_read_only(client, actor_id, token_id, parent_token_id, browser).await?;
    if action.is_mutating() && read_only {
        return Err(Error(StatusCode::FORBIDDEN, "write permission required"));
    }
    let repo = client
        .query_opt(
            "SELECT owner_id, state, deleted_at IS NOT NULL, archived_at IS NOT NULL, transition_state \
             FROM repositories WHERE id=$1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let owner_id: Uuid = repo.get(0);
    if repo.get::<_, bool>(2) {
        return Err(Error::not_found());
    }
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
    lifecycle::enforce_availability(client, repo_id, false, repo.get(3), repo.get::<_, &str>(4), action.is_mutating())
        .await?;
    crate::token_scopes::authorize_repository_late_with_parent(
        client,
        token_id,
        actor_id,
        parent_token_id,
        repo_id,
        action,
        browser,
    )
    .await
    .map_err(scope_error)?;
    Ok(())
}

/// Late Git publication authorization on the publication owner's own
/// PostgreSQL transaction.
///
/// The coordinator derives `actor` from the request it already authenticated
/// and from the admitted operation; a native hook can never supply an identity,
/// action or digest here.
///
/// Lock order is exact ref -> repository advisory -> local writer -> token
/// `FOR SHARE` -> native CAS. When this authorisation takes the `FOR SHARE`
/// lock before a revocation/narrowing writer arrives, that `FOR UPDATE` writer
/// waits until the native CAS, journal settlement and guard drop finish. When
/// the revoker commits first, the second statement below re-reads the live row
/// with the real database clock after the lock wait and denies the
/// authorisation, so no grant marker is written and the push is refused.
/// Repository, role and live-grant checks run after that lock under the same
/// real-clock re-read.
pub async fn authorize_publication_window(
    tx: &Transaction<'_>,
    actor: &Identity,
    repository_id: Uuid,
    storage_generation: i64,
) -> Result<(), Error> {
    let browser = browser_credentials_allowed();
    // Step 1: take the token row lock (plus parent row lock when browser-bound).
    browser_parent::lock_publication_tokens(tx, actor, browser).await?;
    // Step 2: re-read the live row(s) after the lock wait with clock_timestamp().
    let (read_only, unexpired, live_session) =
        browser_parent::recheck_publication_tokens(tx, actor, browser).await?;
    if !unexpired || !live_session {
        return Err(Error::unauthorized());
    }
    if read_only {
        return Err(Error(StatusCode::FORBIDDEN, "write permission required"));
    }
    // Step 3: current repository generation/state and effective write role,
    // read under the same transaction that now owns the token lock.
    let repo = tx
        .query_opt(
            "SELECT owner_id, state, storage_generation, deleted_at IS NOT NULL, archived_at IS NOT NULL, transition_state \
             FROM repositories WHERE id=$1",
            &[&repository_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if repo.get::<_, bool>(3) {
        return Err(Error::not_found());
    }
    if repo.get::<_, i64>(2) != storage_generation {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed before ref publication"));
    }
    if repo.get::<_, String>(1) != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }
    let owner_id: Uuid = repo.get(0);
    let Some((effective, _, _)) =
        crate::members::rbac::resolve_effective_role(&**tx, repository_id, owner_id, actor.id).await?
    else {
        return Err(Error::not_found());
    };
    if effective < Role::Write {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient repository role"));
    }
    lifecycle::enforce_availability(&**tx, repository_id, false, repo.get(4), repo.get::<_, &str>(5), true).await?;
    // Step 4: the fixed action is ContentsWrite; the token can only narrow.
    crate::token_scopes::authorize_repository_late_with_parent(
        &**tx,
        actor.token_id,
        actor.id,
        actor.parent_token_id,
        repository_id,
        crate::token_scopes::RepoAction::ContentsWrite,
        browser,
    )
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
