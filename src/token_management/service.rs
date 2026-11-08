//! Shared token/session management service.
//!
//! One implementation backs both the JSON API (`auth::authenticate`, i.e.
//! Authorization only) and the browser UI (`web::authenticate_web` after the
//! cookie/Origin/CSRF middleware). The service receives an already
//! authenticated [`Identity`] and never inspects transport-specific headers, so
//! an API request cannot claim browser authority with a marker header.
//!
//! # Lock protocol
//!
//! Every management transaction first takes a per-user advisory transaction
//! lock, then re-verifies the acting token `FOR SHARE` (active, not restricted,
//! and writable for mutations), then locks the target token `FOR UPDATE` with a
//! `user_id` predicate. Serialising all management for one user before touching
//! the token row prevents two same-user requests from taking reciprocal
//! SHARE -> UPDATE upgrades and deadlocking. The pool's `lock_timeout` keeps a
//! concurrent publisher/reader from holding a request forever.
//!
//! # Semantics
//!
//! * Only `kind = 'api'` tokens owned by the actor are manageable. Browser
//!   children, CI and trusted-integration credentials are never addressable as
//!   API tokens.
//! * New tokens are always `is_restricted = true`. An empty grant set is an
//!   explicit deny-all; it is never "all".
//! * A restricted token can only be narrowed. `is_restricted` never goes from
//!   `true` to `false`.
//! * Rotation mints a fresh 256-bit secret (only its digest is stored), copies
//!   the still-authorised scopes/read-only/expiry/name, revokes the old row in
//!   the same transaction and returns the secret once. Rotating an already
//!   rotated/revoked token is a deterministic 409; no plaintext replay store
//!   exists.
//! * Revocation is idempotent (204) for the owner and always 404 across users.
//!   Session revocation uses `UPDATE ... SET revoked = true` and never deletes
//!   audit/GC references.

use super::cursors::{decode as decode_cursor, encode as cursor};
use crate::{
    Error, auth,
    db::{self, Identity},
    token_management::{
        grants::{insert_grants, load_grants, replace_grants, validate_namespace_grant, validate_repository_grant},
        models::{self, *},
    },
};
use axum::http::StatusCode;
use deadpool_postgres::{Pool, Transaction};
use rand::RngCore;
use std::collections::{BTreeMap, BTreeSet};
use tokio_postgres::Row;
use uuid::Uuid;

/// Seed for the management advisory lock, distinct from member policy locks.
const MANAGEMENT_LOCK_SEED: i64 = 7331;

const TOKEN_FIELDS: &str = "t.id, t.display_name, t.read_only, t.is_restricted, t.scope_version, \
     to_char(t.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS expires_at, \
     to_char(t.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at, \
     t.created_at AS cursor_ts";

fn conflict(message: &'static str) -> Error {
    Error(StatusCode::CONFLICT, message)
}

/// Mint a new opaque credential. Only the SHA-256 digest reaches PostgreSQL.
fn new_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("ryt_{}", hex::encode(bytes))
}

/// Serialise all management work for one user before any token row lock.
async fn lock_user(tx: &Transaction<'_>, actor: &Identity) -> Result<(), Error> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::text, $2))",
        &[&actor.id.to_string(), &MANAGEMENT_LOCK_SEED],
    )
    .await
    .map_err(Error::internal)?;
    Ok(())
}

/// Re-verify the acting token after the advisory lock. This observes the real
/// database clock and the current `read_only`/`is_restricted` values, so a role
/// or token change that happened while waiting is seen by this request.
async fn verify_issuer(tx: &Transaction<'_>, actor: &Identity, mutation: bool) -> Result<(), Error> {
    let allow_browser = auth::web_scope_enabled();
    let row = tx
        .query_opt(
            "SELECT t.read_only, t.is_restricted FROM tokens t \
              WHERE t.id = $1 AND t.user_id = $2 AND t.digest = $3 AND NOT t.revoked \
                AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                AND (t.kind = 'api' OR ($4 AND t.kind = 'browser' AND t.is_restricted = false \
                     AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id = t.id \
                                  AND NOT s.revoked AND s.expires_at > clock_timestamp()))) \
              FOR SHARE OF t",
            &[&actor.token_id, &actor.id, &actor.token_digest, &allow_browser],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    let read_only: bool = row.get(0);
    let restricted: bool = row.get(1);
    if restricted {
        return Err(Error(StatusCode::FORBIDDEN, "restricted tokens cannot manage tokens or sessions"));
    }
    if mutation && read_only {
        return Err(Error(StatusCode::FORBIDDEN, "write permission required"));
    }
    Ok(())
}

async fn begin(tx: &Transaction<'_>, actor: &Identity, mutation: bool) -> Result<(), Error> {
    lock_user(tx, actor).await?;
    verify_issuer(tx, actor, mutation).await
}

// ---------------------------------------------------------------------------
// Read views
// ---------------------------------------------------------------------------

/// Load name-bearing grant metadata for a bounded page of tokens in two
/// statements (no per-row queries, no unbounded scan).
async fn token_views(tx: &Transaction<'_>, rows: &[Row]) -> Result<Vec<TokenView>, Error> {
    let ids: Vec<Uuid> = rows.iter().map(|row| row.get("id")).collect();
    let mut repositories: BTreeMap<Uuid, BTreeMap<Uuid, (String, String, BTreeSet<String>)>> = BTreeMap::new();
    let repo_rows = tx
        .query(
            "SELECT ts.token_id, ts.repository_id, ns.slug, r.name, ts.action \
               FROM token_repository_scopes ts \
               JOIN repositories r ON r.id = ts.repository_id \
               JOIN namespaces ns ON ns.id = r.owner_id \
              WHERE ts.token_id = ANY($1::uuid[]) \
              ORDER BY ns.slug, r.name, ts.action",
            &[&ids],
        )
        .await
        .map_err(Error::internal)?;
    for row in repo_rows {
        let token_id: Uuid = row.get(0);
        let repository_id: Uuid = row.get(1);
        let owner: String = row.get(2);
        let name: String = row.get(3);
        let action: String = row.get(4);
        repositories
            .entry(token_id)
            .or_default()
            .entry(repository_id)
            .or_insert_with(|| (owner, name, BTreeSet::new()))
            .2
            .insert(action);
    }
    let mut namespaces: BTreeMap<Uuid, BTreeMap<Uuid, (String, BTreeSet<String>)>> = BTreeMap::new();
    let namespace_rows = tx
        .query(
            "SELECT ts.token_id, ts.organization_id, o.slug, ts.action \
               FROM token_namespace_scopes ts \
               JOIN organizations o ON o.id = ts.organization_id \
              WHERE ts.token_id = ANY($1::uuid[]) \
              ORDER BY o.slug, ts.action",
            &[&ids],
        )
        .await
        .map_err(Error::internal)?;
    for row in namespace_rows {
        let token_id: Uuid = row.get(0);
        let organization_id: Uuid = row.get(1);
        let slug: String = row.get(2);
        let action: String = row.get(3);
        namespaces
            .entry(token_id)
            .or_default()
            .entry(organization_id)
            .or_insert_with(|| (slug, BTreeSet::new()))
            .1
            .insert(action);
    }

    let mut views = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row.get("id");
        let mut repository_grants = Vec::new();
        for (repository_id, (owner, name, actions)) in repositories.remove(&id).unwrap_or_default() {
            repository_grants.push(RepositoryGrantView {
                repository_id,
                owner,
                name,
                actions: actions.into_iter().collect(),
            });
        }
        let mut namespace_grants = Vec::new();
        for (organization_id, (slug, actions)) in namespaces.remove(&id).unwrap_or_default() {
            namespace_grants.push(NamespaceGrantView { organization_id, slug, actions: actions.into_iter().collect() });
        }
        views.push(TokenView {
            id,
            display_name: row.get("display_name"),
            read_only: row.get("read_only"),
            is_restricted: row.get("is_restricted"),
            scope_version: row.get("scope_version"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
            repository_grants,
            namespace_grants,
        });
    }
    Ok(views)
}

async fn load_token_view(tx: &Transaction<'_>, token_id: Uuid) -> Result<TokenView, Error> {
    let row = tx
        .query_one(&format!("SELECT {TOKEN_FIELDS} FROM tokens t WHERE t.id = $1"), &[&token_id])
        .await
        .map_err(Error::internal)?;
    Ok(token_views(tx, &[row]).await?.pop().expect("one view"))
}

// ---------------------------------------------------------------------------
// Public service surface
// ---------------------------------------------------------------------------

/// List the actor's own API tokens. Keyset-bounded by actor and kind; revoked
/// tokens are excluded.
pub async fn list_tokens(pool: &Pool, actor: &Identity, after: Option<String>, limit: i64) -> Result<TokenPage, Error> {
    let scope = format!("tokens:api:{}", actor.id);
    let (after_ts, after_id) = decode_cursor(after.as_ref(), &scope)?;
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    begin(&tx, actor, false).await?;
    let rows = match (&after_ts, &after_id) {
        (Some(after_ts), Some(after_id)) => tx
            .query(
                &format!(
                    "SELECT {TOKEN_FIELDS} FROM tokens t \
                      WHERE t.user_id = $1 AND t.kind = 'api' AND NOT t.revoked \
                        AND (t.created_at, t.id) > ($2::timestamptz, $3::uuid) \
                      ORDER BY t.created_at, t.id LIMIT $4"
                ),
                &[&actor.id, after_ts, after_id, &(limit + 1)],
            )
            .await
            .map_err(Error::internal)?,
        _ => tx
            .query(
                &format!(
                    "SELECT {TOKEN_FIELDS} FROM tokens t \
                      WHERE t.user_id = $1 AND t.kind = 'api' AND NOT t.revoked \
                      ORDER BY t.created_at, t.id LIMIT $2"
                ),
                &[&actor.id, &(limit + 1)],
            )
            .await
            .map_err(Error::internal)?,
    };
    let more = rows.len() as i64 > limit;
    let rows = &rows[..rows.len().min(limit as usize)];
    let next_after = if more { rows.last().map(|row| cursor(&scope, row)).transpose()? } else { None };
    let items = token_views(&tx, rows).await?;
    auth::finish_tx(tx, actor, false).await?;
    Ok(TokenPage { items, next_after })
}

pub async fn get_token(pool: &Pool, actor: &Identity, token_id: Uuid) -> Result<TokenView, Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    begin(&tx, actor, false).await?;
    let row = tx
        .query_opt(
            &format!(
                "SELECT {TOKEN_FIELDS} FROM tokens t \
                  WHERE t.id = $1 AND t.user_id = $2 AND t.kind = 'api'"
            ),
            &[&token_id, &actor.id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let view = token_views(&tx, &[row]).await?.pop().expect("one view");
    auth::finish_tx(tx, actor, false).await?;
    Ok(view)
}

/// Create an explicitly restricted token. The secret is returned once.
pub async fn create_token(pool: &Pool, actor: &Identity, input: CreateTokenInput) -> Result<IssuedToken, Error> {
    let display_name = models::validate_display_name(&input.display_name)?;
    let days = i32::try_from(models::validate_expiry_days(input.expires_in_days)?).map_err(|_| Error::bad_request())?;
    let repositories = models::normalize_repository_grants(input.repository_grants)?;
    let namespaces = models::normalize_namespace_grants(input.namespace_grants)?;
    models::validate_grant_count(&repositories, &namespaces)?;

    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    begin(&tx, actor, true).await?;
    for (repository_id, actions) in &repositories {
        validate_repository_grant(&tx, actor, *repository_id, actions).await?;
    }
    for (organization_id, actions) in &namespaces {
        validate_namespace_grant(&tx, actor, *organization_id, actions).await?;
    }
    let token_id = Uuid::new_v4();
    let secret = new_secret();
    tx.execute(
        "INSERT INTO tokens(id, user_id, digest, read_only, expires_at, kind, is_restricted, scope_version, display_name) \
         VALUES ($1, $2, $3, $4, clock_timestamp() + make_interval(days => $5::int), 'api', true, 1, $6)",
        &[&token_id, &actor.id, &db::digest(&secret), &input.read_only, &days, &display_name],
    )
    .await
    .map_err(Error::internal)?;
    insert_grants(&tx, token_id, &repositories, &namespaces).await?;
    let view = load_token_view(&tx, token_id).await?;
    auth::finish_tx(tx, actor, true).await?;
    Ok(IssuedToken { token: view, secret })
}

/// Replace the complete grant set (narrowing only) and optionally the display
/// name under an optimistic `scope_version` check.
pub async fn update_token(
    pool: &Pool,
    actor: &Identity,
    token_id: Uuid,
    input: UpdateTokenInput,
) -> Result<TokenView, Error> {
    if input.expected_scope_version <= 0 {
        return Err(Error(StatusCode::BAD_REQUEST, "expected_scope_version must be positive"));
    }
    let display_name = input.display_name.as_deref().map(models::validate_display_name).transpose()?;
    let scope_update = input.repository_grants.is_some() || input.namespace_grants.is_some();
    let repositories = models::normalize_repository_grants(input.repository_grants.unwrap_or_default())?;
    let namespaces = models::normalize_namespace_grants(input.namespace_grants.unwrap_or_default())?;
    if scope_update {
        models::validate_grant_count(&repositories, &namespaces)?;
    }

    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    begin(&tx, actor, true).await?;
    let row = tx
        .query_opt(
            "SELECT t.scope_version, t.is_restricted FROM tokens t \
              WHERE t.id = $1 AND t.user_id = $2 AND t.kind = 'api' AND NOT t.revoked \
              FOR UPDATE OF t",
            &[&token_id, &actor.id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let current_version: i64 = row.get(0);
    let restricted: bool = row.get(1);
    if current_version != input.expected_scope_version {
        return Err(conflict("scope version conflict"));
    }
    if scope_update {
        if restricted {
            let (current_repositories, current_namespaces) = load_grants(&tx, token_id).await?;
            if !models::is_repository_subset(&repositories, &current_repositories)
                || !models::is_namespace_subset(&namespaces, &current_namespaces)
            {
                return Err(Error(StatusCode::FORBIDDEN, "scope updates may only narrow an existing grant set"));
            }
        }
        replace_grants(&tx, token_id, &repositories, &namespaces).await?;
        // A legacy unrestricted token can become restricted (the expected
        // direction); `true` can never go back to `false`.
        tx.execute(
            "UPDATE tokens SET is_restricted = true, scope_version = scope_version + 1 WHERE id = $1",
            &[&token_id],
        )
        .await
        .map_err(Error::internal)?;
    }
    if let Some(name) = display_name {
        tx.execute("UPDATE tokens SET display_name = $2 WHERE id = $1", &[&token_id, &name])
            .await
            .map_err(Error::internal)?;
    }
    let view = load_token_view(&tx, token_id).await?;
    auth::finish_tx(tx, actor, true).await?;
    Ok(view)
}

/// Atomically rotate a token: mint a fresh secret, copy the still-authorised
/// scopes/read-only/expiry/name, revoke the old row. A second rotation of the
/// same old row observes `revoked = true` and returns 409.
pub async fn rotate_token(pool: &Pool, actor: &Identity, token_id: Uuid) -> Result<IssuedToken, Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    begin(&tx, actor, true).await?;
    let row = tx
        .query_opt(
            "SELECT t.revoked, (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) AS live \
               FROM tokens t \
              WHERE t.id = $1 AND t.user_id = $2 AND t.kind = 'api' \
              FOR UPDATE OF t",
            &[&token_id, &actor.id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let revoked: bool = row.get(0);
    let live: bool = row.get(1);
    if revoked || !live {
        return Err(conflict("token is already revoked or expired"));
    }
    let (repositories, namespaces) = load_grants(&tx, token_id).await?;
    // Re-check every copied grant against the actor's current role. Any
    // failure aborts the whole rotation before a new row or revocation exists:
    // a stale role, non-ready repository or database error must never silently
    // drop a scope while the old token is revoked. Callers narrow first.
    for (repository_id, actions) in &repositories {
        validate_repository_grant(&tx, actor, *repository_id, actions).await?;
    }
    for (organization_id, actions) in &namespaces {
        validate_namespace_grant(&tx, actor, *organization_id, actions).await?;
    }
    let kept_repositories = repositories;
    let kept_namespaces = namespaces;
    let new_id = Uuid::new_v4();
    let secret = new_secret();
    tx.execute(
        "INSERT INTO tokens(id, user_id, digest, read_only, expires_at, kind, is_restricted, scope_version, display_name) \
         SELECT $1, user_id, $2, read_only, expires_at, 'api', is_restricted, 1, display_name \
           FROM tokens WHERE id = $3",
        &[&new_id, &db::digest(&secret), &token_id],
    )
    .await
    .map_err(Error::internal)?;
    insert_grants(&tx, new_id, &kept_repositories, &kept_namespaces).await?;
    tx.execute("UPDATE tokens SET revoked = true, scope_version = scope_version + 1 WHERE id = $1", &[&token_id])
        .await
        .map_err(Error::internal)?;
    let view = load_token_view(&tx, new_id).await?;
    auth::finish_tx(tx, actor, true).await?;
    Ok(IssuedToken { token: view, secret })
}

/// Idempotent owner revocation. Cross-user and non-API ids are always 404.
pub async fn revoke_token(pool: &Pool, actor: &Identity, token_id: Uuid) -> Result<(), Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    begin(&tx, actor, true).await?;
    let row = tx
        .query_opt(
            "SELECT t.revoked FROM tokens t \
              WHERE t.id = $1 AND t.user_id = $2 AND t.kind = 'api' FOR UPDATE OF t",
            &[&token_id, &actor.id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if !row.get::<_, bool>(0) {
        tx.execute("UPDATE tokens SET revoked = true, scope_version = scope_version + 1 WHERE id = $1", &[&token_id])
            .await
            .map_err(Error::internal)?;
    }
    auth::finish_tx(tx, actor, true).await
}

/// List the actor's live browser sessions (never their secrets or CSRF value).
pub async fn list_sessions(
    pool: &Pool,
    actor: &Identity,
    after: Option<String>,
    limit: i64,
) -> Result<SessionPage, Error> {
    let scope = format!("sessions:{}", actor.id);
    let (after_ts, after_id) = decode_cursor(after.as_ref(), &scope)?;
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    begin(&tx, actor, false).await?;
    let fields = "SELECT t.id AS id, \
                    to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at, \
                    to_char(s.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS expires_at, \
                    s.created_at AS cursor_ts \
               FROM web_sessions s JOIN tokens t ON t.id = s.token_id \
              WHERE t.user_id = $1 AND t.kind = 'browser' AND NOT t.revoked AND NOT s.revoked \
                AND s.expires_at > clock_timestamp()";
    let rows = match (&after_ts, &after_id) {
        (Some(after_ts), Some(after_id)) => tx
            .query(
                &format!("{fields} AND (s.created_at, t.id) > ($2::timestamptz, $3::uuid) ORDER BY s.created_at, t.id LIMIT $4"),
                &[&actor.id, after_ts, after_id, &(limit + 1)],
            )
            .await
            .map_err(Error::internal)?,
        _ => tx
            .query(
                &format!("{fields} ORDER BY s.created_at, t.id LIMIT $2"),
                &[&actor.id, &(limit + 1)],
            )
            .await
            .map_err(Error::internal)?,
    };
    let more = rows.len() as i64 > limit;
    let rows = &rows[..rows.len().min(limit as usize)];
    let next_after = if more { rows.last().map(|row| cursor(&scope, row)).transpose()? } else { None };
    let items = rows
        .iter()
        .map(|row| SessionView {
            token_id: row.get("id"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
        })
        .collect();
    auth::finish_tx(tx, actor, false).await?;
    Ok(SessionPage { items, next_after })
}

/// Revoke one of the actor's own browser sessions. The `web_sessions` row is
/// updated, never deleted, so audit/GC references stay valid.
pub async fn revoke_session(pool: &Pool, actor: &Identity, session_token_id: Uuid) -> Result<(), Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    begin(&tx, actor, true).await?;
    let updated = tx
        .execute(
            "UPDATE tokens SET revoked = true, scope_version = scope_version + 1 \
              WHERE id = $1 AND user_id = $2 AND kind = 'browser'",
            &[&session_token_id, &actor.id],
        )
        .await
        .map_err(Error::internal)?;
    if updated == 0 {
        return Err(Error::not_found());
    }
    tx.execute("UPDATE web_sessions SET revoked = true WHERE token_id = $1", &[&session_token_id])
        .await
        .map_err(Error::internal)?;
    auth::finish_tx(tx, actor, true).await
}
