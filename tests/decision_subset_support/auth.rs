//! Real API-token actors, collaboration RBAC and token-narrowing rows.
//!
//! An `Identity` is never built field-by-field here (`token_digest` is
//! crate-private by design). The fixture inserts a real `ryt_<64 hex>` token
//! row with the real `db::digest`, then authenticates that secret through the
//! production `auth::authenticate` path. Every later decision re-reads this
//! token row, its scopes and its RBAC role under the decision locks.
use anyhow::{Result, anyhow, ensure};
use axum::http::{HeaderMap, HeaderValue, header};
use deadpool_postgres::Pool;
use rootyard::db;
use uuid::Uuid;

pub struct Actor {
    pub identity: db::Identity,
    pub token: String,
    pub token_id: Uuid,
    pub user_id: Uuid,
}

fn secret() -> String {
    // `ryt_` plus exactly 64 lowercase hex characters, like the real API.
    format!("ryt_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

async fn issue_token(pool: &Pool, user_id: Uuid) -> Result<(Uuid, String)> {
    let token = secret();
    let token_id = Uuid::new_v4();
    let digest = db::digest(&token);
    pool.get()
        .await?
        .execute(
            "INSERT INTO tokens(id,user_id,digest,read_only,kind) VALUES($1,$2,$3,false,'api')",
            &[&token_id, &user_id, &digest],
        )
        .await?;
    Ok((token_id, token))
}

async fn authenticate(pool: &Pool, token: &str) -> Result<db::Identity> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| anyhow!("token is not a valid header"))?,
    );
    rootyard::auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("real API token authentication failed: {}", error.1))
}

pub async fn owner(pool: &Pool, tenant_id: Uuid) -> Result<Actor> {
    let (token_id, token) = issue_token(pool, tenant_id).await?;
    let identity = authenticate(pool, &token).await?;
    ensure!(identity.id == tenant_id && identity.token_id == token_id, "owner token identity differs");
    Ok(Actor { identity, token, token_id, user_id: tenant_id })
}

/// A real non-owner collaborator row plus its own API token.
pub async fn collaborator(pool: &Pool, tenant_id: Uuid, repository_id: Uuid, role: &str) -> Result<Actor> {
    ensure!(matches!(role, "read" | "triage" | "write" | "maintain" | "admin"), "invalid RBAC role");
    let user_id = Uuid::new_v4();
    let username = format!("member{}", &user_id.simple().to_string()[..12]);
    pool.get().await?.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&user_id, &username]).await?;
    pool.get()
        .await?
        .execute(
            "INSERT INTO repository_collaborators(repository_id,tenant_id,user_id,role)
             VALUES($1,$2,$3,$4)",
            &[&repository_id, &tenant_id, &user_id, &role],
        )
        .await?;
    let (token_id, token) = issue_token(pool, user_id).await?;
    let identity = authenticate(pool, &token).await?;
    ensure!(identity.id == user_id, "collaborator token identity differs");
    Ok(Actor { identity, token, token_id, user_id })
}

/// A real API user with no repository role at all (unauthorized cancel attempt).
pub async fn stranger(pool: &Pool) -> Result<Actor> {
    let user_id = Uuid::new_v4();
    let username = format!("stranger{}", &user_id.simple().to_string()[..12]);
    pool.get().await?.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&user_id, &username]).await?;
    let (token_id, token) = issue_token(pool, user_id).await?;
    let identity = authenticate(pool, &token).await?;
    Ok(Actor { identity, token, token_id, user_id })
}

pub async fn revoke_token(pool: &Pool, token_id: Uuid) -> Result<()> {
    let updated = pool.get().await?.execute("UPDATE tokens SET revoked=true WHERE id=$1", &[&token_id]).await?;
    ensure!(updated == 1, "token revocation did not hit exactly one row");
    Ok(())
}

/// Actual database-clock expiry, never a rewritten `expires_at` value.
pub async fn expire_after_millis(pool: &Pool, token_id: Uuid, millis: i64) -> Result<()> {
    ensure!(millis > 0, "expiry must be in the future");
    let updated = pool
        .get()
        .await?
        .execute(
            "UPDATE tokens SET expires_at = clock_timestamp() + ($2::bigint::text || ' milliseconds')::interval
             WHERE id=$1",
            &[&token_id, &millis],
        )
        .await?;
    ensure!(updated == 1, "token expiry did not hit exactly one row");
    Ok(())
}

pub async fn token_expiry(pool: &Pool, token_id: Uuid) -> Result<Option<i64>> {
    let row = pool
        .get()
        .await?
        .query_one("SELECT (extract(epoch FROM expires_at)*1000)::bigint FROM tokens WHERE id=$1", &[&token_id])
        .await?;
    Ok(row.get(0))
}

/// Replace the restricted scope set with exactly `actions` on one repository.
pub async fn restrict_token(pool: &Pool, token_id: Uuid, repository_id: Uuid, actions: &[&str]) -> Result<()> {
    ensure!(!actions.is_empty(), "a restricted token needs at least one action");
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute("UPDATE tokens SET is_restricted=true, scope_version=scope_version+1 WHERE id=$1", &[&token_id]).await?;
    tx.execute("DELETE FROM token_repository_scopes WHERE token_id=$1", &[&token_id]).await?;
    for action in actions {
        tx.execute(
            "INSERT INTO token_repository_scopes(token_id,repository_id,action) VALUES($1,$2,$3)",
            &[&token_id, &repository_id, action],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn remove_collaborator(pool: &Pool, repository_id: Uuid, user_id: Uuid) -> Result<()> {
    let deleted = pool
        .get()
        .await?
        .execute(
            "DELETE FROM repository_collaborators WHERE repository_id=$1 AND user_id=$2",
            &[&repository_id, &user_id],
        )
        .await?;
    ensure!(deleted == 1, "collaborator revocation did not hit exactly one row");
    Ok(())
}

/// Read-only verification that the protected decision row keeps the real
/// token digest rather than a caller-provided grant.
pub async fn assert_stored_token_digest(pool: &Pool, decision_id: Uuid, token: &str) -> Result<()> {
    let row = pool
        .get()
        .await?
        .query_one("SELECT token_digest FROM ref_store_publication_decisions WHERE decision_id=$1", &[&decision_id])
        .await?;
    let stored: String = row.get(0);
    ensure!(stored == hex::encode(db::digest(token)), "decision did not persist the real API token digest");
    Ok(())
}
