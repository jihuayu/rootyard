//! Real users, tokens, repository provisioning and the collaborator grant.
use anyhow::{Result, anyhow, ensure};
use base64::Engine as _;
use deadpool_postgres::Pool;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db;
use rootyard::members::models::Role;
use rootyard::ref_store::serving::{ProvisionRequest, provision};
use serde_json::{Value, json};
use std::path::Path;
use uuid::Uuid;

use super::super::db::deadline;
use super::super::http;
use super::SHA1;

/// Result of the production token issuance, before any identity is derived.
/// The secret stays inside this module and the HTTP helpers' arguments.
pub(super) struct IssuedUser {
    pub(super) user_id: Uuid,
    pub(super) username: String,
    pub(super) token: String,
}

/// Create a real user and its writable token through the production
/// `db::issue_token`. The user row precedes any token so no credential is ever
/// orphaned by a later fixture refusal.
pub(super) async fn issued_user(pool: &Pool, prefix: &str) -> Result<IssuedUser> {
    let username = format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..12]);
    let issued = db::issue_token(pool, &username, true, false).await?;
    let user_id = issued["user_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| anyhow!("token response has no user id"))?;
    let token = issued["token"].as_str().ok_or_else(|| anyhow!("token response has no secret"))?.to_owned();
    let username = issued["username"].as_str().ok_or_else(|| anyhow!("token response has no username"))?.to_owned();
    Ok(IssuedUser { user_id, username, token })
}

/// Authenticate an issued token through the production `auth::authenticate`.
pub(super) async fn authenticate(pool: &Pool, user: &IssuedUser) -> Result<db::Identity> {
    let username: String =
        pool.get().await?.query_one("SELECT username FROM users WHERE id=$1", &[&user.user_id]).await?.get(0);
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{}", user.token));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|_| anyhow!("token header refused"))?,
    );
    let identity = rootyard::auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("real token authentication failed: {}", error.1))?;
    ensure!(!identity.read_only && identity.id == user.user_id, "issued token identity differs");
    ensure!(identity.username == user.username, "issued token belongs to another user");
    Ok(identity)
}

/// One ready `pg_refstore` repository and its serving binding from the real
/// provision path (`ref_store::serving::{ProvisionRequest, provision}`).
pub(super) async fn provision_with(pool: &Pool, actor: &db::Identity, name: &str, store: &BlobStore) -> Result<Uuid> {
    let receipt = provision(
        pool,
        actor,
        ProvisionRequest { owner: None, name: name.into(), object_format: SHA1 },
        store.backend_identity(),
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("real provision of `{name}` refused: {error}"))?;
    ensure!(receipt.created, "fresh provision of `{name}` replayed instead of creating");
    ensure!(receipt.repository.storage_backend == "pg_refstore", "a provisioned repository is not pg_refstore");
    ensure!(receipt.repository.state == "ready", "a provisioned repository is not ready");
    Ok(receipt.repository.id)
}

/// Grant the producer `write` on the owner's bound repository through the real
/// owner route (`POST /api/repos/{owner}/bound/collaborators`), then read the
/// stored grant back through the producer's own token. The owner's admin role is
/// resolved by the production `auth::authorize_repo_with_role`; the insertion is
/// the production `members::rbac::upsert_collaborator`, never SQL here.
pub(super) async fn grant_producer(
    http: &http::Http,
    owner_token: &str,
    owner_username: &str,
    producer: &IssuedUser,
) -> Result<Value> {
    let (owner_id, whoami_owner) = http.whoami(owner_token).await?;
    ensure!(whoami_owner == owner_username, "the owner token authenticates another user");
    let (status, body) =
        http.post_collaborator(owner_token, owner_username, "bound", &producer.username, Role::Write).await?;
    ensure!(status == axum::http::StatusCode::CREATED, "the owner collaborator grant answered {status}");
    http::ensure_created(&body, &producer.username, Role::Write)?;
    let stored_user: Uuid = body["user_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| anyhow!("the collaborator response has no user id"))?;
    ensure!(stored_user == producer.user_id, "the collaborator grant names another user");
    // The producer's own token must now read that exact grant.
    let (status, stored) = http.get_collaborator(&producer.token, owner_username, "bound", &producer.username).await?;
    ensure!(status == axum::http::StatusCode::OK, "the producer collaborator read answered {status}");
    http::ensure_read_back(&stored, producer.user_id, &producer.username, Role::Write)?;
    Ok(json!({
        "repository_owner_id": owner_id.to_string(),
        "user_id": producer.user_id.to_string(),
        "username": producer.username,
        "role": Role::Write.as_str(),
        "route": format!("/api/repos/{owner_username}/bound/collaborators"),
        "status": status.as_u16(),
    }))
}

/// Fixture-local offline data directory: the operator-initialized volume
/// identity the real `backup --offline` CLI requires (no server runs).
pub(super) fn write_volume_identity(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir.join("repos"))?;
    let volume = dir.join(".volume-id");
    ensure!(!volume.exists(), "refusing to overwrite an existing volume identity");
    // `Storage::open_role` requires exactly 36 bytes and parses the UUID text,
    // so write the canonical hyphenated form with no trailing newline.
    std::fs::write(&volume, Uuid::new_v4().to_string())?;
    std::fs::set_permissions(&volume, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
