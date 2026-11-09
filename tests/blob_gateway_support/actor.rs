//! Real API-token actors. The token secret is minted by the production
//! `db::issue_token` path and authenticated through `auth::authenticate`; no
//! `Identity` is assembled field-by-field in this fixture.
use anyhow::{Result, anyhow, ensure};
use axum::http::{HeaderMap, HeaderValue, header};
use deadpool_postgres::Pool;
use rootyard::db;
use uuid::Uuid;

pub struct Actor {
    pub identity: db::Identity,
    pub token: String,
    pub username: String,
}

async fn issue(pool: &Pool, username: &str) -> Result<Actor> {
    let value = db::issue_token(pool, username, true, false)
        .await
        .map_err(|error| anyhow!("real API token issue failed: {error}"))?;
    let token = value["token"].as_str().ok_or_else(|| anyhow!("token response has no secret"))?.to_owned();
    let user_id = Uuid::parse_str(value["user_id"].as_str().ok_or_else(|| anyhow!("token response has no user id"))?)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| anyhow!("token is not a valid header"))?,
    );
    let identity = rootyard::auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("real token authentication failed: {}", error.1))?;
    ensure!(identity.id == user_id && !identity.read_only, "issued writable token identity differs");
    Ok(Actor { identity, token, username: username.to_owned() })
}

/// Real owner. The personal namespace slug equals the username.
pub async fn owner(pool: &Pool) -> Result<Actor> {
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    issue(pool, &format!("gateway{suffix}")).await
}

/// A real user with no role on another actor's repository.
pub async fn stranger(pool: &Pool) -> Result<Actor> {
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    issue(pool, &format!("stranger{suffix}")).await
}
