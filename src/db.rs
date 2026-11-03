use anyhow::{Context, Result, bail};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_postgres::NoTls;
use uuid::Uuid;

pub fn pool(url: &str) -> Result<Pool> {
    let mut cfg: tokio_postgres::Config = url.parse()?;
    cfg.connect_timeout(std::time::Duration::from_secs(5));
    let options = format!(
        "{} -c statement_timeout=5000 -c lock_timeout=3000",
        cfg.get_options().unwrap_or("")
    );
    cfg.options(&options);
    cfg.application_name("rootyard");
    Ok(Pool::builder(Manager::from_config(
        cfg,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    ))
    .runtime(deadpool_postgres::Runtime::Tokio1)
    .max_size(16)
    .wait_timeout(Some(std::time::Duration::from_secs(5)))
    .create_timeout(Some(std::time::Duration::from_secs(5)))
    .build()?)
}

pub async fn migrate(pool: &Pool) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock(738390103)", &[])
        .await?;
    tx.batch_execute(include_str!("../migrations/001_initial.sql"))
        .await?;
    if tx
        .query_opt("SELECT version FROM schema_migrations WHERE version=2", &[])
        .await?
        .is_none()
    {
        tx.batch_execute(include_str!("../migrations/002_reliability.sql"))
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

pub fn digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub async fn issue_token(
    pool: &Pool,
    username: &str,
    create_user: bool,
    read_only: bool,
) -> Result<serde_json::Value> {
    if !valid_name(username) {
        bail!(
            "invalid username: use 1-63 lowercase ASCII letters, digits, underscores or hyphens; begin with a letter or digit"
        );
    }
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let user_id = if create_user {
        let id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO users (id, username) VALUES ($1, $2)",
            &[&id, &username],
        )
        .await
        .context("user already exists or cannot be created")?;
        id
    } else {
        tx.query_opt("SELECT id FROM users WHERE username = $1", &[&username])
            .await?
            .context("user not found")?
            .get(0)
    };
    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let token = format!("ryt_{}", hex::encode(random));
    let token_id = Uuid::new_v4();
    tx.execute(
        "INSERT INTO tokens (id, user_id, digest, read_only) VALUES ($1,$2,$3,$4)",
        &[&token_id, &user_id, &digest(&token), &read_only],
    )
    .await?;
    tx.commit().await?;
    Ok(
        serde_json::json!({"user_id":user_id,"username":username,"token_id":token_id,"token":token,"read_only":read_only}),
    )
}

#[derive(Clone)]
pub struct Identity {
    pub id: Uuid,
    pub token_id: Uuid,
    pub username: String,
    pub read_only: bool,
}

#[derive(Clone, Serialize)]
pub struct Repository {
    pub id: Uuid,
    pub name: String,
    pub owner: String,
    pub state: String,
    pub clone_path: String,
    pub storage_backend: String,
    pub storage_generation: i64,
}

impl Repository {
    pub fn from_row(row: &tokio_postgres::Row) -> Self {
        let owner: String = row.get("username");
        let name: String = row.get("name");
        Self {
            id: row.get("id"),
            clone_path: format!("/git/{owner}/{name}.git"),
            name,
            owner,
            state: row.get("state"),
            storage_backend: row.get("storage_backend"),
            storage_generation: row.get("storage_generation"),
        }
    }
}

pub const REPO_SELECT: &str = "SELECT r.id, r.name, r.state, r.storage_backend, r.storage_generation, u.username FROM repositories r JOIN users u ON u.id = r.owner_id";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_are_paths_never() {
        for good in ["a", "0", "repo-one", "a_b"] {
            assert!(valid_name(good));
        }
        for bad in [
            "", ".", "..", "a.git", "-a", "A", "a/b", "a%2fb", "a\\b", "a\0", "é",
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert!(!valid_name(&"a".repeat(64)));
    }
    #[test]
    fn hashes_are_stable_and_distinct() {
        assert_eq!(digest("one").len(), 32);
        assert_eq!(digest("one"), digest("one"));
        assert_ne!(digest("one"), digest("two"));
    }
}
