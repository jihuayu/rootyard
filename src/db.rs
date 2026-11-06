use anyhow::{Context, Result, bail};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_postgres::NoTls;
use uuid::Uuid;

pub fn pool(url: &str) -> Result<Pool> {
    let mut cfg: tokio_postgres::Config = url.parse()?;
    if matches!(cfg.get_ssl_mode(), tokio_postgres::config::SslMode::Require) {
        bail!("PostgreSQL TLS requires a local TLS proxy; no silent downgrade");
    }
    cfg.connect_timeout(std::time::Duration::from_secs(5));
    let options = format!(
        "{} -c statement_timeout=5000 -c lock_timeout=3000 -c timezone=UTC",
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

/// Post-001 migrations in execution order. Parallel tracks reserve disjoint ranges:
/// 009..=019 (Forge PRs/Checks/Auth), 020..=029 (LFS/Browse), 030..=039 (CI Mirror/GC).
pub const MIGRATIONS: &[(i32, &str)] = &[
    (2, include_str!("../migrations/002_reliability.sql")),
    (3, include_str!("../migrations/003_recovery_operations.sql")),
    (6, include_str!("../migrations/006_forge_issues.sql")),
    (7, include_str!("../migrations/007_forge_idempotency.sql")),
    (8, include_str!("../migrations/008_ci_checkouts.sql")),
    (9, include_str!("../migrations/009_forge_pulls.sql")),
    (20, include_str!("../migrations/020_lfs_objects.sql")),
    (30, include_str!("../migrations/030_ci_mirror.sql")),
    (40, include_str!("../migrations/040_webhooks.sql")),
    (50, include_str!("../migrations/050_members_rbac.sql")),
    (60, include_str!("../migrations/060_sharding_fencing.sql")),
    (70, include_str!("../migrations/070_repository_object_format.sql")),
    (80, include_str!("../migrations/080_cluster_security.sql")),
    (81, include_str!("../migrations/081_shard_marker_transitions.sql")),
    (82, include_str!("../migrations/082_cluster_transport_nonces.sql")),
    (90, include_str!("../migrations/090_workspaces.sql")),
    (91, include_str!("../migrations/091_workspace_capture.sql")),
    (92, include_str!("../migrations/092_sandbox_jobs.sql")),
    (110, include_str!("../migrations/110_audit_sequence.sql")),
    (120, include_str!("../migrations/120_organizations.sql")),
];

pub const SCHEMA_VERSIONS: &[i32] = &[1, 2, 3, 6, 7, 8, 9, 20, 30, 40, 50, 60, 70, 80, 81, 82, 90, 91, 92, 110, 120];

pub async fn migrate(pool: &Pool) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock(738390103)", &[])
        .await?;
    tx.batch_execute(include_str!("../migrations/001_initial.sql"))
        .await?;
    for &(version, sql) in MIGRATIONS {
        if tx
            .query_opt(
                "SELECT version FROM schema_migrations WHERE version=$1",
                &[&version],
            )
            .await?
            .is_none()
        {
            tx.batch_execute(sql).await?;
        }
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
    pub(crate) token_digest: Vec<u8>,
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
    pub object_format: String,
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
            object_format: row.get("object_format"),
        }
    }
}

pub const REPO_SELECT: &str = "SELECT r.id, r.name, r.state, r.storage_backend, r.storage_generation, r.object_format, ns.slug AS username FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id";

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
    #[test]
    fn migrations_are_strictly_ordered_and_match_schema_versions() {
        assert_eq!(SCHEMA_VERSIONS[0], 1);
        assert_eq!(SCHEMA_VERSIONS.len(), MIGRATIONS.len() + 1);
        for (i, &(version, sql)) in MIGRATIONS.iter().enumerate() {
            assert_eq!(SCHEMA_VERSIONS[i + 1], version);
            assert!(SCHEMA_VERSIONS[i] < version);
            assert!(!sql.trim().is_empty());
        }
    }
}
