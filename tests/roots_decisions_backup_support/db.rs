//! Parent-owned database attachment for the roots/decisions backup drill.
//!
//! The Python drill owns exactly one disposable database and runs the real
//! `migrate` CLI before this helper starts. This module therefore **never**
//! creates a schema, never runs `db::migrate`, and never drops/truncates
//! anything: it only connects to the inherited `ROOTYARD_TEST_DATABASE_URL`.
//!
//! The read helpers below mirror the shared `retention_roots_support::db`
//! surface the reused `pack.rs`/`roots.rs` modules expect, but read the
//! inherited database instead of creating one.
use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::ref_store::core::PgRefStoreCore;
use rootyard::ref_store::{CoreGateInit, CoreGateVersion, GitObjectFormat, RefName, VersionCheck};
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

const OP_SECONDS: u64 = 120;

pub fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(OP_SECONDS)
}

pub fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set for the roots/decisions backup drill")
}

/// Real pool over the inherited URL. The URL is used verbatim (the parent owns
/// its search path and settings); only the pool size is chosen here.
pub fn pool_for(url: &str, max: usize) -> Result<Pool> {
    let config: tokio_postgres::Config = url.parse()?;
    Ok(Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(max)
        .build()?)
}

pub struct Db {
    pub pool: Pool,
    url: String,
}

impl Db {
    /// Attach to the parent-owned migrated database. Never migrates.
    pub async fn attach(max: usize) -> Result<Self> {
        let url = database_url();
        let pool = pool_for(&url, max)?;
        let client = pool.get().await?;
        let ready: bool = client
            .query_one(
                "SELECT to_regclass('ref_store_core_roots') IS NOT NULL
                    AND to_regclass('ref_store_core_root_heads') IS NOT NULL
                    AND to_regclass('ref_store_publication_decisions') IS NOT NULL
                    AND to_regclass('ref_store_decision_cancellations') IS NOT NULL
                    AND to_regclass('ref_store_core_protocol_repos') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_snapshot_history') IS NOT NULL
                    AND EXISTS(SELECT 1 FROM schema_migrations WHERE version=144)",
                &[],
            )
            .await?
            .get(0);
        ensure!(ready, "the parent-owned database is not migrated to schema 144 with the real roots/decision tables");
        drop(client);
        Ok(Self { pool, url })
    }

    pub fn new_pool(&self, max: usize) -> Result<Pool> {
        pool_for(&self.url, max)
    }

    /// One trusted user (also the repository owner/tenant) and one isolated,
    /// explicitly provisioning gitfs repository. Same shape the shared fixture
    /// uses; only the database is inherited.
    pub async fn business(&self, format: GitObjectFormat) -> Result<(Uuid, Uuid)> {
        let tenant = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let object_format = format.as_str();
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO users(id,username) VALUES($1,$2)",
                &[&tenant, &format!("roots{}", &tenant.simple().to_string()[..10])],
            )
            .await?;
        client
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state,object_format)
                 VALUES($1,$2,$3,'provisioning',$4)",
                &[&repo, &tenant, &format!("repo{}", &repo.simple().to_string()[..10]), &object_format],
            )
            .await?;
        drop(client);
        Ok((tenant, repo))
    }

    pub async fn gate(&self, repo: Uuid, tenant: Uuid, format: GitObjectFormat) -> Result<CoreGateVersion> {
        let init = CoreGateInit::new(repo, tenant, format, Uuid::new_v4(), 1, 1, RefName::branch("refs/heads/main")?)?;
        let mut client = self.pool.get().await?;
        Ok(PgRefStoreCore.initialize(&mut client, &init, deadline()).await?.version())
    }
}

pub async fn username(pool: &Pool, user_id: Uuid) -> Result<String> {
    let client = pool.get().await?;
    let row = client
        .query_opt("SELECT username FROM users WHERE id=$1", &[&user_id])
        .await?
        .ok_or_else(|| anyhow!("fixture user row disappeared"))?;
    Ok(row.get(0))
}

pub async fn gate_version(pool: &Pool, repo: Uuid, tenant: Uuid) -> Result<CoreGateVersion> {
    let mut client = pool.get().await?;
    match PgRefStoreCore.check_version(&mut client, repo, tenant, None, deadline()).await? {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => Ok(version),
        VersionCheck::Unknown => Err(anyhow!("gate disappeared")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    pub roots: i64,
    pub root_oid_refs: i64,
    pub pack_bindings: i64,
    pub receipts: i64,
    pub logical_bytes: i64,
}

pub async fn repo_usage(pool: &Pool, repo: Uuid) -> Result<Option<Usage>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT roots,root_oid_refs,pack_bindings,receipts,logical_bytes
             FROM ref_store_core_root_repo_usage WHERE repository_id=$1",
            &[&repo],
        )
        .await?;
    Ok(row.map(|r| Usage {
        roots: r.get(0),
        root_oid_refs: r.get(1),
        pack_bindings: r.get(2),
        receipts: r.get(3),
        logical_bytes: r.get(4),
    }))
}

pub async fn tenant_usage(pool: &Pool, tenant: Uuid) -> Result<Option<Usage>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT roots,root_oid_refs,pack_bindings,receipts,logical_bytes
             FROM ref_store_core_root_tenant_usage WHERE tenant_id=$1",
            &[&tenant],
        )
        .await?;
    Ok(row.map(|r| Usage {
        roots: r.get(0),
        root_oid_refs: r.get(1),
        pack_bindings: r.get(2),
        receipts: r.get(3),
        logical_bytes: r.get(4),
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootCounts {
    pub heads: i64,
    pub captures: i64,
    pub refs: i64,
    pub oids: i64,
    pub packs: i64,
    pub tombstones: i64,
    pub receipts: i64,
}

pub async fn root_counts(pool: &Pool, repo: Uuid) -> Result<RootCounts> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT (SELECT count(*) FROM ref_store_core_root_heads WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_roots WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_root_refs WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_root_oids WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_root_packs WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_root_tombstones WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_root_receipts WHERE repository_id=$1)",
            &[&repo],
        )
        .await?;
    Ok(RootCounts {
        heads: row.get(0),
        captures: row.get(1),
        refs: row.get(2),
        oids: row.get(3),
        packs: row.get(4),
        tombstones: row.get(5),
        receipts: row.get(6),
    })
}

pub async fn roots_revision(pool: &Pool, repo: Uuid) -> Result<Option<i64>> {
    let client = pool.get().await?;
    let row = client
        .query_opt("SELECT roots_revision FROM ref_store_core_protocol_repos WHERE repository_id=$1", &[&repo])
        .await?;
    Ok(row.map(|r| r.get(0)))
}

/// Wait on the actual database clock (never a mutated `expires_at`) until the
/// named A5 source pin is expired.
pub async fn wait_pin_expired(pool: &Pool, pin_id: Uuid) -> Result<()> {
    let started = std::time::Instant::now();
    loop {
        let client = pool.get().await?;
        let row = client
            .query_opt("SELECT expires_at <= clock_timestamp() FROM ref_store_core_pins WHERE pin_id=$1", &[&pin_id])
            .await?;
        drop(client);
        let Some(row) = row else {
            return Err(anyhow!("source pin disappeared before it expired"));
        };
        if row.get::<_, bool>(0) {
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(20) {
            return Err(anyhow!("source pin did not expire on the actual database clock"));
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}
