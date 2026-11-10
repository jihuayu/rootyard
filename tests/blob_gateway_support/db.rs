//! Real PostgreSQL fixture for the Blob Git gateway suite.
//!
//! One random schema, the actual `db::migrate` path (migration 144 asserted),
//! real pools and real business rows. A missing variable is a hard failure: no
//! case silently skips when PostgreSQL is absent.
use anyhow::{Result, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::db;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

const OP_SECONDS: u64 = 120;

pub fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(OP_SECONDS)
}

pub fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set for the blob_git_gateway suite")
}

pub fn pool_for(url: &str, schema: &str, max: usize) -> Result<Pool> {
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000"));
    Ok(Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(max)
        .build()?)
}

pub struct Db {
    admin: Pool,
    pub pool: Pool,
    schema: String,
}

impl Db {
    pub async fn setup() -> Result<Self> {
        let url = database_url();
        let admin = db::pool(&url)?;
        let schema = format!("blob_git_gateway_{}", Uuid::new_v4().simple());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
        let pool = pool_for(&url, &schema, 16)?;
        db::migrate(&pool).await?;
        let client = pool.get().await?;
        let installed: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=144)
                    AND to_regclass('ref_store_core_gates') IS NOT NULL
                    AND to_regclass('ref_store_core_refs') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_memberships') IS NOT NULL
                    AND to_regclass('ref_store_core_protocol_repos') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        ensure!(installed, "db::migrate did not install migration 144 and the core gate/pack tables");
        drop(client);
        Ok(Self { admin, pool, schema })
    }

    pub async fn teardown(&self) -> Result<()> {
        self.admin.get().await?.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema)).await?;
        Ok(())
    }

    pub async fn finish(&self, outcome: Result<()>) -> Result<()> {
        match outcome {
            Ok(()) => self.teardown().await,
            Err(error) => {
                let _ = self.teardown().await;
                Err(error)
            }
        }
    }
}
