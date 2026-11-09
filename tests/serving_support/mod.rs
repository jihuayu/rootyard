//! Shared real-PostgreSQL harness for the `pg_refstore` serving suite.
//!
//! Every `Identity` is produced by the production `auth::authenticate` path from
//! a real `ryt_<64 hex>` API token row (`token_digest` is crate-private by
//! design), every schema is a random task-owned schema migrated by the real
//! `db::migrate`, and Blob backend identities are minted by opening the real
//! production profile factory. Nothing here creates a GitFS directory, runs a
//! Git command or performs provider IO.
use anyhow::{Result, anyhow, ensure};
use axum::http::{HeaderMap, HeaderValue, header};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::BlobBackendIdentity;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

pub const DEADLINE_SECONDS: u64 = 20;

pub fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set when running the ignored ref_store_serving suite")
}

pub fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(DEADLINE_SECONDS)
}

pub struct Fixture {
    admin: Pool,
    pub pool: Pool,
    pub schema: String,
}

impl Fixture {
    /// One fresh migrated schema. The suite fails loudly if migration 145 is not
    /// part of `db::migrate` instead of silently testing an older shape.
    pub async fn new() -> Result<Self> {
        Self::with_pool_size(16).await
    }

    /// Same fixture with an explicit pool size. `1` proves the factory never
    /// needs two concurrent checkouts (no post-commit re-checkout deadlock).
    pub async fn with_pool_size(max_size: usize) -> Result<Self> {
        let url = database_url();
        let admin = db::pool(&url)?;
        let schema = format!("ref_store_serving_{}", Uuid::new_v4().simple());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
        let mut config: tokio_postgres::Config = url.parse()?;
        config.options(format!(
            "-c search_path={schema} -c timezone=UTC -c statement_timeout=20000 -c lock_timeout=15000"
        ));
        let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(max_size)
            .build()?;
        db::migrate(&pool).await?;
        let installed: bool = pool
            .get()
            .await?
            .query_one(
                "SELECT to_regclass('ref_store_serving_repositories') IS NOT NULL
                        AND to_regclass('ref_store_core_protocol_repos') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        ensure!(
            installed,
            "the migrated schema has no migration-145 serving binding table; wire 145_ref_store_serving.sql into db::migrate"
        );
        Ok(Self { admin, pool, schema })
    }

    pub async fn teardown(self) -> Result<()> {
        self.pool.close();
        self.admin.get().await?.batch_execute(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema)).await?;
        Ok(())
    }
}

#[allow(dead_code)] // Shared by serving and serving-read integration targets.
pub struct Actor {
    pub identity: db::Identity,
    pub token: String,
    pub user_id: Uuid,
    pub username: String,
}

fn secret() -> String {
    format!("ryt_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

async fn issue_token(pool: &Pool, user_id: Uuid, restricted: bool) -> Result<(Uuid, String)> {
    let token = secret();
    let token_id = Uuid::new_v4();
    let digest = db::digest(&token);
    pool.get()
        .await?
        .execute(
            "INSERT INTO tokens(id,user_id,digest,read_only,kind,is_restricted) VALUES($1,$2,$3,false,'api',$4)",
            &[&token_id, &user_id, &digest, &restricted],
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

/// A real user + user namespace + API token, authenticated through the
/// production path. `restricted` marks the token as an explicit restricted set
/// (no create scope exists, so provisioning must refuse it).
pub async fn actor(pool: &Pool, restricted: bool) -> Result<Actor> {
    let user_id = Uuid::new_v4();
    let username = format!("srv{}", &user_id.simple().to_string()[..12]);
    let client = pool.get().await?;
    client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&user_id, &username]).await?;
    // The production users_personal_namespace trigger creates this namespace.
    drop(client);
    let (token_id, token) = issue_token(pool, user_id, restricted).await?;
    let identity = authenticate(pool, &token).await?;
    ensure!(identity.id == user_id && identity.token_id == token_id, "authenticated identity differs");
    Ok(Actor { identity, token, user_id, username })
}

static BLOB_ENV: Mutex<()> = Mutex::new(());

/// Digest of the *actually opened* production Blob profile. Two calls that
/// differ in `bucket` name two different physical backends without provider IO.
pub fn backend_identity(bucket: &str) -> Result<BlobBackendIdentity> {
    let guard = BLOB_ENV.lock().unwrap_or_else(|poison| poison.into_inner());
    unsafe {
        std::env::set_var("ROOTYARD_BLOB_DRIVER", "opendal");
        std::env::set_var("ROOTYARD_BLOB_SERVICE", "s3");
        std::env::set_var("ROOTYARD_BLOB_ENDPOINT", "http://127.0.0.1:1");
        std::env::set_var("ROOTYARD_BLOB_REGION", "us-east-1");
        std::env::set_var("ROOTYARD_BLOB_ACCESS_KEY_ID", "serving-fixture-access-key");
        std::env::set_var("ROOTYARD_BLOB_SECRET_ACCESS_KEY", "serving-fixture-secret-key");
        std::env::set_var("ROOTYARD_BLOB_BUCKET", bucket);
        std::env::set_var("ROOTYARD_BLOB_RETRY_MAX_TIMES", "0");
        std::env::remove_var("ROOTYARD_BLOB_CONTAINER");
        std::env::remove_var("ROOTYARD_BLOB_ACCOUNT_NAME");
        std::env::remove_var("ROOTYARD_BLOB_ACCOUNT_KEY");
        std::env::remove_var("ROOTYARD_BLOB_SESSION_TOKEN");
        std::env::remove_var("ROOTYARD_BLOB_ROOT");
    }
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("fixture Blob profile rejected: {error}"))?;
    let store = BlobStore::open(profile).map_err(|error| anyhow!("fixture Blob store rejected: {error}"))?;
    let identity = store.backend_identity().clone();
    drop(guard);
    Ok(identity)
}
