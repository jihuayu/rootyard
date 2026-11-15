//! Real PostgreSQL fixture for the retention-roots suite.
//!
//! One random schema, the actual `db::migrate` path (migration 144 plus the
//! frozen 139/142/143 row shapes) and real pools only. Missing configuration is
//! a hard failure; no test may skip itself when PG is absent.
use anyhow::{Result, anyhow, ensure};
use axum::http::{HeaderMap, HeaderValue, header};
use base64::Engine as _;
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db;
use rootyard::ref_store::core::PgRefStoreCore;
use rootyard::ref_store::serving::{ProvisionRequest, provision};
use rootyard::ref_store::{CoreGateInit, CoreGateVersion, GitObjectFormat, RefName, VersionCheck};
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

const OP_SECONDS: u64 = 30;

pub fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(OP_SECONDS)
}

pub fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set for ref_store_retention_roots")
}

pub fn random_key() -> i64 {
    i64::from_be_bytes(Uuid::new_v4().into_bytes()[..8].try_into().expect("eight bytes"))
}

pub fn pool_for(url: &str, schema: &str, max: usize, extra: Option<&str>) -> Result<Pool> {
    let mut config: tokio_postgres::Config = url.parse()?;
    let mut options =
        format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000");
    if let Some(extra) = extra {
        options.push_str(&format!(" -c {extra}"));
    }
    config.options(options);
    Ok(Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(max)
        .build()?)
}

/// One real writable API identity created through the production token path.
/// The secret is used only to authenticate the returned Identity and is never
/// printed or retained by the fixture.
pub async fn serving_actor(pool: &Pool, label: &str) -> Result<db::Identity> {
    let username = format!("{label}{}", Uuid::new_v4().simple());
    let issued = db::issue_token(pool, &username, true, false).await?;
    let username = issued["username"].as_str().ok_or_else(|| anyhow!("issued token has no username"))?;
    let secret = issued["token"].as_str().ok_or_else(|| anyhow!("issued token has no secret"))?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|_| anyhow!("token header refused"))?,
    );
    let identity = rootyard::auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("real token authentication failed: {}", error.1))?;
    ensure!(!identity.read_only && identity.username == username, "issued serving identity differs");
    Ok(identity)
}

/// A real writable identity with an initial restricted repository grant set.
/// The token is issued through `db::issue_token`; only the missing public grant
/// issuance path is represented by labeled initial scope metadata.
pub async fn serving_actor_with_scopes(
    pool: &Pool,
    repo_id: Uuid,
    actions: &[&str],
    label: &str,
) -> Result<db::Identity> {
    let username = format!("{label}{}", Uuid::new_v4().simple());
    let issued = db::issue_token(pool, &username, true, false).await?;
    let token_id: Uuid = issued["token_id"]
        .as_str()
        .ok_or_else(|| anyhow!("issued token has no id"))?
        .parse()
        .map_err(|_| anyhow!("issued token id is invalid"))?;
    let username = issued["username"].as_str().ok_or_else(|| anyhow!("issued token has no username"))?;
    let secret = issued["token"].as_str().ok_or_else(|| anyhow!("issued token has no secret"))?;
    let client = pool.get().await?;
    client.execute("UPDATE tokens SET is_restricted=true WHERE id=$1", &[&token_id]).await?;
    for action in actions {
        client
            .execute(
                "INSERT INTO token_repository_scopes(token_id,repository_id,action) VALUES($1,$2,$3)",
                &[&token_id, &repo_id, action],
            )
            .await?;
    }
    drop(client);
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|_| anyhow!("token header refused"))?,
    );
    rootyard::auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("real restricted token authentication failed: {}", error.1))
}

/// A real collaborator identity with an initial role metadata row. Role rows are
/// fixture inputs because the public collaborator transport is outside this
/// core-lane checkpoint.
pub async fn grant_collaborator(pool: &Pool, repo_id: Uuid, tenant_id: Uuid, user_id: Uuid, role: &str) -> Result<()> {
    pool.get()
        .await?
        .execute(
            "INSERT INTO repository_collaborators(repository_id,tenant_id,user_id,role)
             VALUES($1,$2,$3,$4)",
            &[&repo_id, &tenant_id, &user_id, &role],
        )
        .await?;
    Ok(())
}

pub async fn serving_collaborator(
    pool: &Pool,
    repo_id: Uuid,
    tenant_id: Uuid,
    role: &str,
    label: &str,
) -> Result<db::Identity> {
    let identity = serving_actor(pool, label).await?;
    grant_collaborator(pool, repo_id, tenant_id, identity.id, role).await?;
    Ok(identity)
}

pub async fn set_collaborator_role(pool: &Pool, repo_id: Uuid, user_id: Uuid, role: &str) -> Result<()> {
    let changed = pool
        .get()
        .await?
        .execute(
            "UPDATE repository_collaborators SET role=$3,version=version+1,updated_at=clock_timestamp()
             WHERE repository_id=$1 AND user_id=$2",
            &[&repo_id, &user_id, &role],
        )
        .await?;
    ensure!(changed == 1, "collaborator role update changed {changed} rows");
    Ok(())
}

pub async fn revoke_scope(pool: &Pool, identity: &db::Identity, repo_id: Uuid) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let removed = rootyard::token_scopes::revoke_repository_scope(&tx, identity.token_id, identity.id, repo_id).await?;
    ensure!(removed, "restricted token scope was not present");
    tx.commit().await?;
    Ok(())
}

/// Provision one actual ready `pg_refstore` repository through the production
/// serving path. No GitFS directory or forged ready row is created.
pub async fn provision_serving(
    pool: &Pool,
    actor: &db::Identity,
    store: &BlobStore,
    name: &str,
) -> Result<db::Repository> {
    let receipt = provision(
        pool,
        actor,
        ProvisionRequest { owner: None, name: name.to_owned(), object_format: GitObjectFormat::Sha1 },
        store.backend_identity(),
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("serving provision failed: {error}"))?;
    ensure!(receipt.created, "serving provision unexpectedly replayed");
    ensure!(
        receipt.repository.storage_backend == "pg_refstore" && receipt.repository.state == "ready",
        "provisioned repository is not ready pg_refstore"
    );
    Ok(receipt.repository)
}

pub struct Db {
    admin: Pool,
    pub pool: Pool,
    url: String,
    schema: String,
    /// Only the random schema created by `setup` belongs to this fixture.
    /// `setup_public` binds an existing run-owned database and must never drop
    /// its `public` schema; the caller drops that whole database instead.
    owns_schema: bool,
}

impl Db {
    /// The actual connection URL this fixture opened (never a credential of the
    /// process: it is the caller-supplied `ROOTYARD_TEST_DATABASE_URL`).
    pub fn database_url(&self) -> String {
        self.url.clone()
    }

    /// The random schema every pool of this fixture is bound to.
    pub fn schema(&self) -> &str {
        &self.schema
    }
}

impl Db {
    pub async fn setup() -> Result<Self> {
        let url = database_url();
        let admin = db::pool(&url)?;
        let schema = format!("retention_root_test_{}", Uuid::new_v4().simple());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
        let pool = pool_for(&url, &schema, 16, None)?;
        db::migrate(&pool).await?;
        let client = pool.get().await?;
        // The serving lane reads the production `public.cluster_authority` row.
        // The random fixture schema owns all other tables, so ensure this one
        // production-shaped singleton exists without replacing any existing row.
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS public.cluster_authority (
                     singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
                     incarnation UUID NOT NULL DEFAULT gen_random_uuid(),
                     rotated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
                 );
                 INSERT INTO public.cluster_authority(singleton) VALUES(true) ON CONFLICT DO NOTHING;",
            )
            .await?;
        let installed: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=144)
                    AND to_regclass('ref_store_core_root_heads') IS NOT NULL
                    AND to_regclass('ref_store_core_roots') IS NOT NULL
                    AND to_regclass('ref_store_core_root_refs') IS NOT NULL
                    AND to_regclass('ref_store_core_root_oids') IS NOT NULL
                    AND to_regclass('ref_store_core_root_packs') IS NOT NULL
                    AND to_regclass('ref_store_core_root_tombstones') IS NOT NULL
                    AND to_regclass('ref_store_core_root_receipts') IS NOT NULL
                    AND to_regclass('ref_store_core_root_repo_usage') IS NOT NULL
                    AND to_regclass('ref_store_core_root_tenant_usage') IS NOT NULL
                    AND to_regclass('ref_store_core_protocol_repos') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_snapshot_history') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        ensure!(installed, "db::migrate did not install migration 144 or its real roots tables");
        drop(client);
        Ok(Self { admin, pool, url, schema, owns_schema: true })
    }

    /// Bind the *existing* run-owned database's `public` schema instead of
    /// creating a random fixture schema.
    ///
    /// The format22 paired drill creates a fresh run-owned database, migrates
    /// it in `public` with the product migrator, and then runs this seed helper.
    /// The product backup source validator reads explicit `public.*` tables, so
    /// a random `search_path` schema would hide every seeded row. This mode
    /// therefore migrates and verifies `public` only. It never creates or owns a
    /// schema; `teardown` never drops `public`, and the harness drops the whole
    /// dedicated database.
    pub async fn setup_public() -> Result<Self> {
        let url = database_url();
        let admin = db::pool(&url)?;
        let schema = "public".to_owned();
        let pool = pool_for(&url, &schema, 16, None)?;
        db::migrate(&pool).await?;
        let client = pool.get().await?;
        let active: Option<String> = client.query_one("SELECT current_schema()", &[]).await?.get(0);
        ensure!(
            active.as_deref() == Some(schema.as_str()),
            "the run-owned database's public schema is not the fixture search_path"
        );
        let installed: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=147)
                    AND to_regclass('public.ref_store_core_protocol_repos') IS NOT NULL
                    AND to_regclass('public.ref_store_core_root_heads') IS NOT NULL
                    AND to_regclass('public.ref_store_core_roots') IS NOT NULL
                    AND to_regclass('public.ref_store_core_root_refs') IS NOT NULL
                    AND to_regclass('public.ref_store_core_root_oids') IS NOT NULL
                    AND to_regclass('public.ref_store_core_root_packs') IS NOT NULL
                    AND to_regclass('public.ref_store_core_root_tombstones') IS NOT NULL
                    AND to_regclass('public.ref_store_core_root_receipts') IS NOT NULL
                    AND to_regclass('public.ref_store_core_root_repo_usage') IS NOT NULL
                    AND to_regclass('public.ref_store_core_root_tenant_usage') IS NOT NULL
                    AND to_regclass('public.ref_store_core_pack_snapshot_history') IS NOT NULL
                    AND to_regclass('public.ref_store_core_serving_reads') IS NOT NULL
                    AND to_regclass('public.ref_store_core_serving_read_refs') IS NOT NULL
                    AND to_regclass('public.ref_store_core_serving_read_packs') IS NOT NULL
                    AND to_regclass('public.ref_store_core_serving_read_artifacts') IS NOT NULL
                    AND to_regclass('public.ref_store_core_serving_read_repo_usage') IS NOT NULL
                    AND to_regclass('public.ref_store_core_serving_read_tenant_usage') IS NOT NULL
                    AND to_regclass('public.ref_store_serving_operations') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        ensure!(
            installed,
            "the run-owned database's public schema lacks migration 147, its roots tables or its serving-read tables"
        );
        drop(client);
        Ok(Self { admin, pool, url, schema, owns_schema: false })
    }

    pub fn new_pool(&self, max: usize) -> Result<Pool> {
        pool_for(&self.url, &self.schema, max, None)
    }

    pub async fn teardown(&self) -> Result<()> {
        if !self.owns_schema {
            ensure!(self.schema == "public", "the fixture is bound to a schema it does not own");
            // The whole dedicated run-owned database is dropped by the harness;
            // this fixture only ever owns the random schema `setup` created.
            return Ok(());
        }
        ensure!(self.schema != "public", "refusing to drop the run-owned database's public schema");
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

    /// One trusted user (also tenant/repository owner) and one isolated,
    /// explicitly provisioning gitfs repository.
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

pub async fn cluster_incarnation(pool: &Pool) -> Result<Uuid> {
    Ok(pool
        .get()
        .await?
        .query_one("SELECT incarnation FROM public.cluster_authority WHERE singleton=true", &[])
        .await?
        .get(0))
}

pub async fn set_cluster_incarnation(pool: &Pool, incarnation: Uuid) -> Result<()> {
    let changed = pool
        .get()
        .await?
        .execute(
            "UPDATE public.cluster_authority SET incarnation=$1, rotated_at=clock_timestamp()
             WHERE singleton=true",
            &[&incarnation],
        )
        .await?;
    ensure!(changed == 1, "cluster authority restore changed {changed} rows");
    Ok(())
}

/// Rotate the real cluster authority row inside this fixture schema. This is a
/// test-only SQL mutation of the dedicated cluster fixture, not a product path.
pub async fn rotate_cluster(pool: &Pool) -> Result<Uuid> {
    let row = pool
        .get()
        .await?
        .query_one(
            "UPDATE public.cluster_authority SET incarnation=gen_random_uuid(), rotated_at=clock_timestamp()
             WHERE singleton=true RETURNING incarnation",
            &[],
        )
        .await?;
    let incarnation: Uuid = row.get(0);
    ensure!(!incarnation.is_nil(), "rotated cluster incarnation is nil");
    Ok(incarnation)
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
    let row = pool
        .get()
        .await?
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
    let row = pool
        .get()
        .await?
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
    let row = pool
        .get()
        .await?
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
    let row = pool
        .get()
        .await?
        .query_opt("SELECT roots_revision FROM ref_store_core_protocol_repos WHERE repository_id=$1", &[&repo])
        .await?;
    Ok(row.map(|r| r.get(0)))
}

/// Wait on the actual database clock (never a mutated `expires_at` value) until
/// the named pin is expired.
pub async fn wait_pin_expired(pool: &Pool, pin_id: Uuid) -> Result<()> {
    let started = std::time::Instant::now();
    loop {
        let row = pool
            .get()
            .await?
            .query_opt("SELECT expires_at <= clock_timestamp() FROM ref_store_core_pins WHERE pin_id=$1", &[&pin_id])
            .await?;
        if row.is_none() {
            return Err(anyhow!("source pin disappeared before it expired"));
        }
        if row.expect("pin row").get::<_, bool>(0) {
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(15) {
            return Err(anyhow!("source pin did not expire on the actual database clock"));
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}
