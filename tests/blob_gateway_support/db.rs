//! Real PostgreSQL fixture for the Blob Git gateway suite.
//!
//! One random schema, the actual `db::migrate` path (migration 144 asserted),
//! real pools and real business rows. A missing variable is a hard failure: no
//! case silently skips when PostgreSQL is absent.
//!
//! The out-of-process service also needs a database and a Blob profile, so both
//! are pinned for the whole test binary:
//!
//! * PostgreSQL sessions select [`Db::schema`] through `options=-c search_path`.
//!   This fixture appends that selector to the operator's
//!   `ROOTYARD_TEST_DATABASE_URL` exactly once, so every production pool,
//!   teardown session and the launched binary's `DATABASE_URL` resolve to the
//!   same migrated schema and no run migrates or touches the database's default
//!   (probably `public`) schema;
//! * `ROOTYARD_BLOB_ROOT` is a *remote object prefix* (see
//!   `blob_store::config::validate_root`), never a local directory. Each run
//!   pins one random relative prefix that the service and this process share,
//!   and [`Drop`] of the owner deletes exactly the objects below it.
use std::sync::OnceLock;

use anyhow::{Result, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::db;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

const OP_SECONDS: u64 = 120;
const ROOT_ENV: &str = "ROOTYARD_BLOB_ROOT";

pub fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(OP_SECONDS)
}

/// A console-safe rendering of a database URL: credentials, host, port and
/// query (which may carry a password or `options`) are all replaced.
pub fn redact_database_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (scheme, rest),
        None => return "<not a database url>".to_owned(),
    };
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let user = authority.split('@').next().unwrap_or_default();
    let user = user.split(':').next().unwrap_or_default();
    let database = tail.split('?').next().unwrap_or_default();
    let user = if user.is_empty() { "<user?>" } else { user };
    format!("{scheme}://{user}@<redacted-host>{database}<redacted-query>")
}

/// Render one parsed configuration back to a URL with exactly one `options`
/// parameter, keeping every other query pair as given.
fn render_database_url(config: &tokio_postgres::Config) -> String {
    let mut target = String::new();
    for host in config.get_hosts() {
        if !target.is_empty() {
            target.push(',');
        }
        match host {
            tokio_postgres::config::Host::Tcp(host) => target.push_str(host),
            tokio_postgres::config::Host::Unix(path) => target.push_str(&path.to_string_lossy()),
        }
    }
    let ports = config.get_ports();
    if ports.iter().any(|port| *port != 5432) {
        target.push(':');
        target.push_str(&ports.iter().map(u16::to_string).collect::<Vec<_>>().join(","));
    }
    let auth = match (config.get_user(), config.get_password()) {
        (Some(user), Some(password)) => {
            format!("{}:{}@", percent(user), percent(std::str::from_utf8(password).unwrap_or_default()))
        }
        (Some(user), None) => format!("{}@", percent(user)),
        _ => String::new(),
    };
    let database = config.get_dbname().map(percent).unwrap_or_default();
    let mut query = Vec::new();
    if let Some(options) = config.get_options() {
        query.push(format!("options={}", percent(options)));
    }
    if config.get_ssl_mode() != tokio_postgres::config::SslMode::Prefer {
        query.push(format!("sslmode={:?}", config.get_ssl_mode()).to_ascii_lowercase());
    }
    let query = if query.is_empty() { String::new() } else { format!("?{}", query.join("&")) };
    format!("postgres://{auth}{target}/{database}{query}")
}

/// Percent-encode everything outside the URL-safe unreserved/structured set.
fn percent(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b' ' | b':') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `(base url without `options`, parsed selector segments)`.
fn split_options(url: &str) -> (String, Vec<String>) {
    let Some((head, query)) = url.split_once('?') else { return (url.to_owned(), Vec::new()) };
    let mut kept = Vec::new();
    let mut options = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        match pair.split_once('=') {
            Some(("options", value)) => options.push(value.to_owned()),
            _ => kept.push(pair.to_owned()),
        }
    }
    let base = if kept.is_empty() { head.to_owned() } else { format!("{head}?{}", kept.join("&")) };
    (base, options)
}

/// Wrapped exactly once: a reused `ROOTYARD_TEST_DATABASE_URL` that already
/// selects a schema contributes its selector instead of a second `options` key.
fn with_search_path(url: &str, schema: &str) -> Result<String> {
    let (base, _) = split_options(url);
    let mut config: tokio_postgres::Config = base.parse()?;
    let options = format!("{} -c search_path={schema}", config.get_options().unwrap_or(""));
    config.options(&options);
    Ok(render_database_url(&config))
}

pub fn pool_for(url: &str, schema: &str, max: usize) -> Result<Pool> {
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!(
        "{} -c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000",
        config.get_options().unwrap_or("")
    ));
    Ok(Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(max)
        .build()?)
}

/// The per-binary fixture environment. This fixture keeps no process-global
/// clean-up hook: a supervisor that terminates the process on a deadline would
/// skip it anyway. Instead, every launch claims a fresh random schema and a
/// fresh random remote prefix, so a killed run can never be reused, and the
/// clean-up the suite does perform is reported through [`Db::teardown`],
/// `db::delete_owned_prefix` and [`finish`].
struct RunEnvironment {
    schema: String,
    root: String,
    previous_root: Option<std::ffi::OsString>,
}

impl RunEnvironment {
    fn prepare() -> Result<Self> {
        let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("ROOTYARD_TEST_DATABASE_URL must be set for the blob_git_gateway suite"))?;
        let schema = format!("blob_git_gateway_{}", Uuid::new_v4().simple());
        let pinned = with_search_path(&url, &schema)?;
        let root = format!("blob-gateway-suite/{}", Uuid::new_v4().simple());
        ensure!(!root.starts_with('/') && root.split('/').all(|part| !part.is_empty()), "fixture prefix is relative");
        let previous_root = std::env::var_os(ROOT_ENV);
        // SAFETY: every read of these variables in this test binary goes through
        // this module's `OnceLock`, i.e. strictly after this single write, and
        // `finish` only runs after the suite's only service process exited.
        unsafe {
            std::env::set_var("ROOTYARD_TEST_DATABASE_URL", &pinned);
            std::env::set_var(ROOT_ENV, &root);
        }
        Ok(Self { schema, root, previous_root })
    }

    fn restore(&self) {
        unsafe {
            match &self.previous_root {
                Some(value) => std::env::set_var(ROOT_ENV, value),
                None => std::env::remove_var(ROOT_ENV),
            }
            std::env::remove_var("ROOTYARD_TEST_DATABASE_URL");
        }
    }
}

static RUN: OnceLock<RunEnvironment> = OnceLock::new();

/// Pin the run environment (idempotent) and return its schema.
pub fn prepare() -> Result<&'static str> {
    let environment = RUN.get_or_init(|| {
        RunEnvironment::prepare()
            .unwrap_or_else(|error| panic!("blob_git_gateway fixture environment cannot be prepared: {error:#}"))
    });
    Ok(&environment.schema)
}

/// The remote object prefix this run owns.
#[allow(dead_code)] // Blob-prefix clean-up lands with the storage fixture.
pub fn owned_root() -> Result<&'static str> {
    prepare()?;
    Ok(RUN.get().map(|environment| environment.root.as_str()).expect("run environment was just prepared"))
}

/// Put the operator's environment back after the suite's service stopped and
/// its schema and Blob prefix were deleted. Only this test process changes.
#[allow(dead_code)] // Called when the storage fixture lands.
pub fn finish() {
    if let Some(environment) = RUN.get() {
        environment.restore();
    }
}

pub struct Db {
    admin: Pool,
    pub pool: Pool,
    schema: String,
    /// The pinned run URL (schema selector included); the launched service gets
    /// exactly this value as `DATABASE_URL`.
    #[allow(dead_code)] // Consumed by the service fixture.
    url: String,
}

impl Db {
    pub async fn setup() -> Result<Self> {
        let schema = prepare()?.to_owned();
        let url = std::env::var("ROOTYARD_TEST_DATABASE_URL").expect("run environment was just prepared");
        // Admin sessions bypass the schema selector of the pinned URL, so
        // teardown of one schema can never be redirected by another schema.
        let admin = db::pool(&url)?;
        admin
            .get()
            .await?
            .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
            .await
            .map_err(|error| anyhow::anyhow!("could not create the run schema: {error}"))?;
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
        Ok(Self { admin, pool, schema, url })
    }

    /// The run database URL, already selecting [`Db::schema`]; this is what the
    /// launched service receives as `DATABASE_URL`.
    pub fn database_url(&self) -> &str {
        &self.url
    }

    /// The run-owned schema installed by `db::migrate`.
    pub fn schema(&self) -> &str {
        &self.schema
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_never_echoes_credentials_host_or_query() {
        let url = "postgres://alice:s3cret-value@db.internal.example:55433/rootyard?sslmode=require&password=pw";
        let redacted = redact_database_url(url);
        for secret in ["s3cret-value", "db.internal.example", "55433", "password", "sslmode"] {
            assert!(!redacted.contains(secret), "redaction leaked {secret}: {redacted}");
        }
        assert!(redacted.starts_with("postgres://alice@"));
        assert!(redacted.ends_with("/rootyard<redacted-query>"));
    }

    #[test]
    fn search_path_is_appended_once_and_keeps_other_parameters() {
        let url = "postgres://u@127.0.0.1:55433/rootyard?sslmode=disable";
        let pinned = with_search_path(url, "blob_git_gateway_a").unwrap();
        assert_eq!(pinned.matches("options=").count(), 1);
        assert!(pinned.contains("search_path%3Dblob_git_gateway_a"));
        assert!(pinned.contains("sslmode=disable"));
        let (base, options) = split_options(url);
        assert_eq!(base, url);
        assert!(options.is_empty());
        let reused = with_search_path(&pinned, "blob_git_gateway_b").unwrap();
        assert_eq!(reused.matches("options=").count(), 1);
        assert!(reused.contains("blob_git_gateway_b"));
        assert!(!reused.contains("blob_git_gateway_a"));
    }
}
