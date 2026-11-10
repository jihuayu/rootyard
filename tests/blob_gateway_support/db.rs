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
use zeroize::Zeroizing;

const OP_SECONDS: u64 = 120;

pub fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(OP_SECONDS)
}

pub fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set for the blob_git_gateway suite")
}

/// The exact server options every fixture pool runs under.
fn fixture_options(schema: &str) -> String {
    format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000")
}

pub fn pool_for(url: &str, schema: &str, max: usize) -> Result<Pool> {
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(fixture_options(schema));
    Ok(Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(max)
        .build()?)
}

/// Percent-encode one query component the way PostgreSQL URL parsing (the
/// `url` crate) decodes it: everything except unreserved bytes.
fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Decode one percent-encoded query component; `+` stays literal, as in a URL
/// query. An undecodable escape is refused without echoing the input.
fn decode_component(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3).and_then(|pair| std::str::from_utf8(pair).ok());
            let byte = hex.and_then(|hex| u8::from_str_radix(hex, 16).ok());
            out.push(byte.ok_or_else(|| anyhow::anyhow!("database URL has an undecodable query component"))?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| anyhow::anyhow!("database URL has an undecodable query component"))
}

/// A `DATABASE_URL` for a child service: the configured database with every one
/// of its parameters plus this fixture's `options` (`search_path` to the random
/// schema, UTC, the same statement/lock bounds as [`pool_for`]).
///
/// PostgreSQL refuses a repeated `options`, so a URL that already carries one
/// (decoded, case-insensitive) is refused instead of being silently overridden.
/// Every other parameter, including `hostaddr` and `target_session_attrs`, is
/// preserved verbatim and in order. The result and its password are never
/// printed.
pub fn service_url(url: &str, schema: &str) -> Result<String> {
    let encoded = encode_component(&fixture_options(schema));
    // A fragment (unused by PostgreSQL connection URLs) stays last if present.
    let (head, fragment) = url.split_once('#').map_or((url, ""), |(head, fragment)| (head, fragment));
    let fragment = if fragment.is_empty() { String::new() } else { format!("#{fragment}") };
    let Some((base, query)) = head.split_once('?') else {
        return Ok(format!("{head}?options={encoded}{fragment}"));
    };
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let key = pair.split_once('=').map_or(pair, |(key, _)| key);
        ensure!(
            !decode_component(key)?.trim_end_matches('\\').eq_ignore_ascii_case("options"),
            "database URL already carries an options parameter; refusing to override it"
        );
    }
    Ok(format!("{base}?options={encoded}&{query}{fragment}"))
}

pub struct Db {
    admin: Pool,
    pub pool: Pool,
    /// The configured database URL; it may carry a password, is wiped when the
    /// fixture drops and is never shown.
    url: Zeroizing<String>,
    schema: String,
}

impl Db {
    /// A `DATABASE_URL` for a child service: this fixture's random schema
    /// through [`service_url`]. It may carry a password and is never shown.
    pub fn service_url(&self) -> Result<String> {
        service_url(self.url.as_str(), &self.schema)
    }

    pub async fn setup() -> Result<Self> {
        let url = Zeroizing::new(database_url());
        let admin = db::pool(url.as_str())?;
        let schema = format!("blob_git_gateway_{}", Uuid::new_v4().simple());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
        let pool = pool_for(url.as_str(), &schema, 16)?;
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
        let fixture = Self { admin, pool, url, schema };
        let child_url = fixture.service_url()?;
        let _: tokio_postgres::Config = child_url.parse()?;
        Ok(fixture)
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
