//! Real PostgreSQL fixture for the Blob Git gateway suite.
//!
//! One random schema, the actual `db::migrate` path (migration 144 asserted),
//! real pools and real business rows. A missing variable is a hard failure: no
//! case silently skips when PostgreSQL is absent.
//!
//! The out-of-process service also needs a database and a Blob profile, so both
//! are pinned once for the whole test binary:
//!
//! * PostgreSQL sessions select [`Db::schema`] through `options=-c search_path`.
//!   This fixture appends that selector to the operator's
//!   `ROOTYARD_TEST_DATABASE_URL` exactly once, so every production pool,
//!   teardown session and the launched binary's `DATABASE_URL` resolve to the
//!   same migrated schema and no run migrates or touches the database's default
//!   (probably `public`) schema;
//! * `ROOTYARD_BLOB_ROOT` is a *remote object prefix* (see
//!   `blob_store::config::validate_root`), never a local directory. Each run
//!   pins one random relative prefix that the service and this process share;
//!   `blob` owns deleting exactly the objects below it and `finish` restores
//!   the operator's value.
//!
//! Nothing here logs the database URL: [`redact_database_url`] is the only
//! rendering that may be printed.
use std::sync::OnceLock;

use anyhow::{Result, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::db;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

const OP_SECONDS: u64 = 120;
const ROOT_ENV: &str = "ROOTYARD_BLOB_ROOT";
const URL_ENV: &str = "ROOTYARD_TEST_DATABASE_URL";

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

/// Escape one value for the `application_name` startup parameter, which cannot
/// carry whitespace or a quote.
fn escape_startup_value(value: &str) -> String {
    value.chars().map(|c| if c.is_ascii_graphic() && c != '\\' { c } else { '_' }).collect()
}

/// Render one parsed configuration back to a URL with exactly one `options`
/// parameter. Every other connection parameter the parser retained (`host`,
/// `hostaddr`, `user`, `password`, `dbname`, `sslnegotiation`, `connect_timeout`,
/// `tcp_user_timeout`, `keepalives`, `target_session_attrs`, both channel
/// bindings and `load_balance_hosts`) is written back, so none is silently
/// dropped; it is placed in `server_options` last and therefore wins.
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
    // Only a non-default port list is rendered, so the port never unbalances the
    // host list.
    if !ports.is_empty() && ports.iter().any(|port| *port != 5432) {
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
    if config.get_ssl_negotiation() != tokio_postgres::config::SslNegotiation::Postgres {
        query.push(format!("sslnegotiation={:?}", config.get_ssl_negotiation()).to_ascii_lowercase());
    }
    if let Some(timeout) = config.get_connect_timeout() {
        query.push(format!("connect_timeout={}", timeout.as_secs()));
    }
    if let Some(timeout) = config.get_tcp_user_timeout() {
        query.push(format!("tcp_user_timeout={}", timeout.as_millis()));
    }
    if !config.get_keepalives() {
        query.push("keepalives=0".to_owned());
    }
    if let Some(idle) = config.get_keepalives_idle() {
        query.push(format!("keepalives_idle={}", idle.as_secs()));
    }
    if config.get_keepalives_interval() != Duration::from_secs(0) {
        query.push(format!("keepalives_interval={}", config.get_keepalives_interval().as_secs()));
    }
    if config.get_keepalives_retries() != 0 {
        query.push(format!("keepalives_retries={}", config.get_keepalives_retries()));
    }
    if config.get_channel_binding() != tokio_postgres::config::ChannelBinding::Prefer {
        query.push(format!("channel_binding={:?}", config.get_channel_binding()).to_ascii_lowercase());
    }
    if config.get_target_session_attrs() != tokio_postgres::config::TargetSessionAttrs::Any {
        query.push(format!("target_session_attrs={:?}", config.get_target_session_attrs()).to_ascii_lowercase());
    }
    if config.get_load_balance_hosts() != tokio_postgres::config::LoadBalanceHosts::Disable {
        query.push(format!("load_balance_hosts={:?}", config.get_load_balance_hosts()).to_ascii_lowercase());
    }
    // `hostaddr` has no `Config` setter for a render: it is emitted as a URL
    // parameter, which the parser re-reads exactly as given (empty means unset).
    query.push(format!("application_name={}", escape_startup_value(config.get_application_name().unwrap_or(""))));
    let hostaddr: Vec<String> = config.get_hostaddrs().iter().map(|address| address.to_string()).collect();
    if !hostaddr.is_empty() {
        query.push(format!("hostaddr={}", escape_startup_value(&hostaddr.join(","))));
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
/// `extra` is appended to those selectors, never added as a second `options`.
fn with_search_path(url: &str, schema: &str, extra: Option<&str>) -> Result<String> {
    let (base, mut options) = split_options(url);
    let mut config: tokio_postgres::Config = base.parse()?;
    let mut selector = options.pop().unwrap_or_else(|| config.get_options().unwrap_or("").to_owned());
    if let Some(extra) = extra {
        if !selector.is_empty() {
            selector.push(' ');
        }
        selector.push_str(extra);
    }
    let selector = format!("{selector} -c search_path={schema}");
    config.options(&selector);
    Ok(render_database_url(&config))
}

/// The exact server options every fixture pool runs under.
fn fixture_options(schema: &str) -> String {
    format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000")
}

/// The `options` the pinned run URL carries, decoded.
fn pinned_options(url: &str) -> String {
    let (_, options) = split_options(url);
    options.into_iter().next().and_then(|value| decode_component(&value).ok()).unwrap_or_default()
}

/// A fixture-owned pool on the pinned URL: every parameter of the URL is kept,
/// the pinned selectors and bounds stay in force and this pool's `search_path`
/// is the one supplied.
pub fn pool_for(url: &str, schema: &str, max: usize) -> Result<Pool> {
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(&format!("{} -c search_path={schema}", pinned_options(url)).trim());
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

/// The per-binary fixture environment. This fixture keeps no process-global
/// clean-up hook: a supervisor that terminates the process on a deadline would
/// skip it anyway. Instead, every launch claims a fresh random schema and a
/// fresh random remote prefix, so a killed run can never be reused, and the
/// clean-up the suite does perform is reported through [`Db::teardown`],
/// the [`blob`](super::blob) store and [`finish`].
struct RunEnvironment {
    /// Schema selector included; the launched service receives exactly this as
    /// `DATABASE_URL`.
    database_url: Zeroizing<String>,
    schema: String,
    root: String,
    previous_root: Option<std::ffi::OsString>,
}

impl RunEnvironment {
    fn prepare() -> Result<Self> {
        let url = std::env::var(URL_ENV)
            .map_err(|_| anyhow::anyhow!("{URL_ENV} must be set for the blob_git_gateway suite"))?;
        // The operator's URL may carry a password; it is wiped with the run.
        let url = Zeroizing::new(url);
        // The out-of-process service receives the pinned URL unchanged and
        // adds its own bounded pool settings on top, so the service and this
        // process share one schema and one set of limits.
        let schema = format!("blob_git_gateway_{}", Uuid::new_v4().simple());
        let pinned = Zeroizing::new(with_search_path(url.as_str(), &schema, None)?);
        ensure!(pinned.matches("options=").count() == 1, "the pinned run URL must carry exactly one options parameter");
        let root = format!("blob-gateway-suite/{}", Uuid::new_v4().simple());
        ensure!(!root.starts_with('/') && root.split('/').all(|part| !part.is_empty()), "fixture prefix is relative");
        let previous_root = std::env::var_os(ROOT_ENV);
        // SAFETY: every read of these variables in this test binary goes through
        // this module's `OnceLock`, i.e. strictly after this single write, and
        // `finish` only runs after the suite's only service process exited.
        unsafe {
            std::env::set_var(URL_ENV, pinned.as_str());
            std::env::set_var(ROOT_ENV, &root);
        }
        Ok(Self { database_url: pinned, schema, root, previous_root })
    }

    fn restore(&self) {
        unsafe {
            match &self.previous_root {
                Some(value) => std::env::set_var(ROOT_ENV, value),
                None => std::env::remove_var(ROOT_ENV),
            }
            std::env::remove_var(URL_ENV);
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
pub fn owned_root() -> Result<&'static str> {
    prepare()?;
    Ok(RUN.get().map(|environment| environment.root.as_str()).expect("run environment was just prepared"))
}

/// Put the operator's environment back after the suite's service stopped and
/// its schema and Blob prefix were deleted. Only this test process changes.
pub fn finish() {
    if let Some(environment) = RUN.get() {
        environment.restore();
    }
}

pub struct Db {
    admin: Pool,
    pub pool: Pool,
    /// The pinned run URL (schema selector included, held zeroized); the
    /// launched service gets exactly this value as `DATABASE_URL`.
    url: Zeroizing<String>,
    schema: String,
}

impl Db {
    /// A `DATABASE_URL` for a child service: the already-pinned run URL, which
    /// selects [`Db::schema`]. No `options` is appended again. It may carry a
    /// password and is never shown.
    pub fn service_url(&self) -> &str {
        self.url.as_str()
    }

    /// The run database URL, already selecting [`Db::schema`]; this is what the
    /// launched service receives as `DATABASE_URL`.
    pub fn database_url(&self) -> &str {
        self.url.as_str()
    }

    /// The run-owned schema installed by `db::migrate`.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub async fn setup() -> Result<Self> {
        let schema = prepare()?.to_owned();
        let url = std::env::var(URL_ENV)
            .map(|url| Zeroizing::new(url))
            .map_err(|_| anyhow::anyhow!("{URL_ENV} must be set for the blob_git_gateway suite"))?;
        // Admin sessions bypass the schema selector of the pinned URL, so
        // teardown of one schema can never be redirected by another schema.
        let admin = db::pool(url.as_str())?;
        admin
            .get()
            .await?
            .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
            .await
            .map_err(|error| anyhow::anyhow!("could not create the run schema: {error}"))?;
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
        // The pinned URL already carries exactly one `options`, so the
        // child-service form is that URL; a refusal here is still a hard
        // failure. It must resolve to this run's schema, and appending the
        // selector again must never add a second `options`.
        let child_url = service_url(url.as_str(), &schema)?;
        ensure!(
            child_url == url.as_str(),
            "the pinned run URL must already select the run schema through a single options parameter"
        );
        let child: tokio_postgres::Config = child_url.parse()?;
        ensure!(
            child.get_options().is_some_and(|options| options.contains(&format!("search_path={schema}"))),
            "the pinned run URL must select the run schema"
        );
        let fixture = Self { admin, pool, url, schema };
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
        let pinned = with_search_path(url, "blob_git_gateway_a", None).unwrap();
        assert_eq!(pinned.matches("options=").count(), 1);
        assert!(pinned.contains("search_path%3Dblob_git_gateway_a"));
        assert!(pinned.contains("sslmode=disable"));
        let (base, options) = split_options(url);
        assert_eq!(base, url);
        assert!(options.is_empty());
        let reused = with_search_path(&pinned, "blob_git_gateway_b", None).unwrap();
        assert_eq!(reused.matches("options=").count(), 1);
        assert!(reused.contains("blob_git_gateway_b"));
        assert!(!reused.contains("blob_git_gateway_a"));
    }

    #[test]
    fn pinned_url_keeps_every_parameter_and_service_url_adds_no_options() {
        let url = "postgres://u@127.0.0.1:55433/rootyard?sslmode=disable&\
                   target_session_attrs=read-write&connect_timeout=9&channel_binding=disable&\
                   keepalives_interval=7&keepalives_retries=3&load_balance_hosts=random&application_name=probe";
        let pinned =
            with_search_path(url, "blob_git_gateway_a", Some("-c statement_timeout=1 -c lock_timeout=1")).unwrap();
        assert_eq!(pinned.matches("options=").count(), 1);
        for kept in [
            "sslmode=disable",
            "target_session_attrs=read-write",
            "connect_timeout=9",
            "channel_binding=disable",
            "keepalives_interval=7",
            "keepalives_retries=3",
            "load_balance_hosts=random",
            "application_name=probe",
            "statement_timeout%3D1",
            "search_path%3Dblob_git_gateway_a",
        ] {
            assert!(pinned.contains(kept), "pinned URL dropped {kept}");
        }
        // PostgreSQL refuses a repeated `options`: the pinned URL itself is
        // exactly what a child service receives.
        let refused = service_url(&pinned, "blob_git_gateway_a").unwrap_err();
        assert!(refused.to_string().contains("options"));
    }

    #[test]
    fn service_url_preserves_supported_parameters_and_refuses_options() {
        let url = "postgres://u@127.0.0.1:55433/rootyard?sslmode=disable&connect_timeout=9&application_name=probe";
        let child = service_url(url, "blob_git_gateway_a").unwrap();
        assert_eq!(child.matches("options=").count(), 1);
        for kept in ["sslmode=disable", "connect_timeout=9", "application_name=probe"] {
            assert!(child.contains(kept), "child URL dropped {kept}");
        }
        for malformed in [
            "postgres://u@h/rootyard?options=",
            "postgres://u@h/rootyard?OPTIONS=-c%20search_path%3Dpublic",
            "postgres://u@h/rootyard?options\\=-c%20search_path%3Dpublic",
            "postgres://u@h/rootyard?options=%ZZ",
            "postgres://u@h/rootyard?sslmode=disable&options=-c%20search_path%3Dx",
        ] {
            let error = service_url(malformed, "blob_git_gateway_a").unwrap_err();
            assert!(!error.to_string().contains("search_path"), "refusal echoed the URL");
        }
    }
}
