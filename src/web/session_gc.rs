//! Bounded background garbage collection for expired browser sessions.
//!
//! Only `browser` child tokens (and their CSRF-bound `web_sessions` rows) are
//! ever deleted. Every cycle is a fixed-size, oldest-first batch under a strict
//! server-side statement timeout: session rows first, then child tokens whose
//! expiry is already past retention and that no durable foreign-key root still
//! references. API/operator tokens, active sessions, and immediately expired
//! sessions stay untouched. The parent API token id is only encoded in the
//! cookie-held session secret; no parent/child SQL column exists, so this
//! cleanup never invents one. After parent revocation, each child expires
//! within 12 hours and is then eligible for another retention period, which
//! bounds cleanup after a parent revocation without touching admission checks.
use deadpool_postgres::Pool;
use std::{
    env,
    sync::{Arc, OnceLock, atomic::Ordering},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

/// Fixed maximum rows deleted per statement per cycle. The bound is not
/// configurable so a hostile or mistaken deployment cannot widen one lock scope.
pub const BATCH_LIMIT: i64 = 128;
/// Default cadence of one full GC cycle; overridable for bounded local drills.
pub const DEFAULT_INTERVAL_SECONDS: u64 = 60;
/// Default retention after expiry before any row becomes deletion input.
pub const DEFAULT_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
/// Server-side bound for a single GC statement.
pub const STATEMENT_TIMEOUT_MS: u64 = 5_000;

/// One bounded GC cycle's committed row counts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Purged {
    pub sessions: u64,
    pub tokens: u64,
}

/// Operator-tunable, validated GC cadence and retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub retention_seconds: i64,
}

impl Policy {
    /// Explicit opt-in knobs only. Retention of zero means "as soon as the row
    /// is expired", which still never touches an unexpired row.
    pub fn from_env() -> anyhow::Result<Self> {
        let enabled = match env::var("ROOTYARD_SESSION_GC") {
            Ok(value) if value == "true" => true,
            Ok(value) if value == "false" => false,
            Ok(_) => anyhow::bail!("ROOTYARD_SESSION_GC must be true or false"),
            Err(_) => true,
        };
        let interval_seconds = number("ROOTYARD_SESSION_GC_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS)?;
        anyhow::ensure!(interval_seconds > 0, "ROOTYARD_SESSION_GC_INTERVAL_SECONDS must be positive");
        let retention_seconds = signed("ROOTYARD_SESSION_GC_RETENTION_SECONDS", DEFAULT_RETENTION_SECONDS)?;
        anyhow::ensure!(retention_seconds >= 0, "ROOTYARD_SESSION_GC_RETENTION_SECONDS must not be negative");
        Ok(Self { enabled, interval_seconds, retention_seconds })
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_seconds)
    }
}

fn number(name: &str, default: u64) -> anyhow::Result<u64> {
    match env::var(name) {
        Ok(value) => value.parse().map_err(|_| anyhow::anyhow!("invalid {name}")),
        Err(_) => Ok(default),
    }
}

fn signed(name: &str, default: i64) -> anyhow::Result<i64> {
    match env::var(name) {
        Ok(value) => value.parse().map_err(|_| anyhow::anyhow!("invalid {name}")),
        Err(_) => Ok(default),
    }
}

/// Bounded, monotonic counter state. It has no label cardinality and can be
/// sampled from the metrics surface without changing this module.
#[derive(Debug, Default)]
pub struct Counters {
    cycles: std::sync::atomic::AtomicU64,
    session_rows: std::sync::atomic::AtomicU64,
    tokens: std::sync::atomic::AtomicU64,
    failures: std::sync::atomic::AtomicU64,
}

/// Immutable point-in-time counter sample.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub cycles: u64,
    pub session_rows_deleted: u64,
    pub tokens_deleted: u64,
    pub failures: u64,
}

impl Counters {
    fn add(&self, purged: Purged) {
        self.cycles.fetch_add(1, Ordering::Relaxed);
        self.session_rows.fetch_add(purged.sessions, Ordering::Relaxed);
        self.tokens.fetch_add(purged.tokens, Ordering::Relaxed);
    }

    fn failed(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            cycles: self.cycles.load(Ordering::Relaxed),
            session_rows_deleted: self.session_rows.load(Ordering::Relaxed),
            tokens_deleted: self.tokens.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
        }
    }
}

static COUNTERS: OnceLock<Arc<Counters>> = OnceLock::new();

/// Process-wide bounded counters shared by every embedded GC loop.
pub fn counters() -> Arc<Counters> {
    COUNTERS.get_or_init(|| Arc::new(Counters::default())).clone()
}

/// Run one cycle every fixed interval until cancellation, then return. The
/// caller awaits this task, so scoped work never outlives shutdown.
pub async fn run(pool: Pool, stop: CancellationToken) {
    let policy = match Policy::from_env() {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("rootyard: browser-session GC disabled: {error}");
            return;
        }
    };
    if !policy.enabled {
        eprintln!("rootyard: browser-session GC disabled by configuration");
        return;
    }
    eprintln!(
        "rootyard: browser-session GC every {}s with {}s retention (batch {BATCH_LIMIT})",
        policy.interval_seconds, policy.retention_seconds
    );
    loop {
        if stop.is_cancelled() {
            return;
        }
        match purge_once(&pool, policy.retention_seconds).await {
            Ok(purged) => counters().add(purged),
            Err(error) => {
                counters().failed();
                eprintln!("rootyard: browser-session GC cycle failed: {error:#}");
            }
        }
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(policy.interval()) => {}
        }
    }
}

/// One bounded cycle: expired session rows, then unreferenced expired tokens.
pub async fn purge_once(pool: &Pool, retention_seconds: i64) -> anyhow::Result<Purged> {
    anyhow::ensure!(
        retention_seconds >= 0,
        "retention_seconds must not be negative; a negative retention would move the expiry cutoff into the future"
    );
    let sessions = purge_sessions(pool, retention_seconds).await?;
    let tokens = purge_tokens(pool, retention_seconds).await?;
    Ok(Purged { sessions, tokens })
}

fn timeout_sql() -> String {
    format!("SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT_MS}ms'; SET LOCAL lock_timeout = '2000ms'")
}

const SESSION_DELETE: &str = "\
WITH expired AS (\
    SELECT s.token_id FROM web_sessions s JOIN tokens t ON t.id = s.token_id \
    WHERE t.kind = 'browser' AND t.expires_at IS NOT NULL \
      AND t.expires_at < clock_timestamp() - ($1::bigint * interval '1 second') \
      AND s.expires_at < clock_timestamp() - ($1::bigint * interval '1 second') \
    ORDER BY s.expires_at, s.token_id LIMIT $2 FOR UPDATE OF s SKIP LOCKED\
) \
DELETE FROM web_sessions w USING expired e WHERE w.token_id = e.token_id";

const TOKEN_DELETE: &str = "\
WITH expired AS (\
    SELECT t.id FROM tokens t \
    WHERE t.kind = 'browser' AND t.expires_at IS NOT NULL \
      AND t.expires_at < clock_timestamp() - ($1::bigint * interval '1 second') \
      AND NOT EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id = t.id) \
      AND NOT EXISTS (SELECT 1 FROM git_operations o WHERE o.token_id = t.id) \
      AND NOT EXISTS (SELECT 1 FROM git_ref_admissions a WHERE a.token_id = t.id) \
      AND NOT EXISTS (SELECT 1 FROM ci_checkout_jobs j WHERE j.issuer_token_id = t.id) \
      AND NOT EXISTS (SELECT 1 FROM ci_checkout_delegations d WHERE d.issuer_token_id = t.id) \
      AND NOT EXISTS (SELECT 1 FROM cluster_operator_tokens c WHERE c.token_id = t.id) \
    ORDER BY t.expires_at, t.id LIMIT $2 FOR UPDATE SKIP LOCKED\
) \
DELETE FROM tokens t USING expired e \
WHERE t.id = e.id AND t.kind = 'browser' AND t.expires_at IS NOT NULL \
  AND t.expires_at < clock_timestamp() - ($1::bigint * interval '1 second') \
  AND NOT EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id = t.id) \
  AND NOT EXISTS (SELECT 1 FROM git_operations o WHERE o.token_id = t.id) \
  AND NOT EXISTS (SELECT 1 FROM git_ref_admissions a WHERE a.token_id = t.id) \
  AND NOT EXISTS (SELECT 1 FROM ci_checkout_jobs j WHERE j.issuer_token_id = t.id) \
  AND NOT EXISTS (SELECT 1 FROM ci_checkout_delegations d WHERE d.issuer_token_id = t.id) \
  AND NOT EXISTS (SELECT 1 FROM cluster_operator_tokens c WHERE c.token_id = t.id)";

async fn purge_sessions(pool: &Pool, retention_seconds: i64) -> anyhow::Result<u64> {
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    transaction.batch_execute(&timeout_sql()).await?;
    let affected = transaction.execute(SESSION_DELETE, &[&retention_seconds, &BATCH_LIMIT]).await?;
    transaction.commit().await?;
    Ok(affected)
}

async fn purge_tokens(pool: &Pool, retention_seconds: i64) -> anyhow::Result<u64> {
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    transaction.batch_execute(&timeout_sql()).await?;
    let affected = transaction.execute(TOKEN_DELETE, &[&retention_seconds, &BATCH_LIMIT]).await.map_err(|error| {
        if error.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) {
            anyhow::anyhow!(
                "unexpected foreign-key reference blocks expired browser-token GC; \
                     extend the reference-preservation probe and its index instead of \
                     widening a cascading delete: {error}"
            )
        } else {
            anyhow::anyhow!(error)
        }
    })?;
    transaction.commit().await?;
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn purge_once_rejects_negative_retention_before_touching_the_pool() {
        // The pool is built but never connects; reaching SQL would surface a
        // connection error instead of the retention validation message.
        let manager = deadpool_postgres::Manager::from_config(
            tokio_postgres::Config::new(),
            tokio_postgres::NoTls,
            deadpool_postgres::ManagerConfig::default(),
        );
        let pool = Pool::builder(manager).max_size(1).build().expect("pool builds without connecting");
        let error = purge_once(&pool, -1).await.expect_err("negative retention must be rejected");
        assert!(error.to_string().contains("retention_seconds must not be negative"), "unexpected error: {error:#}");
    }

    #[test]
    fn counters_are_monotonic_and_bounded() {
        let counters = Counters::default();
        counters.add(Purged { sessions: 3, tokens: 2 });
        counters.add(Purged { sessions: 1, tokens: 0 });
        counters.failed();
        assert_eq!(
            counters.snapshot(),
            CounterSnapshot { cycles: 2, session_rows_deleted: 4, tokens_deleted: 2, failures: 1 }
        );
    }

    #[test]
    fn migration133_indexes_cover_the_full_fk_probe_columns() {
        // Source contract for the catalog fixture: each index must lead with the
        // exact columns the GC reference probes use, not merely carry the name.
        const MIGRATION: &str = include_str!("../../migrations/133_browser_session_gc_indexes.sql");
        let expected = [
            ("git_operations_token_actor_idx", "ON git_operations (token_id, actor_id)"),
            ("git_ref_admissions_token_actor_idx", "ON git_ref_admissions (token_id, actor_id)"),
            ("ci_checkout_jobs_issuer_token_idx", "ON ci_checkout_jobs (issuer_token_id)"),
            ("ci_checkout_delegations_issuer_token_idx", "ON ci_checkout_delegations (issuer_token_id)"),
            ("web_sessions_expiry_token_idx", "ON web_sessions (expires_at, token_id)"),
            ("tokens_browser_expiry_idx", "ON tokens (expires_at, id) WHERE kind = 'browser'"),
        ];
        assert_eq!(MIGRATION.matches("CREATE INDEX").count(), expected.len());
        for (name, columns) in expected {
            assert!(MIGRATION.contains(name), "missing index {name}");
            assert!(MIGRATION.contains(columns), "index {name} does not lead with {columns}");
        }
    }
}
