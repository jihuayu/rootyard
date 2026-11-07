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
//!
//! The token pass is bounded in *inspected* rows as well as deleted rows: one
//! `MATERIALIZED` candidate window of at most 128 expired `browser` tokens is
//! taken in `(expires_at, id)` index order and locked, and only those 128 rows
//! are probed against the six durable reference roots. A bounded keyset cursor
//! over that same index order walks the remaining candidates on later cycles
//! and wraps back to the head once the scan reaches the end, so a large
//! permanently referenced prefix can never pin a cycle on the same rows.
use deadpool_postgres::Pool;
use std::{
    env,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Fixed maximum rows deleted (and inspected) per statement per cycle. The
/// bound is not configurable so a hostile or mistaken deployment cannot widen
/// one lock scope.
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

/// Bounded, saturating counter state. It has no label cardinality and the
/// metrics surface samples this one counter set through `snapshot()`. Values
/// reset on process restart and are held at `u64::MAX` instead of wrapping.
#[derive(Debug, Default)]
pub struct Counters {
    cycles: AtomicU64,
    session_rows: AtomicU64,
    tokens: AtomicU64,
    failures: AtomicU64,
}

/// Saturating increment shared by every counter. A plain `fetch_add` would wrap
/// past `u64::MAX` and a wrapped value reads as a decrease, so the update is a
/// compare-exchange loop on `saturating_add` (valid on the declared MSRV).
fn bump(value: &AtomicU64, amount: u64) {
    let mut current = value.load(Ordering::Relaxed);
    loop {
        match value.compare_exchange_weak(current, current.saturating_add(amount), Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
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
    /// Record rows whose deletion transaction is already committed. It is
    /// called at each pass boundary, not once per cycle: a session pass can
    /// commit and be counted before a later token pass fails, while a
    /// successful cycle passes its newly committed rows here exactly once.
    fn deleted(&self, purged: Purged) {
        bump(&self.session_rows, purged.sessions);
        bump(&self.tokens, purged.tokens);
    }

    /// Record one completed cycle. Only a cycle whose both passes committed
    /// increments this, so a failed attempt is never also counted as a cycle.
    fn completed(&self) {
        bump(&self.cycles, 1);
    }

    fn failed(&self) {
        bump(&self.failures, 1);
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

/// Bounded keyset position over the `(expires_at, id)` order of the
/// `tokens_browser_expiry_idx` browser index. It holds two scalars only — never
/// a global row set — and is advanced only after a batch commits, so a failed
/// or rolled-back cycle retries the same position and a process restart simply
/// begins again at the head.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TokenCursor {
    position: Option<(String, Uuid)>,
}

/// Run one cycle every fixed interval until cancellation, then return. The
/// caller awaits this task, so scoped work never outlives shutdown. The keyset
/// cursor lives here, so the background loop walks forward across cycles
/// instead of restating the oldest window on every cycle.
pub async fn run(pool: Pool, stop: CancellationToken) {
    let policy = match Policy::from_env() {
        Ok(policy) => policy,
        Err(error) => {
            // Configuration messages name only the fixed environment variables.
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
    let counters = counters();
    let mut cursor = TokenCursor::default();
    loop {
        if stop.is_cancelled() {
            return;
        }
        match purge_cycle(&pool, policy.retention_seconds, &mut cursor, &counters).await {
            Ok(_) => counters.completed(),
            Err(error) => {
                counters.failed();
                // Route through the shared classification surface: only a fixed
                // kind, the validated SQLSTATE and request correlation are
                // recorded, never database text, URLs or row content.
                let classified = crate::Error::internal(error);
                eprintln!("rootyard: browser-session GC cycle failed: {} {}", classified.0.as_u16(), classified.1);
            }
        }
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(policy.interval()) => {}
        }
    }
}

/// One bounded cycle from the head of the expiry order: expired session rows,
/// then unreferenced expired tokens. Kept as a single-batch entry point; the
/// background loop uses the same internals with its own advancing cursor.
///
/// A direct caller records the rows each pass really committed, through the
/// same process counter set as the loop, so its deletions are observable and
/// explainable. Only [`run`] additionally records completed cycles and failed
/// attempts, because those describe loop iterations rather than one call.
pub async fn purge_once(pool: &Pool, retention_seconds: i64) -> anyhow::Result<Purged> {
    let mut cursor = TokenCursor::default();
    let counters = counters();
    purge_cycle(pool, retention_seconds, &mut cursor, &counters).await
}

/// Two independent short transactions. Each pass's committed row count is
/// added to `counters` immediately after that pass's `COMMIT` and before the
/// next pass can fail, so a committed session deletion is never lost when the
/// token pass fails. A successful pass is not added again by the caller, and
/// the cycle itself is recorded only by [`run`] after this returns `Ok`.
async fn purge_cycle(
    pool: &Pool,
    retention_seconds: i64,
    cursor: &mut TokenCursor,
    counters: &Counters,
) -> anyhow::Result<Purged> {
    anyhow::ensure!(
        retention_seconds >= 0,
        "retention_seconds must not be negative; a negative retention would move the expiry cutoff into the future"
    );
    let sessions = purge_sessions(pool, retention_seconds).await?;
    // purge_sessions returns only after COMMIT, so these rows are durable even
    // if the token pass below fails and this attempt counts as a failure.
    counters.deleted(Purged { sessions, tokens: 0 });
    let tokens = purge_tokens(pool, retention_seconds, cursor).await?;
    counters.deleted(Purged { sessions: 0, tokens });
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

/// Fixed first-window branch: no keyset bound, so the partial browser index on
/// `(expires_at, id)` serves the ordered `LIMIT`. `LIMIT` sits inside the
/// `MATERIALIZED` candidate CTE, ahead of every reference probe, so one cycle
/// never scans more than `BATCH_LIMIT` expired tokens.
const TOKEN_DELETE_FIRST: &str = r#"WITH candidates AS MATERIALIZED (
    SELECT t.id, t.expires_at, t.expires_at::text AS expires_at_text
    FROM tokens t
    WHERE t.kind = 'browser' AND t.expires_at IS NOT NULL
      AND t.expires_at < statement_timestamp() - ($1::bigint * interval '1 second')
    ORDER BY t.expires_at, t.id
    LIMIT $2
    FOR UPDATE SKIP LOCKED
),
purged AS (
    DELETE FROM tokens t
    USING (
        SELECT c.id FROM candidates c
        WHERE NOT EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id = c.id)
          AND NOT EXISTS (SELECT 1 FROM git_operations o WHERE o.token_id = c.id)
          AND NOT EXISTS (SELECT 1 FROM git_ref_admissions a WHERE a.token_id = c.id)
          AND NOT EXISTS (SELECT 1 FROM ci_checkout_jobs j WHERE j.issuer_token_id = c.id)
          AND NOT EXISTS (SELECT 1 FROM ci_checkout_delegations d WHERE d.issuer_token_id = c.id)
          AND NOT EXISTS (SELECT 1 FROM cluster_operator_tokens k WHERE k.token_id = c.id)
    ) e
    WHERE t.id = e.id
      AND t.kind = 'browser' AND t.expires_at IS NOT NULL
      AND t.expires_at < statement_timestamp() - ($1::bigint * interval '1 second')
      AND NOT EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM git_operations o WHERE o.token_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM git_ref_admissions a WHERE a.token_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM ci_checkout_jobs j WHERE j.issuer_token_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM ci_checkout_delegations d WHERE d.issuer_token_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM cluster_operator_tokens k WHERE k.token_id = t.id)
    RETURNING t.id
)
SELECT (SELECT count(*) FROM candidates)::bigint AS scanned,
       (SELECT count(*) FROM purged)::bigint AS purged,
       (SELECT expires_at_text FROM candidates ORDER BY expires_at DESC, id DESC LIMIT 1),
       (SELECT id FROM candidates ORDER BY expires_at DESC, id DESC LIMIT 1)"#;

/// The single fixed keyset predicate for the after-cursor branch. It is a
/// strict row comparison (never `cursor IS NULL OR ...`), so the planner keeps
/// the `(expires_at, id)` index range instead of re-filtering a large prefix.
#[cfg(test)]
const TOKEN_CURSOR_BOUND_AFTER: &str = "    AND (t.expires_at, t.id) > ($3::text::timestamptz, $4::uuid)\n";

/// Fixed after-cursor branch: identical shape to the first window except for
/// the keyset bound, so both statements have one stable, index-usable plan.
const TOKEN_DELETE_AFTER: &str = r#"WITH candidates AS MATERIALIZED (
    SELECT t.id, t.expires_at, t.expires_at::text AS expires_at_text
    FROM tokens t
    WHERE t.kind = 'browser' AND t.expires_at IS NOT NULL
      AND t.expires_at < statement_timestamp() - ($1::bigint * interval '1 second')
    AND (t.expires_at, t.id) > ($3::text::timestamptz, $4::uuid)
    ORDER BY t.expires_at, t.id
    LIMIT $2
    FOR UPDATE SKIP LOCKED
),
purged AS (
    DELETE FROM tokens t
    USING (
        SELECT c.id FROM candidates c
        WHERE NOT EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id = c.id)
          AND NOT EXISTS (SELECT 1 FROM git_operations o WHERE o.token_id = c.id)
          AND NOT EXISTS (SELECT 1 FROM git_ref_admissions a WHERE a.token_id = c.id)
          AND NOT EXISTS (SELECT 1 FROM ci_checkout_jobs j WHERE j.issuer_token_id = c.id)
          AND NOT EXISTS (SELECT 1 FROM ci_checkout_delegations d WHERE d.issuer_token_id = c.id)
          AND NOT EXISTS (SELECT 1 FROM cluster_operator_tokens k WHERE k.token_id = c.id)
    ) e
    WHERE t.id = e.id
      AND t.kind = 'browser' AND t.expires_at IS NOT NULL
      AND t.expires_at < statement_timestamp() - ($1::bigint * interval '1 second')
      AND NOT EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM git_operations o WHERE o.token_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM git_ref_admissions a WHERE a.token_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM ci_checkout_jobs j WHERE j.issuer_token_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM ci_checkout_delegations d WHERE d.issuer_token_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM cluster_operator_tokens k WHERE k.token_id = t.id)
    RETURNING t.id
)
SELECT (SELECT count(*) FROM candidates)::bigint AS scanned,
       (SELECT count(*) FROM purged)::bigint AS purged,
       (SELECT expires_at_text FROM candidates ORDER BY expires_at DESC, id DESC LIMIT 1),
       (SELECT id FROM candidates ORDER BY expires_at DESC, id DESC LIMIT 1)"#;

async fn purge_sessions(pool: &Pool, retention_seconds: i64) -> anyhow::Result<u64> {
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    transaction.batch_execute(&timeout_sql()).await?;
    let affected = transaction.execute(SESSION_DELETE, &[&retention_seconds, &BATCH_LIMIT]).await?;
    transaction.commit().await?;
    Ok(affected)
}

/// Fixed context per failure class. The typed `tokio_postgres::Error` (and its
/// validated SQLSTATE) stays in the source chain; nothing from the database
/// message is formatted into the text.
fn token_statement_error(error: tokio_postgres::Error) -> anyhow::Error {
    let context = if error.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) {
        "unexpected foreign-key reference blocks expired browser-token GC; extend the \
         reference-preservation probe and its index instead of widening a cascading delete"
    } else {
        "expired browser-token GC batch failed"
    };
    anyhow::Error::new(error).context(context)
}

async fn purge_tokens(pool: &Pool, retention_seconds: i64, cursor: &mut TokenCursor) -> anyhow::Result<u64> {
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    transaction.batch_execute(&timeout_sql()).await?;
    let row = match &cursor.position {
        Some((expires_at, id)) => {
            let params: [&(dyn tokio_postgres::types::ToSql + Sync); 4] =
                [&retention_seconds, &BATCH_LIMIT, expires_at, id];
            transaction.query_one(TOKEN_DELETE_AFTER, &params).await.map_err(token_statement_error)?
        }
        None => {
            let params: [&(dyn tokio_postgres::types::ToSql + Sync); 2] = [&retention_seconds, &BATCH_LIMIT];
            transaction.query_one(TOKEN_DELETE_FIRST, &params).await.map_err(token_statement_error)?
        }
    };
    let scanned: i64 = row.get(0);
    let purged: i64 = row.get(1);
    // Advance past the scanned window even when every candidate is referenced:
    // the keyset position is the last *candidate*, not the last deleted row.
    // Reaching the end (a window shorter than the limit, including an empty one)
    // returns to the head after commit so newly expired rows are seen again.
    let next = match (scanned >= BATCH_LIMIT, row.get::<_, Option<String>>(2), row.get::<_, Option<Uuid>>(3)) {
        (true, Some(expires_at), Some(id)) => Some((expires_at, id)),
        _ => None,
    };
    transaction.commit().await?;
    // Only a committed batch moves the cursor; a failed or rolled-back cycle
    // retries from exactly the same position.
    cursor.position = next;
    Ok(u64::try_from(purged).unwrap_or(0))
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
    fn counters_accumulate_without_labels() {
        let counters = Counters::default();
        counters.deleted(Purged { sessions: 3, tokens: 2 });
        counters.completed();
        counters.deleted(Purged { sessions: 1, tokens: 0 });
        counters.completed();
        counters.failed();
        assert_eq!(
            counters.snapshot(),
            CounterSnapshot { cycles: 2, session_rows_deleted: 4, tokens_deleted: 2, failures: 1 }
        );
    }

    #[test]
    fn partial_cycle_counts_each_pass_only_after_its_commit() {
        let counters = Counters::default();
        // purge_cycle records the session pass immediately after its COMMIT,
        // before the token pass starts. The token pass then fails, so run
        // records one failure and no completed cycle.
        counters.deleted(Purged { sessions: 4, tokens: 0 });
        counters.failed();
        assert_eq!(
            counters.snapshot(),
            CounterSnapshot { cycles: 0, session_rows_deleted: 4, tokens_deleted: 0, failures: 1 }
        );
        // The retry commits no new session rows and three token rows: every
        // pass is recorded once, and only the whole successful cycle counts.
        counters.deleted(Purged { sessions: 0, tokens: 3 });
        counters.completed();
        assert_eq!(
            counters.snapshot(),
            CounterSnapshot { cycles: 1, session_rows_deleted: 4, tokens_deleted: 3, failures: 1 }
        );
    }

    #[test]
    fn counters_saturate_at_the_maximum_instead_of_wrapping() {
        let counters = Counters::default();
        counters.deleted(Purged { sessions: u64::MAX, tokens: u64::MAX });
        counters.deleted(Purged { sessions: 1, tokens: 1 });
        bump(&counters.failures, u64::MAX);
        counters.failed();
        assert_eq!(
            counters.snapshot(),
            CounterSnapshot { cycles: 0, session_rows_deleted: u64::MAX, tokens_deleted: u64::MAX, failures: u64::MAX }
        );
    }

    #[test]
    fn token_batches_bound_candidates_before_reference_probes() {
        for sql in [TOKEN_DELETE_FIRST, TOKEN_DELETE_AFTER] {
            assert!(sql.contains("AS MATERIALIZED"), "candidates must be materialized: {sql}");
            assert_eq!(sql.matches("NOT EXISTS").count(), 12, "six probes for candidates and six rechecks");
            let limit = sql.find("LIMIT $2").expect("bounded candidate window");
            let first_probe = sql.find("NOT EXISTS").expect("reference probes");
            assert!(limit < first_probe, "LIMIT must precede every reference probe");
            assert!(sql.contains("FOR UPDATE SKIP LOCKED"));
            assert!(sql.contains("statement_timestamp()"), "stable, indexable cutoff");
            assert!(sql.contains("count(*) FROM candidates"), "scanned-window count drives cursor advance");
        }
        assert!(TOKEN_DELETE_AFTER.contains(TOKEN_CURSOR_BOUND_AFTER.trim_end()));
        assert_eq!(TOKEN_DELETE_AFTER.replace(TOKEN_CURSOR_BOUND_AFTER, ""), TOKEN_DELETE_FIRST);
        assert!(!TOKEN_DELETE_FIRST.contains("$3"), "the first window takes no cursor parameters");
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
