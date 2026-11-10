//! Private, fixed-cardinality operational metrics. PostgreSQL is authoritative.
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use deadpool_postgres::{Pool, Status};
use std::{
    fmt::Write,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;

use crate::{
    metrics_workers,
    web::session_gc::{self, CounterSnapshot},
};

/// Validate before binding: wildcard, public and private LAN addresses are forbidden.
pub fn validate_bind(address: SocketAddr) -> anyhow::Result<SocketAddr> {
    anyhow::ensure!(address.ip().is_loopback(), "metrics listener must bind a loopback address");
    Ok(address)
}

/// Process-lifetime transport counters, not durable operation/event receipts.
#[derive(Default)]
pub struct TransferCounters {
    succeeded: AtomicU64,
    failed: AtomicU64,
    received: AtomicU64,
    sent: AtomicU64,
}
impl TransferCounters {
    pub fn record_success(&self) {
        increment(&self.succeeded, 1);
    }
    pub fn record_failure(&self) {
        increment(&self.failed, 1);
    }
    pub fn add_received_bytes(&self, bytes: u64) {
        increment(&self.received, bytes);
    }
    pub fn add_sent_bytes(&self, bytes: u64) {
        increment(&self.sent, bytes);
    }
}
fn increment(value: &AtomicU64, amount: u64) {
    let mut current = value.load(Ordering::Relaxed);
    loop {
        match value.compare_exchange_weak(current, current.saturating_add(amount), Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

#[derive(Clone)]
struct MetricsState {
    pool: Pool,
    git_slots: Arc<Semaphore>,
    capacity: usize,
    counters: Arc<TransferCounters>,
    workers: metrics_workers::Config,
}

/// Mount only on the separately configured loopback listener, never the app router.
pub fn router(
    pool: Pool,
    git_slots: Arc<Semaphore>,
    capacity: usize,
    counters: Arc<TransferCounters>,
    workers: metrics_workers::Config,
) -> Router {
    Router::new().route("/metrics", get(scrape)).with_state(MetricsState {
        pool,
        git_slots,
        capacity,
        counters,
        workers,
    })
}

// One SQL statement provides one consistent MVCC snapshot, without exposing any
// database strings. Unknown operations remain unknown after explicit resolution;
// the resolution relation determines whether operator attention is outstanding.
// Browser row counts cover every stored row of that kind, revoked and already
// expired included; the two oldest-expiry subqueries only consider rows whose
// expiry is already past, so an unexpired session is never the "oldest expired"
// sample, an empty set reports zero and the database clock is authoritative.
// The webhook age likewise joins deliveries to their hook and measures only an
// active hook's pending, retry-delayed failed and live leased rows.
const SNAPSHOT_SQL: &str = r#"
SELECT
 (SELECT count(*) FROM repositories WHERE state='provisioning'),
 (SELECT count(*) FROM repositories WHERE state='ready'),
 (SELECT count(*) FROM repositories WHERE state='recovering'),
 (SELECT count(*) FROM git_operations o WHERE outcome='unknown'
    AND NOT EXISTS (SELECT 1 FROM operation_resolutions r WHERE r.operation_id=o.id)),
 (SELECT count(*) FROM event_deliveries WHERE state='pending'),
 (SELECT count(*) FROM event_deliveries WHERE state='leased'),
 (SELECT COALESCE(GREATEST(EXTRACT(EPOCH FROM (statement_timestamp()-min(e.created_at))),0),0)::double precision
    FROM event_deliveries d JOIN outbox_events e ON e.event_id=d.event_id WHERE d.state<>'delivered'),
 (SELECT COALESCE(GREATEST(EXTRACT(EPOCH FROM (statement_timestamp()-min(d.created_at))),0),0)::double precision
    FROM forge_webhook_deliveries d JOIN forge_webhooks h ON h.id=d.webhook_id
    WHERE h.active AND d.state IN ('pending','failed','leased')),
 (SELECT count(*) FROM repositories WHERE state='provisioning' AND next_retry_at<=statement_timestamp()),
 (SELECT COALESCE(GREATEST(EXTRACT(EPOCH FROM (statement_timestamp()-min(created_at))),0),0)::double precision
    FROM repositories WHERE state='provisioning'),
 (SELECT count(*) FROM web_sessions s JOIN tokens t ON t.id=s.token_id WHERE t.kind='browser'),
 (SELECT count(*) FROM tokens WHERE kind='browser'),
 (SELECT COALESCE(GREATEST(EXTRACT(EPOCH FROM (statement_timestamp()-min(s.expires_at))),0),0)::double precision
    FROM web_sessions s JOIN tokens t ON t.id=s.token_id
    WHERE t.kind='browser' AND s.expires_at<statement_timestamp()),
 (SELECT COALESCE(GREATEST(EXTRACT(EPOCH FROM (statement_timestamp()-min(t.expires_at))),0),0)::double precision
    FROM tokens t WHERE t.kind='browser' AND t.expires_at IS NOT NULL AND t.expires_at<statement_timestamp())
"#;

#[derive(Default)]
struct Snapshot {
    repositories: [i64; 3],
    unresolved: i64,
    pending: i64,
    leased: i64,
    delivery_age: f64,
    webhook_delivery_age: f64,
    provisioning_due: i64,
    provisioning_age: f64,
    browser_sessions: i64,
    browser_tokens: i64,
    expired_session_age: f64,
    expired_token_age: f64,
}
async fn snapshot(
    pool: &Pool,
    config: metrics_workers::Config,
) -> anyhow::Result<(Snapshot, metrics_workers::Snapshot)> {
    let mut client = pool.get().await?;
    // The server-side timeout prevents a cancelled HTTP scrape from leaving an
    // expensive or lock-blocked query running indefinitely on a pooled session.
    // Repeatable read gives every statement of one scrape the same MVCC
    // snapshot; the transaction is read-only, so it can neither take write
    // locks nor block writers beyond an ordinary SELECT.
    let transaction = client.build_transaction().read_only(true).start().await?;
    transaction
        .batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ; SET LOCAL statement_timeout = '4000ms'")
        .await?;
    let row = transaction.query_one(SNAPSHOT_SQL, &[]).await?;
    let core = Snapshot {
        repositories: [row.try_get(0)?, row.try_get(1)?, row.try_get(2)?],
        unresolved: row.try_get(3)?,
        pending: row.try_get(4)?,
        leased: row.try_get(5)?,
        delivery_age: row.try_get(6)?,
        webhook_delivery_age: row.try_get(7)?,
        provisioning_due: row.try_get(8)?,
        provisioning_age: row.try_get(9)?,
        browser_sessions: row.try_get(10)?,
        browser_tokens: row.try_get(11)?,
        expired_session_age: row.try_get(12)?,
        expired_token_age: row.try_get(13)?,
    };
    let workers = metrics_workers::query(&transaction, config).await?;
    transaction.commit().await?;
    Ok((core, workers))
}

async fn scrape(State(state): State<MetricsState>) -> Response {
    // Sample pool occupancy before this scrape checks out its own snapshot
    // session, so the gauges describe demand that was already present.
    let pool = state.pool.status();
    // The GC counters are process-local and carry no labels. They are sampled
    // from the single GC counter set outside the snapshot attempt, so a failed
    // SQL snapshot cannot hide or reset them.
    let gc = session_gc::counters().snapshot();
    let snapshot = tokio::time::timeout(Duration::from_secs(5), snapshot(&state.pool, state.workers))
        .await
        .ok()
        .and_then(Result::ok);
    let status = if snapshot.is_some() { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    let body = render(
        state.capacity,
        state.git_slots.available_permits(),
        &state.counters,
        &gc,
        &pool,
        snapshot.as_ref().map(|(core, workers)| (core, workers)),
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
        body,
    )
        .into_response()
}

fn gauge(output: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    let _ = writeln!(output, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}");
}
fn counter(output: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(output, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}");
}
fn render(
    capacity: usize,
    available: usize,
    counters: &TransferCounters,
    gc: &CounterSnapshot,
    pool: &Status,
    snapshot: Option<(&Snapshot, &metrics_workers::Snapshot)>,
) -> String {
    let mut output = String::new();
    output.push_str("# HELP rootyard_error_log_dropped_total Accepted error records lost to queue or writer failure; excludes rate limiting and shutdown.\n# TYPE rootyard_error_log_dropped_total counter\n");
    let _ = writeln!(output, "rootyard_error_log_dropped_total {}", crate::observability::dropped_event_count());
    gauge(
        &mut output,
        "rootyard_postgres_up",
        "Whether the authoritative database snapshot succeeded.",
        u8::from(snapshot.is_some()),
    );
    gauge(&mut output, "rootyard_git_capacity", "Configured concurrent native Git capacity.", capacity);
    gauge(
        &mut output,
        "rootyard_git_in_flight",
        "Occupied native Git slots including provisioning and cleanup.",
        capacity.saturating_sub(available),
    );
    gauge(&mut output, "rootyard_db_pool_max_size", "Configured maximum PostgreSQL pool connections.", pool.max_size);
    gauge(
        &mut output,
        "rootyard_db_pool_size",
        "Tracked established pool objects; excludes connection creation and is not a socket liveness probe.",
        pool.size,
    );
    gauge(
        &mut output,
        "rootyard_db_pool_available",
        "Approximate idle pool objects reported by Deadpool before this scrape.",
        pool.available,
    );
    gauge(
        &mut output,
        "rootyard_db_pool_busy",
        "Approximate checked-out pool objects (tracked size minus reported available).",
        pool.size.saturating_sub(pool.available),
    );
    gauge(
        &mut output,
        "rootyard_db_pool_waiting",
        "Estimated excess pool users; can include callers waiting for connection creation.",
        pool.waiting,
    );
    output.push_str("# HELP rootyard_git_transfers_total Completed Git HTTP transfers by transport outcome.\n# TYPE rootyard_git_transfers_total counter\n");
    let _ = writeln!(
        output,
        "rootyard_git_transfers_total{{outcome=\"success\"}} {}\nrootyard_git_transfers_total{{outcome=\"failure\"}} {}",
        counters.succeeded.load(Ordering::Relaxed),
        counters.failed.load(Ordering::Relaxed)
    );
    output.push_str("# HELP rootyard_git_transfer_bytes_total Git HTTP body bytes observed by direction.\n# TYPE rootyard_git_transfer_bytes_total counter\n");
    let _ = writeln!(
        output,
        "rootyard_git_transfer_bytes_total{{direction=\"received\"}} {}\nrootyard_git_transfer_bytes_total{{direction=\"sent\"}} {}",
        counters.received.load(Ordering::Relaxed),
        counters.sent.load(Ordering::Relaxed)
    );
    // The GC counters describe this process's own bounded loop. They stay
    // exported on a failed SQL snapshot because they never assert database
    // health, and they are read from the GC module's single counter set.
    counter(&mut output, "rootyard_session_gc_cycles_total", "Committed bounded browser-session GC cycles.", gc.cycles);
    counter(
        &mut output,
        "rootyard_session_gc_session_rows_deleted_total",
        "Expired browser web_sessions rows committed as deleted by GC.",
        gc.session_rows_deleted,
    );
    counter(
        &mut output,
        "rootyard_session_gc_tokens_deleted_total",
        "Expired browser tokens committed as deleted by GC after reference probes.",
        gc.tokens_deleted,
    );
    counter(
        &mut output,
        "rootyard_session_gc_failures_total",
        "Browser-session GC cycles that failed; rows committed by an earlier pass remain counted.",
        gc.failures,
    );
    // A failed SQL snapshot omits only database-derived gauges: zero would falsely imply health.
    if let Some((s, workers)) = snapshot {
        output.push_str("# HELP rootyard_repositories Repositories by durable metadata state.\n# TYPE rootyard_repositories gauge\n");
        for (state, count) in ["provisioning", "ready", "recovering"].iter().zip(s.repositories) {
            let _ = writeln!(output, "rootyard_repositories{{state=\"{state}\"}} {count}");
        }
        gauge(
            &mut output,
            "rootyard_operations_unresolved",
            "Unknown operations without an explicit resolution record.",
            s.unresolved,
        );
        output.push_str("# HELP rootyard_event_deliveries Outstanding durable consumer deliveries by state.\n# TYPE rootyard_event_deliveries gauge\n");
        let _ = writeln!(
            output,
            "rootyard_event_deliveries{{state=\"pending\"}} {}\nrootyard_event_deliveries{{state=\"leased\"}} {}",
            s.pending, s.leased
        );
        gauge(
            &mut output,
            "rootyard_event_delivery_oldest_age_seconds",
            "Age of oldest undelivered event including retry delays and expired leases.",
            s.delivery_age,
        );
        gauge(
            &mut output,
            "rootyard_webhook_delivery_oldest_age_seconds",
            "Database-clock age since creation of the oldest outstanding webhook delivery on an active hook in pending, failed or leased state, retry delays and live leases included; delivered, dead_letter and inactive hooks are excluded and an empty set reports 0.",
            s.webhook_delivery_age,
        );
        gauge(
            &mut output,
            "rootyard_provisioning_backlog",
            "All repositories awaiting provisioning including retry delays.",
            s.repositories[0],
        );
        gauge(
            &mut output,
            "rootyard_provisioning_due",
            "Repositories awaiting provisioning whose retry time has arrived.",
            s.provisioning_due,
        );
        gauge(
            &mut output,
            "rootyard_provisioning_oldest_age_seconds",
            "Age of oldest repository awaiting provisioning.",
            s.provisioning_age,
        );
        gauge(
            &mut output,
            "rootyard_browser_web_sessions",
            "Browser sign-in session rows including revoked and already expired rows.",
            s.browser_sessions,
        );
        gauge(
            &mut output,
            "rootyard_browser_tokens",
            "Browser tokens including revoked and already expired rows; API tokens are excluded.",
            s.browser_tokens,
        );
        gauge(
            &mut output,
            "rootyard_expired_browser_session_oldest_age_seconds",
            "Database-clock age of the oldest expired browser session; unexpired rows and an empty set report 0.",
            s.expired_session_age,
        );
        gauge(
            &mut output,
            "rootyard_expired_browser_token_oldest_age_seconds",
            "Database-clock age of the oldest expired browser token; unexpired rows and an empty set report 0.",
            s.expired_token_age,
        );
        metrics_workers::render(&mut output, workers);
    }
    // Opt-in (#106) phase observations, fixed series only. A default build
    // compiles this to nothing, so the exposition above is unchanged.
    crate::baseline_metrics::render(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_loopback_can_bind() {
        for address in ["127.0.0.1:9108", "127.2.3.4:0", "[::1]:9108"] {
            assert!(validate_bind(address.parse().unwrap()).is_ok());
        }
        for address in [
            "0.0.0.0:9108",
            "[::]:9108",
            "192.168.1.1:9108",
            "10.0.0.1:9108",
            "8.8.8.8:9108",
            "[::ffff:127.0.0.1]:9108",
        ] {
            assert!(validate_bind(address.parse().unwrap()).is_err());
        }
    }
    #[test]
    fn failed_snapshot_never_fabricates_backlog() {
        let pool = Status { max_size: 16, size: 13, available: 1, waiting: 7 };
        let gc = CounterSnapshot { cycles: 4, session_rows_deleted: 9, tokens_deleted: 2, failures: 1 };
        let text = render(8, 6, &TransferCounters::default(), &gc, &pool, None);
        assert!(text.contains("rootyard_postgres_up 0\n"));
        assert!(text.contains("rootyard_git_in_flight 2\n"));
        assert!(text.contains("rootyard_db_pool_max_size 16\n"));
        assert!(text.contains("rootyard_db_pool_size 13\n"));
        assert!(text.contains("rootyard_db_pool_available 1\n"));
        assert!(text.contains("rootyard_db_pool_busy 12\n"));
        assert!(text.contains("rootyard_db_pool_waiting 7\n"));
        assert!(!text.contains("rootyard_repositories"));
        assert!(!text.contains("rootyard_event_deliveries"));
        assert!(!text.contains("rootyard_provisioning"));
        assert!(!text.contains("rootyard_operations_unresolved"));
        assert!(!text.contains("rootyard_browser_"));
        assert!(!text.contains("rootyard_expired_browser_"));
        assert!(!text.contains("rootyard_webhook_"));
        assert!(!text.contains("rootyard_workspace_"));
        assert!(!text.contains("rootyard_storage_maintenance"));
        // Process-local GC counters survive the failed snapshot unchanged.
        assert!(text.contains("rootyard_session_gc_cycles_total 4\n"));
        assert!(text.contains("rootyard_session_gc_session_rows_deleted_total 9\n"));
        assert!(text.contains("rootyard_session_gc_tokens_deleted_total 2\n"));
        assert!(text.contains("rootyard_session_gc_failures_total 1\n"));
    }
    #[test]
    fn fixed_labels_and_counter_values() {
        let counters = TransferCounters::default();
        counters.record_success();
        counters.record_failure();
        counters.add_received_bytes(42);
        counters.add_sent_bytes(17);
        let pool = Status { max_size: 16, size: 1, available: 1, waiting: 0 };
        let gc = CounterSnapshot::default();
        let core = Snapshot::default();
        let workers = crate::metrics_workers::Snapshot::default();
        let text = render(8, 8, &counters, &gc, &pool, Some((&core, &workers)));
        assert!(text.contains("rootyard_git_transfer_bytes_total{direction=\"received\"} 42\n"));
        assert!(text.contains("rootyard_git_transfer_bytes_total{direction=\"sent\"} 17\n"));
        assert!(text.contains("rootyard_git_transfers_total{outcome=\"success\"} 1\n"));
        assert!(text.contains("rootyard_git_transfers_total{outcome=\"failure\"} 1\n"));
        assert!(text.contains("rootyard_webhook_delivery_oldest_age_seconds 0\n"));
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let (name, value) = line.split_once(' ').unwrap();
            assert!(name.starts_with("rootyard_"));
            assert!(value.parse::<f64>().unwrap().is_finite());
            // Opt-in baseline series have their own fixed-label test.
            if name.starts_with("rootyard_baseline_") {
                continue;
            }
            if let Some((_, label)) = name.split_once('{') {
                let mut allowed: Vec<String> = [
                    "outcome=\"success\"}",
                    "outcome=\"failure\"}",
                    "direction=\"received\"}",
                    "direction=\"sent\"}",
                    "state=\"provisioning\"}",
                    "state=\"ready\"}",
                    "state=\"recovering\"}",
                    "state=\"pending\"}",
                    "state=\"leased\"}",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect();
                for (backend, kind) in crate::metrics_workers::JOB_KINDS {
                    for state in crate::metrics_workers::JOB_STATES {
                        allowed.push(format!("backend=\"{backend}\",kind=\"{kind}\",state=\"{state}\"}}"));
                    }
                    allowed.push(format!("backend=\"{backend}\",kind=\"{kind}\"}}"));
                }
                for backend in crate::metrics_workers::BACKENDS {
                    for state in crate::metrics_workers::SCAN_STATES {
                        allowed.push(format!("backend=\"{backend}\",state=\"{state}\"}}"));
                    }
                    allowed.push(format!("backend=\"{backend}\"}}"));
                }
                assert!(allowed.iter().any(|entry| entry.as_str() == label), "unexpected label {label}");
            }
        }
        let mut baseline = String::new();
        crate::baseline_metrics::render(&mut baseline);
        assert_eq!(
            text.lines().filter(|l| !l.starts_with('#')).count(),
            92 + baseline.lines().filter(|l| !l.starts_with('#')).count()
        );
    }

    #[test]
    fn browser_session_gauges_and_gc_counters_use_fixed_series() {
        let gc = CounterSnapshot { cycles: 3, session_rows_deleted: 5, tokens_deleted: 7, failures: 1 };
        let snapshot = Snapshot {
            browser_sessions: 4,
            browser_tokens: 9,
            expired_session_age: 3600.0,
            expired_token_age: 691_200.0,
            ..Default::default()
        };
        let pool = Status { max_size: 16, size: 1, available: 1, waiting: 0 };
        let workers = crate::metrics_workers::Snapshot::default();
        let text = render(4, 4, &TransferCounters::default(), &gc, &pool, Some((&snapshot, &workers)));
        for line in [
            "rootyard_session_gc_cycles_total 3\n",
            "rootyard_session_gc_session_rows_deleted_total 5\n",
            "rootyard_session_gc_tokens_deleted_total 7\n",
            "rootyard_session_gc_failures_total 1\n",
            "rootyard_browser_web_sessions 4\n",
            "rootyard_browser_tokens 9\n",
            "rootyard_expired_browser_session_oldest_age_seconds 3600\n",
            "rootyard_expired_browser_token_oldest_age_seconds 691200\n",
        ] {
            assert!(text.contains(line), "missing {line:?} in:\n{text}");
        }
        // No browser-session sample gains a label: the series stay fixed.
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let (name, value) = line.split_once(' ').unwrap();
            assert!(name.starts_with("rootyard_"));
            assert!(value.parse::<f64>().is_ok());
            assert!(!name.contains('{') || !name.contains("browser"), "unexpected label on {name}");
        }
    }
    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let counters = TransferCounters::default();
        counters.add_sent_bytes(u64::MAX);
        counters.add_sent_bytes(1);
        assert_eq!(counters.sent.load(Ordering::Relaxed), u64::MAX);
    }
}
