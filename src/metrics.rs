//! Private, fixed-cardinality operational metrics. PostgreSQL is authoritative.
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use deadpool_postgres::Pool;
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

/// Validate before binding: wildcard, public and private LAN addresses are forbidden.
pub fn validate_bind(address: SocketAddr) -> anyhow::Result<SocketAddr> {
    anyhow::ensure!(
        address.ip().is_loopback(),
        "metrics listener must bind a loopback address"
    );
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
        match value.compare_exchange_weak(
            current,
            current.saturating_add(amount),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
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
}

/// Mount only on the separately configured loopback listener, never the app router.
pub fn router(
    pool: Pool,
    git_slots: Arc<Semaphore>,
    capacity: usize,
    counters: Arc<TransferCounters>,
) -> Router {
    Router::new()
        .route("/metrics", get(scrape))
        .with_state(MetricsState {
            pool,
            git_slots,
            capacity,
            counters,
        })
}

// One SQL statement provides one consistent MVCC snapshot, without exposing any
// database strings. Unknown operations remain unknown after explicit resolution;
// the resolution relation determines whether operator attention is outstanding.
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
 (SELECT count(*) FROM repositories WHERE state='provisioning' AND next_retry_at<=statement_timestamp()),
 (SELECT COALESCE(GREATEST(EXTRACT(EPOCH FROM (statement_timestamp()-min(created_at))),0),0)::double precision
    FROM repositories WHERE state='provisioning')
"#;

#[derive(Default)]
struct Snapshot {
    repositories: [i64; 3],
    unresolved: i64,
    pending: i64,
    leased: i64,
    delivery_age: f64,
    provisioning_due: i64,
    provisioning_age: f64,
}
async fn snapshot(pool: &Pool) -> anyhow::Result<Snapshot> {
    let mut client = pool.get().await?;
    // The server-side timeout prevents a cancelled HTTP scrape from leaving an
    // expensive or lock-blocked query running indefinitely on a pooled session.
    let transaction = client.build_transaction().read_only(true).start().await?;
    transaction
        .batch_execute("SET LOCAL statement_timeout = '4000ms'")
        .await?;
    let row = transaction.query_one(SNAPSHOT_SQL, &[]).await?;
    transaction.commit().await?;
    Ok(Snapshot {
        repositories: [row.try_get(0)?, row.try_get(1)?, row.try_get(2)?],
        unresolved: row.try_get(3)?,
        pending: row.try_get(4)?,
        leased: row.try_get(5)?,
        delivery_age: row.try_get(6)?,
        provisioning_due: row.try_get(7)?,
        provisioning_age: row.try_get(8)?,
    })
}

async fn scrape(State(state): State<MetricsState>) -> Response {
    let snapshot = tokio::time::timeout(Duration::from_secs(5), snapshot(&state.pool))
        .await
        .ok()
        .and_then(Result::ok);
    let status = if snapshot.is_some() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = render(
        state.capacity,
        state.git_slots.available_permits(),
        &state.counters,
        snapshot.as_ref(),
    );
    (
        status,
        [
            (
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

fn gauge(output: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    let _ = writeln!(
        output,
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
    );
}
fn render(
    capacity: usize,
    available: usize,
    counters: &TransferCounters,
    snapshot: Option<&Snapshot>,
) -> String {
    let mut output = String::new();
    gauge(
        &mut output,
        "rootyard_postgres_up",
        "Whether the authoritative database snapshot succeeded.",
        u8::from(snapshot.is_some()),
    );
    gauge(
        &mut output,
        "rootyard_git_capacity",
        "Configured concurrent native Git capacity.",
        capacity,
    );
    gauge(
        &mut output,
        "rootyard_git_in_flight",
        "Occupied native Git slots including provisioning and cleanup.",
        capacity.saturating_sub(available),
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
    // On failure emit no database-derived gauges: zero would falsely imply health.
    if let Some(s) = snapshot {
        output.push_str("# HELP rootyard_repositories Repositories by durable metadata state.\n# TYPE rootyard_repositories gauge\n");
        for (state, count) in ["provisioning", "ready", "recovering"]
            .iter()
            .zip(s.repositories)
        {
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
    }
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
        let text = render(8, 6, &TransferCounters::default(), None);
        assert!(text.contains("rootyard_postgres_up 0\n"));
        assert!(text.contains("rootyard_git_in_flight 2\n"));
        assert!(!text.contains("rootyard_repositories"));
        assert!(!text.contains("rootyard_event_deliveries"));
        assert!(!text.contains("rootyard_provisioning"));
        assert!(!text.contains("rootyard_operations_unresolved"));
    }
    #[test]
    fn fixed_labels_and_counter_values() {
        let counters = TransferCounters::default();
        counters.record_success();
        counters.record_failure();
        counters.add_received_bytes(42);
        counters.add_sent_bytes(17);
        let text = render(8, 8, &counters, Some(&Snapshot::default()));
        assert!(text.contains("rootyard_git_transfer_bytes_total{direction=\"received\"} 42\n"));
        assert!(text.contains("rootyard_git_transfer_bytes_total{direction=\"sent\"} 17\n"));
        assert!(text.contains("rootyard_git_transfers_total{outcome=\"success\"} 1\n"));
        assert!(text.contains("rootyard_git_transfers_total{outcome=\"failure\"} 1\n"));
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let (name, value) = line.split_once(' ').unwrap();
            assert!(name.starts_with("rootyard_"));
            assert!(value.parse::<f64>().unwrap().is_finite());
            if let Some((_, label)) = name.split_once('{') {
                assert!(
                    [
                        "outcome=\"success\"}",
                        "outcome=\"failure\"}",
                        "direction=\"received\"}",
                        "direction=\"sent\"}",
                        "state=\"provisioning\"}",
                        "state=\"ready\"}",
                        "state=\"recovering\"}",
                        "state=\"pending\"}",
                        "state=\"leased\"}"
                    ]
                    .contains(&label)
                );
            }
        }
        assert_eq!(text.lines().filter(|l| !l.starts_with('#')).count(), 17);
    }
    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let counters = TransferCounters::default();
        counters.add_sent_bytes(u64::MAX);
        counters.add_sent_bytes(1);
        assert_eq!(counters.sent.load(Ordering::Relaxed), u64::MAX);
    }
}
