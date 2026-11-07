//! Fixed-cardinality worker backlog, workspace capture-lag, lease and storage
//! repair metrics. PostgreSQL remains the only source of truth.
//!
//! Every label value is a compile-time constant below. The database columns
//! `kind`, `state` and `storage_backend` are strings, so stored values are
//! resolved against these tables and an unexpected value is dropped instead of
//! being exported as a label. No workspace, repository, user or token
//! identifier is ever selected or exposed.
use deadpool_postgres::Transaction;
use std::fmt::Write;
use uuid::Uuid;

/// Fixed backend/kind pairs. GC admission kinds (`*_unreachable_mark`,
/// `*_tombstone_delete`) are deliberately excluded: their backlog is tracked by
/// the separate GC admission issue.
pub const JOB_KINDS: [(&str, &str); 7] = [
    ("gitfs", "gitfs_stage_cleanup"),
    ("gitfs", "gitfs_repack"),
    ("gitfs", "gitfs_cache_hydrate"),
    ("gitfs", "gitfs_cache_evict"),
    ("pando", "pando_repack"),
    ("pando", "pando_cache_hydrate"),
    ("pando", "pando_cache_evict"),
];

/// `queued` and `running` are totals; `due_queued` and `retry_delayed` split
/// `queued` on `not_before`, and `expired_running_lease` splits `running` on
/// `lease_until`. A failed job is terminal: `jobs::finish` only re-queues a
/// retryable error, so `state='failed'` already means the attempt budget is
/// exhausted (or the lease expired at the maximum attempt).
pub const JOB_STATES: [&str; 6] =
    ["queued", "due_queued", "retry_delayed", "running", "expired_running_lease", "failed"];

pub const BACKENDS: [&str; 2] = ["gitfs", "pando"];

/// `missing_scan` has no `last_scan_at` (missing row or NULL column),
/// `due_scan` matches the scheduler's scan-period predicate exactly, and
/// `stale_generation` recorded a scan for another storage generation.
pub const SCAN_STATES: [&str; 3] = ["missing_scan", "due_scan", "stale_generation"];

/// Values validated by the serving process; the metrics listener never re-reads
/// the environment on its own.
#[derive(Clone, Copy)]
pub struct Config {
    /// `state.storage.volume_id`, the workspace `host_id` of this process.
    pub volume_id: Uuid,
    /// The parsed `Policy::scan_period_seconds` of this process.
    pub scan_period_seconds: i64,
}

pub struct Snapshot {
    pub capture_oldest_age: f64,
    pub capture_never_sampled: i64,
    pub lease_expired: i64,
    pub jobs: [[i64; 6]; 7],
    pub oldest_queued_age: [f64; 7],
    pub scan: [[i64; 3]; 2],
    pub oldest_overdue: [f64; 2],
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            capture_oldest_age: 0.0,
            capture_never_sampled: 0,
            lease_expired: 0,
            jobs: [[0_i64; 6]; 7],
            oldest_queued_age: [0.0; 7],
            scan: [[0_i64; 3]; 2],
            oldest_overdue: [0.0; 2],
        }
    }
}

/// One row per fixed kind. `count(...) FILTER` keeps the whole aggregation in a
/// single statement, and an absent kind still yields a zero row through the
/// fixed `VALUES` list.
const JOBS_SQL: &str = r#"
SELECT g.kind,
 count(j.id) FILTER (WHERE j.state='queued'),
 count(j.id) FILTER (WHERE j.state='queued' AND j.not_before<=statement_timestamp()),
 count(j.id) FILTER (WHERE j.state='queued' AND j.not_before>statement_timestamp()),
 count(j.id) FILTER (WHERE j.state='running' AND j.lease_until>statement_timestamp()),
 count(j.id) FILTER (WHERE j.state='running' AND j.lease_until<=statement_timestamp()),
 count(j.id) FILTER (WHERE j.state='failed'),
 COALESCE(GREATEST(EXTRACT(EPOCH FROM (statement_timestamp()-min(j.created_at) FILTER (WHERE j.state='queued'))),0),0)::double precision
FROM (VALUES ('gitfs_stage_cleanup'),('gitfs_repack'),('gitfs_cache_hydrate'),
             ('gitfs_cache_evict'),('pando_repack'),('pando_cache_hydrate'),
             ('pando_cache_evict')) AS g(kind)
LEFT JOIN storage_maintenance_jobs j ON j.kind=g.kind
GROUP BY g.kind
"#;

/// Ready repositories that the scheduler would consider for maintenance. The
/// scheduler additionally filters by local shard primary; that routing is not
/// reproduced here, so these gauges count cluster-wide eligible repositories.
/// The Pando predicate mirrors `scheduler::schedule_pando` (stable authority,
/// serving pack state for the same tenant and storage generation).
const REPO_SCAN_SQL: &str = r#"
SELECT r.storage_backend,
 count(*) FILTER (WHERE s.last_scan_at IS NULL),
 count(*) FILTER (WHERE s.last_scan_at < statement_timestamp()-make_interval(secs=>($1::bigint)::double precision)),
 count(*) FILTER (WHERE s.last_scan_at IS NOT NULL AND s.last_scan_generation IS DISTINCT FROM r.storage_generation),
 COALESCE(GREATEST(EXTRACT(EPOCH FROM (statement_timestamp()-min(s.last_scan_at)
             -make_interval(secs=>($1::bigint)::double precision))),0),0)::double precision
FROM repositories r
LEFT JOIN storage_maintenance_repo_state s ON s.repository_id=r.id AND s.tenant_id=r.owner_id
WHERE r.state='ready' AND (
  r.storage_backend='gitfs'
  OR (r.storage_backend='pando' AND r.transition_state='stable' AND EXISTS (
        SELECT 1 FROM pando_repository_states p
        WHERE p.repository_id=r.id AND p.tenant_id=r.owner_id
          AND p.storage_generation=r.storage_generation AND p.state='serving')))
GROUP BY r.storage_backend
"#;

/// Host-scoped workspace capture freshness. Only rows with the same predicate as
/// `capture::eligible_page` are counted: this host, `ready`, lease still valid.
/// `capture::reconcile_one` and the API baseline (`record_current_at`) both
/// upsert `scanned_at`, so the age measures the oldest recently verified
/// capture/baseline, not a pure scan interval and not `updated_at`.
const WORKSPACE_SQL: &str = r#"
SELECT
 (SELECT COALESCE(GREATEST(EXTRACT(EPOCH FROM (statement_timestamp()-min(c.scanned_at))),0),0)::double precision
    FROM workspaces w JOIN workspace_capture_state c ON c.workspace_id=w.id
   WHERE w.host_id=$1 AND w.state='ready' AND w.lease_until>statement_timestamp()),
 (SELECT count(*) FROM workspaces w
   WHERE w.host_id=$1 AND w.state='ready' AND w.lease_until>statement_timestamp()
     AND NOT EXISTS (SELECT 1 FROM workspace_capture_state c WHERE c.workspace_id=w.id)),
 (SELECT count(*) FROM workspaces w
   WHERE w.host_id=$1 AND w.state='ready' AND w.lease_until<=statement_timestamp())
"#;

fn kind_index(kind: &str) -> Option<usize> {
    JOB_KINDS.iter().position(|(_, name)| *name == kind)
}

fn backend_index(backend: &str) -> Option<usize> {
    BACKENDS.iter().position(|name| *name == backend)
}

/// Runs inside the scrape transaction, so every statement shares the
/// repeatable-read snapshot taken by the first one.
pub async fn query(tx: &Transaction<'_>, config: Config) -> anyhow::Result<Snapshot> {
    let mut snapshot = Snapshot::default();
    for row in tx.query(JOBS_SQL, &[]).await? {
        let kind: String = row.try_get(0)?;
        let Some(index) = kind_index(&kind) else { continue };
        for (state, column) in (0..6).enumerate() {
            snapshot.jobs[index][state] = row.try_get(column + 1)?;
        }
        snapshot.oldest_queued_age[index] = row.try_get(7)?;
    }
    for row in tx.query(REPO_SCAN_SQL, &[&config.scan_period_seconds]).await? {
        let backend: String = row.try_get(0)?;
        let Some(index) = backend_index(&backend) else { continue };
        for (state, column) in (0..3).enumerate() {
            snapshot.scan[index][state] = row.try_get(column + 1)?;
        }
        snapshot.oldest_overdue[index] = row.try_get(4)?;
    }
    let row = tx.query_one(WORKSPACE_SQL, &[&config.volume_id]).await?;
    snapshot.capture_oldest_age = row.try_get(0)?;
    snapshot.capture_never_sampled = row.try_get(1)?;
    snapshot.lease_expired = row.try_get(2)?;
    Ok(snapshot)
}

fn gauge(output: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    let _ = writeln!(output, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}");
}

/// Appends every fixed series, including zero-valued ones, so a missing kind,
/// backend or state never shifts the exposition.
pub fn render(output: &mut String, snapshot: &Snapshot) {
    gauge(
        output,
        "rootyard_workspace_capture_oldest_age_seconds",
        "Database-clock age of the oldest successful capture or API-baseline timestamp among this host's ready, leased workspaces; capture refreshes scanned_at even when content is unchanged, so this is verification freshness, not a scheduled scan interval.",
        snapshot.capture_oldest_age,
    );
    gauge(
        output,
        "rootyard_workspace_capture_never_sampled",
        "Ready, leased workspaces on this host with no workspace_capture_state row. A workspace normally gains a baseline row when it is created, so this counts rows that never recorded one.",
        snapshot.capture_never_sampled,
    );
    gauge(
        output,
        "rootyard_workspace_lease_expired",
        "Ready workspaces on this host whose lease_until is not in the future; not necessarily a fault, and never counted as capture lag or as never sampled.",
        snapshot.lease_expired,
    );
    output.push_str(
        "# HELP rootyard_storage_maintenance_jobs Durable storage maintenance jobs by fixed backend, kind and state; queued and running are totals, due_queued and retry_delayed split queued on not_before, and expired_running_lease splits running on lease_until. failed is terminal.\n# TYPE rootyard_storage_maintenance_jobs gauge\n",
    );
    for (index, (backend, kind)) in JOB_KINDS.iter().enumerate() {
        for (state, value) in JOB_STATES.iter().zip(snapshot.jobs[index]) {
            let _ = writeln!(
                output,
                "rootyard_storage_maintenance_jobs{{backend=\"{backend}\",kind=\"{kind}\",state=\"{state}\"}} {value}"
            );
        }
    }
    output.push_str(
        "# HELP rootyard_storage_maintenance_oldest_queued_age_seconds Database-clock age since creation of the oldest queued job, including retry delays; an empty set reports 0.\n# TYPE rootyard_storage_maintenance_oldest_queued_age_seconds gauge\n",
    );
    for (index, (backend, kind)) in JOB_KINDS.iter().enumerate() {
        let _ = writeln!(
            output,
            "rootyard_storage_maintenance_oldest_queued_age_seconds{{backend=\"{backend}\",kind=\"{kind}\"}} {}",
            snapshot.oldest_queued_age[index]
        );
    }
    output.push_str(
        "# HELP rootyard_storage_maintenance_repos Ready, cluster-wide eligible repositories by fixed backend and scheduled scan state; missing_scan has no recorded scan, due_scan matches the scheduler scan-period predicate, stale_generation recorded a scan for an older storage generation.\n# TYPE rootyard_storage_maintenance_repos gauge\n",
    );
    for (index, backend) in BACKENDS.iter().enumerate() {
        for (state, value) in SCAN_STATES.iter().zip(snapshot.scan[index]) {
            let _ = writeln!(
                output,
                "rootyard_storage_maintenance_repos{{backend=\"{backend}\",state=\"{state}\"}} {value}"
            );
        }
    }
    output.push_str(
        "# HELP rootyard_storage_maintenance_oldest_overdue_scan_age_seconds Database-clock seconds past the scheduler scan due time for the oldest overdue repository; zero when nothing is overdue.\n# TYPE rootyard_storage_maintenance_oldest_overdue_scan_age_seconds gauge\n",
    );
    for (index, backend) in BACKENDS.iter().enumerate() {
        let _ = writeln!(
            output,
            "rootyard_storage_maintenance_oldest_overdue_scan_age_seconds{{backend=\"{backend}\"}} {}",
            snapshot.oldest_overdue[index]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot_exports_every_fixed_series() {
        let mut text = String::new();
        render(&mut text, &Snapshot::default());
        let values: Vec<_> = text.lines().filter(|line| !line.starts_with('#')).collect();
        assert_eq!(values.len(), 60);
        for line in values {
            let (name, value) = line.split_once(' ').unwrap();
            assert!(name.starts_with("rootyard_"), "{name}");
            assert!(value.parse::<f64>().unwrap() >= 0.0, "{line}");
        }
        assert!(text.contains("rootyard_workspace_capture_oldest_age_seconds 0\n"));
        assert!(text.contains("rootyard_workspace_capture_never_sampled 0\n"));
        assert!(text.contains("rootyard_workspace_lease_expired 0\n"));
        assert!(text.contains(
            "rootyard_storage_maintenance_jobs{backend=\"pando\",kind=\"pando_cache_hydrate\",state=\"failed\"} 0\n"
        ));
        assert!(text.contains("rootyard_storage_maintenance_repos{backend=\"gitfs\",state=\"due_scan\"} 0\n"));
        assert!(text.contains(
            "rootyard_storage_maintenance_oldest_overdue_scan_age_seconds{backend=\"pando\"} 0\n"
        ));
    }

    #[test]
    fn values_are_rendered_per_fixed_state() {
        let mut snapshot = Snapshot::default();
        snapshot.capture_oldest_age = 10_800.0;
        snapshot.capture_never_sampled = 1;
        snapshot.lease_expired = 2;
        snapshot.jobs[1] = [3, 2, 1, 4, 5, 6];
        snapshot.oldest_queued_age[1] = 600.0;
        snapshot.scan[0] = [1, 2, 3];
        snapshot.oldest_overdue[0] = 120.0;
        let mut text = String::new();
        render(&mut text, &snapshot);
        for line in [
            "rootyard_workspace_capture_oldest_age_seconds 10800\n",
            "rootyard_workspace_capture_never_sampled 1\n",
            "rootyard_workspace_lease_expired 2\n",
            "rootyard_storage_maintenance_jobs{backend=\"gitfs\",kind=\"gitfs_repack\",state=\"queued\"} 3\n",
            "rootyard_storage_maintenance_jobs{backend=\"gitfs\",kind=\"gitfs_repack\",state=\"due_queued\"} 2\n",
            "rootyard_storage_maintenance_jobs{backend=\"gitfs\",kind=\"gitfs_repack\",state=\"retry_delayed\"} 1\n",
            "rootyard_storage_maintenance_jobs{backend=\"gitfs\",kind=\"gitfs_repack\",state=\"running\"} 4\n",
            "rootyard_storage_maintenance_jobs{backend=\"gitfs\",kind=\"gitfs_repack\",state=\"expired_running_lease\"} 5\n",
            "rootyard_storage_maintenance_jobs{backend=\"gitfs\",kind=\"gitfs_repack\",state=\"failed\"} 6\n",
            "rootyard_storage_maintenance_oldest_queued_age_seconds{backend=\"gitfs\",kind=\"gitfs_repack\"} 600\n",
            "rootyard_storage_maintenance_repos{backend=\"gitfs\",state=\"missing_scan\"} 1\n",
            "rootyard_storage_maintenance_repos{backend=\"gitfs\",state=\"due_scan\"} 2\n",
            "rootyard_storage_maintenance_repos{backend=\"gitfs\",state=\"stale_generation\"} 3\n",
            "rootyard_storage_maintenance_oldest_overdue_scan_age_seconds{backend=\"gitfs\"} 120\n",
        ] {
            assert!(text.contains(line), "missing {line:?} in:\n{text}");
        }
    }

    #[test]
    fn database_strings_never_become_labels() {
        assert!(kind_index("gitfs_repack").is_some());
        assert!(kind_index("gitfs_unreachable_mark").is_none());
        assert!(kind_index("pando_tombstone_delete").is_none());
        assert!(kind_index("pando_repack\"} 1\nrootyard_evil{x=\"").is_none());
        assert!(backend_index("gitfs").is_some());
        assert!(backend_index("pando").is_some());
        assert!(backend_index("local_primary").is_none());
        for (backend, kind) in JOB_KINDS {
            assert_eq!(backend, kind.split('_').next().unwrap(), "{kind}");
        }
    }
}
