//! Mirror operational status endpoint and fixed-cardinality Prometheus metrics.
use crate::{
    AppState, Error, db,
    mirror::{Snapshot, eviction, limiter, sync},
    storage,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Write,
    path::Path as FsPath,
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

static COUNTERS: LazyLock<Mutex<HashMap<Uuid, Arc<MirrorCounters>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Default)]
pub struct MirrorCounters {
    pub syncs_succeeded: AtomicU64,
    pub syncs_failed: AtomicU64,
    pub prepares_succeeded: AtomicU64,
    pub rate_limited: AtomicU64,
    pub evictions: AtomicU64,
    pub evicted_pins: AtomicU64,
    pub evicted_job_views: AtomicU64,
    pub evicted_snapshots: AtomicU64,
    pub reclaimed_bytes: AtomicU64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct VolumeTotals {
    pub disk_bytes: u64,
    pub snapshots: usize,
    pub pins: usize,
    pub job_views: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct RepoInspection {
    pub current_snapshot: Option<Uuid>,
    pub snapshot_count: usize,
    pub pin_count: usize,
    pub job_view_count: usize,
    pub active_leases: usize,
    pub retained_ci_roots: usize,
    pub protected_oids: Vec<String>,
    pub disk_bytes: u64,
}

fn saturating_add(target: &AtomicU64, amount: u64) {
    let mut current = target.load(Ordering::Relaxed);
    loop {
        match target.compare_exchange_weak(
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

impl MirrorCounters {
    pub fn record_sync_success(&self) {
        saturating_add(&self.syncs_succeeded, 1);
    }

    pub fn record_sync_failure(&self) {
        saturating_add(&self.syncs_failed, 1);
    }

    pub fn record_prepare_success(&self) {
        saturating_add(&self.prepares_succeeded, 1);
    }

    pub fn record_rate_limited(&self) {
        saturating_add(&self.rate_limited, 1);
    }

    pub fn record_eviction(
        &self,
        pins: u64,
        job_views: u64,
        snapshots: u64,
        reclaimed_bytes: u64,
    ) {
        saturating_add(&self.evictions, 1);
        saturating_add(&self.evicted_pins, pins);
        saturating_add(&self.evicted_job_views, job_views);
        saturating_add(&self.evicted_snapshots, snapshots);
        saturating_add(&self.reclaimed_bytes, reclaimed_bytes);
    }
}

pub fn init_for_state(state: &AppState) -> Arc<MirrorCounters> {
    let counters = Arc::new(MirrorCounters::default());
    let mut map = COUNTERS.lock().expect("mirror counters registry poisoned");
    map.insert(state.storage.volume_id, counters.clone());
    counters
}

pub fn for_state(state: &AppState) -> Arc<MirrorCounters> {
    let mut map = COUNTERS.lock().expect("mirror counters registry poisoned");
    map.entry(state.storage.volume_id)
        .or_insert_with(|| Arc::new(MirrorCounters::default()))
        .clone()
}

pub(crate) async fn inspect_repo_status(
    state: &AppState,
    repo: &db::Repository,
) -> Result<RepoInspection, Error> {
    let (protected, active_leases, retained_ci_roots) =
        eviction::protected_target_oids(state, repo).await?;
    let repo_root = state.storage.root.join("repos").join(repo.id.to_string());
    if !repo_root.is_dir() {
        return Ok(RepoInspection {
            current_snapshot: None,
            snapshot_count: 0,
            pin_count: 0,
            job_view_count: 0,
            active_leases,
            retained_ci_roots,
            protected_oids: protected.into_iter().collect(),
            disk_bytes: 0,
        });
    }
    let current_snapshot = sync::read_regular(&repo_root.join("current.json"), 4096)
        .ok()
        .and_then(|b| serde_json::from_slice::<Snapshot>(&b).ok())
        .filter(|s| s.repository_id == repo.id && s.storage_generation == repo.storage_generation)
        .map(|s| s.snapshot);
    let mut snapshot_count = 0usize;
    let mut pin_count = 0usize;
    if let Ok(entries) = std::fs::read_dir(&repo_root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("pin-") && name.ends_with(".json") {
                pin_count += 1;
            } else if name.parse::<Uuid>().is_ok() && entry.path().is_dir() {
                snapshot_count += 1;
            }
        }
    }
    let job_view_count = std::fs::read_dir(repo_root.join("job-views"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".git") && e.path().is_dir())
                .count()
        })
        .unwrap_or(0);
    let disk_bytes = storage::disk_bytes(&repo_root, u64::MAX).unwrap_or(0);
    Ok(RepoInspection {
        current_snapshot,
        snapshot_count,
        pin_count,
        job_view_count,
        active_leases,
        retained_ci_roots,
        protected_oids: protected.into_iter().collect(),
        disk_bytes,
    })
}

pub(crate) fn scan_volume_totals(repos_root: &FsPath) -> VolumeTotals {
    if !repos_root.is_dir() {
        return VolumeTotals::default();
    }
    let disk_bytes = storage::disk_bytes(repos_root, u64::MAX).unwrap_or(0);
    let mut snapshots = 0usize;
    let mut pins = 0usize;
    let mut job_views = 0usize;
    if let Ok(repos) = std::fs::read_dir(repos_root) {
        for repo_entry in repos.flatten().filter(|e| e.path().is_dir()) {
            let repo_path = repo_entry.path();
            if let Ok(entries) = std::fs::read_dir(&repo_path) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with("pin-") && name.ends_with(".json") {
                        pins += 1;
                    } else if name.parse::<Uuid>().is_ok() && entry.path().is_dir() {
                        snapshots += 1;
                    }
                }
            }
            if let Ok(views) = std::fs::read_dir(repo_path.join("job-views")) {
                job_views += views
                    .flatten()
                    .filter(|v| {
                        v.file_name().to_string_lossy().ends_with(".git") && v.path().is_dir()
                    })
                    .count();
            }
        }
    }
    VolumeTotals {
        disk_bytes,
        snapshots,
        pins,
        job_views,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MirrorRepoStatus {
    pub repository_id: Uuid,
    pub storage_generation: i64,
    pub current_snapshot: Option<Uuid>,
    pub ready: bool,
    pub snapshot_count: usize,
    pub pin_count: usize,
    pub job_view_count: usize,
    pub active_leases: usize,
    pub active_lease_count: usize,
    pub retained_ci_roots: usize,
    pub protected_oids: Vec<String>,
    pub disk_bytes: u64,
    pub max_repo_bytes: u64,
    pub high_watermark_bytes: Option<u64>,
    pub low_watermark_bytes: Option<u64>,
    pub syncs_in_flight: usize,
    pub sync_in_flight: usize,
    pub sync_capacity: usize,
    pub sync_limit: usize,
    pub closures_in_flight: usize,
    pub closure_capacity: usize,
    pub syncs_succeeded_total: u64,
    pub syncs_failed_total: u64,
    pub prepares_total: u64,
    pub evictions_total: u64,
    pub evicted_pins_total: u64,
    pub evicted_job_views_total: u64,
    pub evicted_snapshots_total: u64,
    pub reclaimed_bytes_total: u64,
    pub rate_limited_total: u64,
}

pub(crate) async fn status(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let repo = crate::mirror::repository(&state, &headers, &owner, &name).await?;
    let info = inspect_repo_status(&state, &repo).await?;
    let lim = limiter::for_state(&state);
    let cnt = for_state(&state);
    let (high_wm, low_wm) = eviction::configured_watermarks();
    let sync_in_flight = lim.sync_in_flight();
    let sync_limit = lim.max_concurrent_syncs;
    let payload = MirrorRepoStatus {
        repository_id: repo.id,
        storage_generation: repo.storage_generation,
        current_snapshot: info.current_snapshot,
        ready: info.current_snapshot.is_some(),
        snapshot_count: info.snapshot_count,
        pin_count: info.pin_count,
        job_view_count: info.job_view_count,
        active_leases: info.active_leases,
        active_lease_count: info.active_leases,
        retained_ci_roots: info.retained_ci_roots,
        protected_oids: info.protected_oids,
        disk_bytes: info.disk_bytes,
        max_repo_bytes: state.config.max_repo_bytes,
        high_watermark_bytes: high_wm,
        low_watermark_bytes: low_wm,
        syncs_in_flight: sync_in_flight,
        sync_in_flight,
        sync_capacity: sync_limit,
        sync_limit,
        closures_in_flight: lim.closure_in_flight(),
        closure_capacity: lim.max_concurrent_closures,
        syncs_succeeded_total: cnt.syncs_succeeded.load(Ordering::Relaxed),
        syncs_failed_total: cnt.syncs_failed.load(Ordering::Relaxed),
        prepares_total: cnt.prepares_succeeded.load(Ordering::Relaxed),
        evictions_total: cnt.evictions.load(Ordering::Relaxed),
        evicted_pins_total: cnt.evicted_pins.load(Ordering::Relaxed),
        evicted_job_views_total: cnt.evicted_job_views.load(Ordering::Relaxed),
        evicted_snapshots_total: cnt.evicted_snapshots.load(Ordering::Relaxed),
        reclaimed_bytes_total: cnt.reclaimed_bytes.load(Ordering::Relaxed),
        rate_limited_total: cnt.rate_limited.load(Ordering::Relaxed),
    };
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(payload)).into_response())
}

async fn query_active_leases(state: &AppState) -> anyhow::Result<i64> {
    let mut client = state.pool.get().await?;
    let tx = client.build_transaction().read_only(true).start().await?;
    tx.batch_execute("SET LOCAL statement_timeout = '4000ms'")
        .await?;
    let row = tx
        .query_one(
            "SELECT count(*) FROM ci_checkout_jobs \
             WHERE NOT cancelled AND NOT revoked AND plan IS NOT NULL \
               AND expires_unix > extract(epoch FROM clock_timestamp())",
            &[],
        )
        .await?;
    tx.commit().await?;
    Ok(row.get(0))
}

pub(crate) async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let active_leases = tokio::time::timeout(Duration::from_secs(5), query_active_leases(&state))
        .await
        .ok()
        .and_then(Result::ok);
    let status_code = if active_leases.is_some() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let volume = scan_volume_totals(&state.storage.root.join("repos"));
    let lim = limiter::for_state(&state);
    let cnt = for_state(&state);
    let git_capacity = state.config.max_concurrent_git;
    let git_in_flight = git_capacity.saturating_sub(state.git_slots.available_permits());
    let body = render_prometheus(
        git_capacity,
        git_in_flight,
        &lim,
        &cnt,
        &volume,
        active_leases,
    );
    (
        status_code,
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

fn counter(output: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    let _ = writeln!(
        output,
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
    );
}

pub(crate) fn render_prometheus(
    git_capacity: usize,
    git_in_flight: usize,
    lim: &limiter::MirrorLimiter,
    cnt: &MirrorCounters,
    volume: &VolumeTotals,
    active_leases: Option<i64>,
) -> String {
    let mut output = String::new();
    let db_up = u8::from(active_leases.is_some());
    gauge(
        &mut output,
        "rootyard_postgres_up",
        "Whether the authoritative database query succeeded.",
        db_up,
    );
    gauge(
        &mut output,
        "rootyard_mirror_postgres_up",
        "Whether the mirror database authority check succeeded.",
        db_up,
    );
    gauge(
        &mut output,
        "rootyard_git_capacity",
        "Configured concurrent native Git capacity.",
        git_capacity,
    );
    gauge(
        &mut output,
        "rootyard_git_in_flight",
        "Occupied native Git slots on the mirror.",
        git_in_flight,
    );
    gauge(
        &mut output,
        "rootyard_mirror_sync_capacity",
        "Configured maximum concurrent mirror sync operations.",
        lim.max_concurrent_syncs,
    );
    gauge(
        &mut output,
        "rootyard_mirror_sync_limit",
        "Configured maximum concurrent mirror sync operations.",
        lim.max_concurrent_syncs,
    );
    gauge(
        &mut output,
        "rootyard_mirror_sync_in_flight",
        "Currently running mirror sync operations.",
        lim.sync_in_flight(),
    );
    gauge(
        &mut output,
        "rootyard_mirror_closure_capacity",
        "Configured maximum concurrent job view closure materializations.",
        lim.max_concurrent_closures,
    );
    gauge(
        &mut output,
        "rootyard_mirror_closure_in_flight",
        "Currently running job view closure materializations.",
        lim.closure_in_flight(),
    );
    gauge(
        &mut output,
        "rootyard_mirror_disk_bytes",
        "Total bytes stored under the mirror repositories root.",
        volume.disk_bytes,
    );
    gauge(
        &mut output,
        "rootyard_mirror_snapshots",
        "Total published snapshot directories on the mirror volume.",
        volume.snapshots,
    );
    gauge(
        &mut output,
        "rootyard_mirror_pins",
        "Total pin metadata receipts on the mirror volume.",
        volume.pins,
    );
    gauge(
        &mut output,
        "rootyard_mirror_job_views",
        "Total materialized isolated job views on the mirror volume.",
        volume.job_views,
    );
    if let Some(leases) = active_leases {
        gauge(
            &mut output,
            "rootyard_mirror_active_leases",
            "Active unexpired CI checkout leases in PostgreSQL.",
            leases,
        );
    }
    let sync_ok = cnt.syncs_succeeded.load(Ordering::Relaxed);
    let sync_err = cnt.syncs_failed.load(Ordering::Relaxed);
    let _ = writeln!(
        output,
        "# HELP rootyard_mirror_syncs_total Mirror snapshot sync operations by outcome.\n\
         # TYPE rootyard_mirror_syncs_total counter\n\
         rootyard_mirror_syncs_total{{outcome=\"success\"}} {sync_ok}\n\
         rootyard_mirror_syncs_total{{outcome=\"failure\"}} {sync_err}"
    );
    counter(
        &mut output,
        "rootyard_mirror_sync_total",
        "Total completed mirror snapshot sync attempts.",
        sync_ok.saturating_add(sync_err),
    );
    counter(
        &mut output,
        "rootyard_mirror_prepares_total",
        "Total successful mirror prepare validations.",
        cnt.prepares_succeeded.load(Ordering::Relaxed),
    );
    let rate_limited = cnt.rate_limited.load(Ordering::Relaxed);
    counter(
        &mut output,
        "rootyard_mirror_rate_limited_total",
        "Mirror requests rejected by sync or closure rate limiting.",
        rate_limited,
    );
    counter(
        &mut output,
        "rootyard_mirror_sync_rate_limited_total",
        "Mirror sync requests rejected by rate limiting.",
        rate_limited,
    );
    counter(
        &mut output,
        "rootyard_mirror_evictions_total",
        "Total mirror eviction runs that removed artifacts.",
        cnt.evictions.load(Ordering::Relaxed),
    );
    let pins = cnt.evicted_pins.load(Ordering::Relaxed);
    let views = cnt.evicted_job_views.load(Ordering::Relaxed);
    let snaps = cnt.evicted_snapshots.load(Ordering::Relaxed);
    let _ = writeln!(
        output,
        "# HELP rootyard_mirror_evicted_items_total Mirror artifacts evicted by kind.\n\
         # TYPE rootyard_mirror_evicted_items_total counter\n\
         rootyard_mirror_evicted_items_total{{kind=\"pins\"}} {pins}\n\
         rootyard_mirror_evicted_items_total{{kind=\"job_views\"}} {views}\n\
         rootyard_mirror_evicted_items_total{{kind=\"snapshots\"}} {snaps}"
    );
    counter(
        &mut output,
        "rootyard_mirror_reclaimed_bytes_total",
        "Total disk bytes reclaimed by mirror eviction.",
        cnt.reclaimed_bytes.load(Ordering::Relaxed),
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn prometheus_rendering_is_fixed_cardinality_and_tracks_counters() {
        let lim = limiter::MirrorLimiter::new(4, 2, Duration::ZERO);
        let cnt = MirrorCounters::default();
        cnt.record_sync_success();
        cnt.record_sync_failure();
        cnt.record_prepare_success();
        cnt.record_rate_limited();
        cnt.record_eviction(2, 3, 1, 8192);
        let vol = VolumeTotals {
            disk_bytes: 65536,
            snapshots: 2,
            pins: 3,
            job_views: 1,
        };
        let text = render_prometheus(8, 1, &lim, &cnt, &vol, Some(5));
        assert!(text.contains("rootyard_postgres_up 1"));
        assert!(text.contains("rootyard_mirror_sync_capacity 4"));
        assert!(text.contains("rootyard_mirror_active_leases 5"));
        assert!(text.contains("rootyard_mirror_syncs_total{outcome=\"success\"} 1"));
        assert!(text.contains("rootyard_mirror_syncs_total{outcome=\"failure\"} 1"));
        assert!(text.contains("rootyard_mirror_rate_limited_total 1"));
        assert!(text.contains("rootyard_mirror_evictions_total 1"));
        assert!(text.contains("rootyard_mirror_evicted_items_total{kind=\"pins\"} 2"));
        assert!(text.contains("rootyard_mirror_evicted_items_total{kind=\"job_views\"} 3"));
        assert!(text.contains("rootyard_mirror_evicted_items_total{kind=\"snapshots\"} 1"));
        assert!(text.contains("rootyard_mirror_reclaimed_bytes_total 8192"));
    }
}
