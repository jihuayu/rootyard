//! Disk watermark and safe LRU eviction for CI read mirrors, preserving `current.json`,
//! active checkout leases in `ci_checkout_jobs`, and active `refs/rootyard-ci/jobs/*` pins.
use crate::{
    AppState, Error, db,
    mirror::{Snapshot, observability, sync},
    storage,
};
use anyhow::Result;
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvictRequest {
    pub storage_generation: Option<i64>,
    pub target_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
    pub high_watermark_bytes: Option<u64>,
    pub low_watermark_bytes: Option<u64>,
    pub max_pins: Option<usize>,
    pub max_job_views: Option<usize>,
    pub max_snapshots: Option<usize>,
    pub evict_oids: Option<Vec<String>>,
    pub dry_run: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvictionReport {
    pub eviction_id: Uuid,
    pub repository_id: Uuid,
    pub storage_generation: i64,
    pub current_snapshot: Option<Uuid>,
    pub evicted_pins: i64,
    pub evicted_job_views: i64,
    pub evicted_snapshots: i64,
    pub reclaimed_bytes: i64,
    pub disk_bytes: u64,
    pub disk_bytes_before: u64,
    pub disk_bytes_after: u64,
    pub retained_pins: usize,
    pub remaining_pins: usize,
    pub retained_job_views: usize,
    pub retained_snapshots: usize,
    pub protected_oids: Vec<String>,
    pub dry_run: bool,
}

pub(crate) fn touch_path(path: &FsPath) {
    let _ = File::open(path).and_then(|f| f.set_modified(SystemTime::now()));
}

fn mtime_nanos(path: &FsPath) -> Option<u128> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
}

pub(crate) fn configured_watermarks() -> (Option<u64>, Option<u64>) {
    let high = std::env::var("ROOTYARD_MIRROR_HIGH_WATERMARK_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let low = std::env::var("ROOTYARD_MIRROR_LOW_WATERMARK_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    (high, low)
}

pub(crate) async fn evict(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    tokio::spawn(async move { run_evict_http(state, owner, name, headers, body).await })
        .await
        .map_err(Error::internal)?
}

pub(crate) async fn prune(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    tokio::spawn(async move { run_evict_http(state, owner, name, headers, body).await })
        .await
        .map_err(Error::internal)?
}

async fn run_evict_http(
    state: Arc<AppState>,
    owner: String,
    name: String,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    let input = if body.is_empty() {
        EvictRequest::default()
    } else {
        serde_json::from_slice::<EvictRequest>(&body).map_err(|_| Error::bad_request())?
    };
    if input.storage_generation.is_some_and(|g| g <= 0)
        || input
            .high_watermark_bytes
            .zip(input.low_watermark_bytes)
            .is_some_and(|(h, l)| l > h)
        || input
            .evict_oids
            .as_ref()
            .is_some_and(|oids| oids.iter().any(|oid| !crate::ci_pins::valid_oid(oid)))
    {
        return Err(Error::bad_request());
    }
    let repo = crate::mirror::repository(&state, &headers, &owner, &name).await?;
    if input
        .storage_generation
        .is_some_and(|g| g != repo.storage_generation)
    {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })?;
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    let report = evict_locked(&state, &repo, &input).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(report)).into_response())
}

pub(crate) async fn protected_target_oids(
    state: &AppState,
    repo: &db::Repository,
) -> Result<(BTreeSet<String>, usize, usize), Error> {
    let leases = crate::ci_checkouts::active_leases(&state.pool, repo.id)
        .await
        .map_err(Error::internal)?;
    let active_lease_count = leases.len();
    let mut protected: BTreeSet<String> = leases
        .into_iter()
        .filter(|l| l.storage_generation == repo.storage_generation)
        .map(|l| l.target_oid)
        .collect();
    let ci_roots = crate::ci_pins::active_pinned_oids(state, repo.id, repo.storage_generation)
        .await
        .map_err(Error::internal)?;
    let retained_ci_roots = ci_roots.len();
    protected.extend(ci_roots);
    Ok((protected, active_lease_count, retained_ci_roots))
}

pub(crate) async fn evict_locked(
    state: &AppState,
    repo: &db::Repository,
    input: &EvictRequest,
) -> Result<EvictionReport, Error> {
    let (protected, _, _) = protected_target_oids(state, repo).await?;
    let repo_root = state.storage.root.join("repos").join(repo.id.to_string());
    let report = evict_repo_directory(
        &repo_root,
        repo.id,
        repo.storage_generation,
        &protected,
        input,
    )
    .map_err(Error::internal)?;
    if !report.dry_run
        && (report.evicted_pins > 0
            || report.evicted_job_views > 0
            || report.evicted_snapshots > 0)
    {
        observability::for_state(state).record_eviction(
            report.evicted_pins as u64,
            report.evicted_job_views as u64,
            report.evicted_snapshots as u64,
            report.reclaimed_bytes as u64,
        );
        if let Ok(client) = state.pool.get().await {
            let _ = client
                .execute(
                    "INSERT INTO ci_mirror_evictions (repository_id, eviction_id, storage_generation, \
                     evicted_pins, evicted_job_views, evicted_snapshots, reclaimed_bytes) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    &[
                        &report.repository_id,
                        &report.eviction_id,
                        &report.storage_generation,
                        &report.evicted_pins,
                        &report.evicted_job_views,
                        &report.evicted_snapshots,
                        &report.reclaimed_bytes,
                    ],
                )
                .await;
        }
    }
    Ok(report)
}

pub(crate) async fn enforce_watermark_locked(state: &AppState, repo: &db::Repository) {
    let (high, low) = configured_watermarks();
    let max_snapshots = std::env::var("ROOTYARD_MIRROR_MAX_SNAPSHOTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());
    if high.is_none() && max_snapshots.is_none() {
        return;
    }
    let req = EvictRequest {
        storage_generation: Some(repo.storage_generation),
        high_watermark_bytes: high,
        low_watermark_bytes: low,
        max_snapshots,
        dry_run: Some(false),
        ..EvictRequest::default()
    };
    let _ = evict_locked(state, repo, &req).await;
}

#[derive(Clone, Debug)]
struct JobViewCandidate {
    generation: i64,
    oid: String,
    path: PathBuf,
    mtime_ns: u128,
    bytes: u64,
    protected: bool,
}

#[derive(Clone, Debug)]
struct PinCandidate {
    generation: i64,
    oid: String,
    snapshot: Uuid,
    json_path: PathBuf,
    pin_dir_path: PathBuf,
    mtime_ns: u128,
    bytes: u64,
    protected: bool,
}

#[derive(Clone, Debug)]
struct SnapshotCandidate {
    snapshot: Uuid,
    path: PathBuf,
    mtime_ns: u128,
    bytes: u64,
}

fn parse_gen_oid(stem: &str) -> Option<(i64, String)> {
    let (gen_str, oid) = stem.split_once('-')?;
    let generation: i64 = gen_str.parse().ok()?;
    (generation > 0 && crate::ci_pins::valid_oid(oid)).then(|| (generation, oid.to_owned()))
}

pub(crate) fn evict_repo_directory(
    repo_root: &FsPath,
    repo_id: Uuid,
    current_generation: i64,
    protected_oids: &BTreeSet<String>,
    input: &EvictRequest,
) -> Result<EvictionReport> {
    let dry_run = input.dry_run.unwrap_or(false);
    let eviction_id = Uuid::new_v4();
    if !repo_root.is_dir() {
        return Ok(EvictionReport {
            eviction_id,
            repository_id: repo_id,
            storage_generation: current_generation,
            current_snapshot: None,
            evicted_pins: 0,
            evicted_job_views: 0,
            evicted_snapshots: 0,
            reclaimed_bytes: 0,
            disk_bytes: 0,
            disk_bytes_before: 0,
            disk_bytes_after: 0,
            retained_pins: 0,
            remaining_pins: 0,
            retained_job_views: 0,
            retained_snapshots: 0,
            protected_oids: protected_oids.iter().cloned().collect(),
            dry_run,
        });
    }

    sync::verify_directory(repo_root)?;
    let current_snapshot = match sync::read_regular(&repo_root.join("current.json"), 4096) {
        Ok(bytes) => {
            let snap: Snapshot = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                snap.repository_id == repo_id,
                "mirror current.json repository mismatch"
            );
            Some(snap.snapshot)
        }
        Err(_) => None,
    };

    let disk_bytes_before = storage::disk_bytes(repo_root, u64::MAX)?;
    let effective_target = input.target_bytes.or(input.max_bytes);
    let explicit_oids: BTreeSet<String> = input
        .evict_oids
        .as_ref()
        .map(|v| v.iter().cloned().collect())
        .unwrap_or_default();

    let mut job_views = Vec::new();
    let views_dir = repo_root.join("job-views");
    if views_dir.is_dir() {
        for entry in std::fs::read_dir(&views_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some((generation, oid)) = name.strip_suffix(".git").and_then(parse_gen_oid) else {
                continue;
            };
            let path = entry.path();
            if path.is_dir() {
                let mtime_ns = mtime_nanos(&path.join("HEAD"))
                    .or_else(|| mtime_nanos(&path))
                    .unwrap_or(0);
                let bytes = storage::disk_bytes(&path, u64::MAX).unwrap_or(0);
                let protected =
                    generation == current_generation && protected_oids.contains(oid.as_str());
                job_views.push(JobViewCandidate {
                    generation,
                    oid,
                    path,
                    mtime_ns,
                    bytes,
                    protected,
                });
            }
        }
    }

    let mut pins = Vec::new();
    let mut snapshots = HashMap::new();
    for entry in std::fs::read_dir(repo_root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if let Some((generation, oid)) = name
            .strip_prefix("pin-")
            .and_then(|s| s.strip_suffix(".json"))
            .and_then(parse_gen_oid)
        {
            if let Ok(bytes) = sync::read_regular(&path, 4096)
                && let Ok(meta) = serde_json::from_slice::<Snapshot>(&bytes) {
                    let pin_dir_path = repo_root
                        .join(meta.snapshot.to_string())
                        .join("pins")
                        .join(format!("{oid}.git"));
                    let dir_bytes = if pin_dir_path.is_dir() {
                        storage::disk_bytes(&pin_dir_path, u64::MAX).unwrap_or(0)
                    } else {
                        0
                    };
                    let mtime_ns = mtime_nanos(&path).unwrap_or(0);
                    let protected =
                        generation == current_generation && protected_oids.contains(oid.as_str());
                    pins.push(PinCandidate {
                        generation,
                        oid,
                        snapshot: meta.snapshot,
                        json_path: path,
                        pin_dir_path,
                        mtime_ns,
                        bytes: (bytes.len() as u64).saturating_add(dir_bytes),
                        protected,
                    });
                }
        } else if let Ok(snap_uuid) = name.parse::<Uuid>()
            && path.is_dir() {
                let mtime_ns = mtime_nanos(&path).unwrap_or(0);
                let bytes = storage::disk_bytes(&path, u64::MAX).unwrap_or(0);
                snapshots.insert(
                    snap_uuid,
                    SnapshotCandidate {
                        snapshot: snap_uuid,
                        path,
                        mtime_ns,
                        bytes,
                    },
                );
            }
    }

    if let Some(high) = input.high_watermark_bytes
        && disk_bytes_before <= high
            && effective_target.is_none()
            && input.max_pins.is_none()
            && input.max_job_views.is_none()
            && input.max_snapshots.is_none()
            && explicit_oids.is_empty()
        {
            return Ok(EvictionReport {
                eviction_id,
                repository_id: repo_id,
                storage_generation: current_generation,
                current_snapshot,
                evicted_pins: 0,
                evicted_job_views: 0,
                evicted_snapshots: 0,
                reclaimed_bytes: 0,
                disk_bytes: disk_bytes_before,
                disk_bytes_before,
                disk_bytes_after: disk_bytes_before,
                retained_pins: pins.len(),
                remaining_pins: pins.len(),
                retained_job_views: job_views.len(),
                retained_snapshots: snapshots.len(),
                protected_oids: protected_oids.iter().cloned().collect(),
                dry_run,
            });
        }

    let byte_goal = if let Some(high) = input.high_watermark_bytes {
        input
            .low_watermark_bytes
            .or(effective_target)
            .unwrap_or(high.saturating_mul(80) / 100)
    } else if let Some(target) = effective_target {
        target
    } else if input.max_pins.is_some()
        || input.max_job_views.is_some()
        || input.max_snapshots.is_some()
        || !explicit_oids.is_empty()
    {
        u64::MAX
    } else {
        0
    };

    let mut current_bytes = disk_bytes_before;
    let mut reclaimed_bytes = 0u64;
    let mut evicted_job_views = 0i64;
    let mut evicted_pins = 0i64;
    let mut evicted_snapshots = 0i64;

    job_views.sort_by(|a, b| {
        (a.generation == current_generation, a.mtime_ns, &a.oid).cmp(&(
            b.generation == current_generation,
            b.mtime_ns,
            &b.oid,
        ))
    });
    let mut retained_job_views = job_views.len();
    for view in &job_views {
        if view.protected {
            continue;
        }
        if view.generation != current_generation
            || explicit_oids.contains(&view.oid)
            || input
                .max_job_views
                .is_some_and(|max| retained_job_views > max)
            || current_bytes > byte_goal
        {
            if !dry_run && view.path.exists() {
                std::fs::remove_dir_all(&view.path)?;
            }
            evicted_job_views += 1;
            retained_job_views = retained_job_views.saturating_sub(1);
            reclaimed_bytes = reclaimed_bytes.saturating_add(view.bytes);
            current_bytes = current_bytes.saturating_sub(view.bytes);
        }
    }

    let mut snap_pin_refs: HashMap<Uuid, usize> = HashMap::new();
    for pin in &pins {
        *snap_pin_refs.entry(pin.snapshot).or_insert(0) += 1;
    }

    pins.sort_by(|a, b| {
        (a.generation == current_generation, a.mtime_ns, &a.oid).cmp(&(
            b.generation == current_generation,
            b.mtime_ns,
            &b.oid,
        ))
    });
    let mut retained_pins = pins.len();
    for pin in &pins {
        if pin.protected {
            continue;
        }
        let over_snap_count = input
            .max_snapshots
            .is_some_and(|max| snapshots.len() > max && Some(pin.snapshot) != current_snapshot);
        if pin.generation != current_generation
            || explicit_oids.contains(&pin.oid)
            || input.max_pins.is_some_and(|max| retained_pins > max)
            || over_snap_count
            || current_bytes > byte_goal
        {
            if !dry_run {
                if pin.json_path.exists() {
                    let _ = std::fs::remove_file(&pin.json_path);
                }
                if pin.pin_dir_path.exists() {
                    let _ = std::fs::remove_dir_all(&pin.pin_dir_path);
                }
            }
            evicted_pins += 1;
            retained_pins = retained_pins.saturating_sub(1);
            reclaimed_bytes = reclaimed_bytes.saturating_add(pin.bytes);
            current_bytes = current_bytes.saturating_sub(pin.bytes);
            if let Some(count) = snap_pin_refs.get_mut(&pin.snapshot) {
                *count = count.saturating_sub(1);
            }
        }
    }

    let mut unreferenced_snapshots: Vec<SnapshotCandidate> = snapshots
        .values()
        .filter(|s| {
            Some(s.snapshot) != current_snapshot
                && snap_pin_refs.get(&s.snapshot).copied().unwrap_or(0) == 0
        })
        .cloned()
        .collect();
    unreferenced_snapshots.sort_by(|a, b| {
        (a.mtime_ns, a.snapshot.to_string()).cmp(&(b.mtime_ns, b.snapshot.to_string()))
    });
    let mut retained_snapshots = snapshots.len();
    for snap in &unreferenced_snapshots {
        if input
            .max_snapshots
            .is_some_and(|max| retained_snapshots > max)
            || current_bytes > byte_goal
            || byte_goal == 0
        {
            if !dry_run && snap.path.exists() {
                std::fs::remove_dir_all(&snap.path)?;
            }
            evicted_snapshots += 1;
            retained_snapshots = retained_snapshots.saturating_sub(1);
            reclaimed_bytes = reclaimed_bytes.saturating_add(snap.bytes);
            current_bytes = current_bytes.saturating_sub(snap.bytes);
        }
    }

    let disk_bytes_after = if dry_run {
        current_bytes
    } else {
        if evicted_pins > 0 || evicted_job_views > 0 || evicted_snapshots > 0 {
            let _ = File::open(repo_root).and_then(|f| f.sync_all());
        }
        storage::disk_bytes(repo_root, u64::MAX).unwrap_or(0)
    };
    let actual_reclaimed = disk_bytes_before
        .saturating_sub(disk_bytes_after)
        .max(reclaimed_bytes);

    Ok(EvictionReport {
        eviction_id,
        repository_id: repo_id,
        storage_generation: current_generation,
        current_snapshot,
        evicted_pins,
        evicted_job_views,
        evicted_snapshots,
        reclaimed_bytes: actual_reclaimed as i64,
        disk_bytes: disk_bytes_after,
        disk_bytes_before,
        disk_bytes_after,
        retained_pins,
        remaining_pins: retained_pins,
        retained_job_views,
        retained_snapshots,
        protected_oids: protected_oids.iter().cloned().collect(),
        dry_run,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_preserves_current_snapshot_and_protected_oids_while_evicting_lru() {
        let temp = tempfile::tempdir().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo_id = Uuid::new_v4();
        let (old_prot, old_unprot, cur_snap) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        for snap in [old_prot, old_unprot, cur_snap] {
            let dir = repo_root.join(snap.to_string());
            sync::private_directory(&dir).unwrap();
            sync::private_directory(&dir.join("repository.git")).unwrap();
            sync::private_directory(&dir.join("pins")).unwrap();
            std::fs::write(dir.join("repository.git/pack-data"), vec![b'x'; 2048]).unwrap();
        }
        let cur_meta = Snapshot {
            repository_id: repo_id,
            storage_generation: 1,
            object_format: "sha1".into(),
            snapshot: cur_snap,
        };
        sync::atomic_file(
            &repo_root,
            "current.json",
            &serde_json::to_vec(&cur_meta).unwrap(),
        )
        .unwrap();

        let (oid_prot, oid_unprot) = ("a".repeat(40), "b".repeat(40));
        let views_dir = repo_root.join("job-views");
        sync::private_directory(&views_dir).unwrap();
        for (oid, snap) in [(&oid_prot, old_prot), (&oid_unprot, old_unprot)] {
            let pin_dir = repo_root
                .join(snap.to_string())
                .join("pins")
                .join(format!("{oid}.git"));
            sync::private_directory(&pin_dir).unwrap();
            std::fs::write(pin_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
            let meta = Snapshot {
                repository_id: repo_id,
                storage_generation: 1,
                object_format: "sha1".into(),
                snapshot: snap,
            };
            sync::atomic_file(
                &repo_root,
                &format!("pin-1-{oid}.json"),
                &serde_json::to_vec(&meta).unwrap(),
            )
            .unwrap();
            let vdir = views_dir.join(format!("1-{oid}.git"));
            sync::private_directory(&vdir).unwrap();
            std::fs::write(vdir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        }

        let protected = BTreeSet::from([oid_prot.clone()]);
        let req = EvictRequest {
            target_bytes: Some(1),
            ..EvictRequest::default()
        };
        let report = evict_repo_directory(&repo_root, repo_id, 1, &protected, &req).unwrap();

        assert_eq!(
            (
                report.evicted_pins,
                report.evicted_job_views,
                report.evicted_snapshots
            ),
            (1, 1, 1)
        );
        assert!(report.reclaimed_bytes > 0);
        assert!(
            repo_root.join("current.json").is_file()
                && repo_root.join(cur_snap.to_string()).is_dir()
        );
        assert!(repo_root.join(old_prot.to_string()).is_dir());
        assert!(repo_root.join(format!("pin-1-{oid_prot}.json")).is_file());
        assert!(views_dir.join(format!("1-{oid_prot}.git")).is_dir());
        assert!(!repo_root.join(old_unprot.to_string()).exists());
        assert!(!repo_root.join(format!("pin-1-{oid_unprot}.json")).exists());
        assert!(!views_dir.join(format!("1-{oid_unprot}.git")).exists());
    }
}
