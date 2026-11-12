//! Mandatory full reconciliation for edits made by normal editors and Git.
//!
//! The background scanner is split into three phases:
//! 1. a short eligibility read with no row lock and no filesystem work;
//! 2. a bounded off-thread, frozen fingerprint scan;
//! 3. a short `FOR UPDATE` transaction that revalidates host, lease epoch and
//!    revision, then commits the fingerprint, revision bump and event together.
//!
//! API mutations (`create`, `restore`, `files::put`, `files::git`) compute
//! their post-write baseline off-thread on the bounded workspace I/O bulkhead
//! outside any PostgreSQL transaction, then persist the pre-computed
//! fingerprint atomically with the workspace revision in their short commit
//! transaction while fencing concurrent background scans via [`super::blocking`].
use super::{scan, service};
use crate::{
    AppState, Error,
    observability::{
        self,
        worker::{OperationContext, Phase, WorkerKind},
    },
};
use futures_util::StreamExt;
use serde_json::json;
use std::{path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const PAGE: i64 = 100;

/// Fingerprint of the workspace as the overlay exposes it, built from raw
/// service-owned layers.
///
/// This must not read the mount: inside a freeze a mount `stat`/`read` queues
/// behind the kernel inode lock of a parked write, the freeze waits for this
/// scan, the scan waits for that write and the write waits for the thaw. See
/// [`super::snapshot`] for the raw merged inventory, upper overrides, whiteouts
/// and the lazy manifest, and for the preserved byte format of the hash.
pub(super) fn fingerprint(repo: &Path) -> Result<String, Error> {
    super::snapshot::fingerprint(repo)
}

/// A workspace with no stored baseline only records one; it never invents a
/// revision. A differing baseline means a native edit the API did not record.
fn capture_changes(previous: Option<&str>, scanned: &str) -> bool {
    previous.is_some_and(|stored| stored != scanned)
}

/// A scan result is only usable when the row it was started from is still the
/// row we are about to write: same revision and same lease epoch.
fn scan_is_current(expected_revision: i64, expected_epoch: i64, revision: i64, epoch: i64) -> bool {
    revision == expected_revision && epoch == expected_epoch
}

/// Persist a pre-computed post-mutation fingerprint inside the caller's short
/// commit transaction without performing any filesystem I/O while locks are held.
pub(super) async fn record_fingerprint(
    tx: &deadpool_postgres::Transaction<'_>,
    id: Uuid,
    value: &str,
) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO workspace_capture_state(workspace_id,fingerprint) VALUES($1,$2) \
         ON CONFLICT(workspace_id) DO UPDATE SET fingerprint=$2,scanned_at=clock_timestamp()",
        &[&id, &value],
    )
    .await
    .map_err(Error::internal)?;
    Ok(())
}

async fn eligible_page(state: &AppState, cursor: Option<Uuid>) -> Result<Vec<(Uuid, i64, i64)>, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT id,lease_epoch,EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces \
             WHERE host_id=$1 AND state='ready' AND lease_until>clock_timestamp() \
             AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT $3",
            &[&state.storage.volume_id, &cursor, &PAGE],
        )
        .await
        .map_err(Error::internal)?;
    Ok(rows.iter().map(|row| (row.get(0), row.get(1), row.get(2))).collect())
}

async fn eligible(state: &AppState, id: Uuid) -> Result<Option<(i64, i64)>, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT revision,lease_epoch FROM workspaces \
             WHERE id=$1 AND host_id=$2 AND state='ready' AND lease_until>clock_timestamp()",
            &[&id, &state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    Ok(row.map(|row| (row.get(0), row.get(1))))
}

fn scan_workspace_fingerprint(repo: &Path, stable_gate: bool) -> Result<String, Error> {
    let before = fingerprint(repo)?;
    if stable_gate {
        return Ok(before);
    }
    let after = fingerprint(repo)?;
    if before != after {
        return Err(service::conflict());
    }
    Ok(after)
}

pub async fn reconcile_one(state: &AppState, id: Uuid) -> Result<bool, Error> {
    if !super::mounts::mounted(id) {
        return Ok(false);
    }
    let Some(scan_token) = super::blocking::begin_scan(id) else {
        return Ok(false);
    };
    let Some((expected_revision, expected_epoch)) = eligible(state, id).await? else {
        return Ok(false);
    };
    let repo = service::workspace_repo(state, id);
    let stable_gate = super::mounts::enabled();
    let scanned = match scan::frozen_with_token(id, scan::timeout(), Some(scan_token.clone()), move || {
        scan_workspace_fingerprint(&repo, stable_gate)
    })
    .await
    {
        Ok(value) => value,
        // A busy bounded pool is skipped; the fair cursor keeps this workspace
        // eligible on the next round.
        Err(scan::ScanFailure::Busy) => return Ok(false),
        // A worker that never returned is reported here, in the async reconcile
        // scope, with the fixed `timeout` label and no source text.
        Err(scan::ScanFailure::Timeout) => {
            observability::observe_timeout();
            return Ok(false);
        }
        Err(scan::ScanFailure::Failed(error)) => return Err(error),
    };
    commit_reconciled(state, id, expected_revision, expected_epoch, Some(&scan_token), &scanned).await
}

/// Reconcile native worktree/index edits on the foreground Data I/O bulkhead
/// when the caller already owns [`super::blocking::MutationGuard`]
/// (`checkpoints::create`), propagating `503`/`504` errors instead of skipping.
pub(super) async fn reconcile_locked(
    state: &AppState,
    id: Uuid,
    guard: &super::blocking::MutationGuard,
) -> Result<bool, Error> {
    if !super::mounts::mounted(id) {
        return Err(Error::internal("workspace FUSE mount missing"));
    }
    let Some((expected_revision, expected_epoch)) = eligible(state, id).await? else {
        return Ok(false);
    };
    let repo = service::workspace_repo(state, id);
    let stable_gate = super::mounts::enabled();
    let freeze_guard = guard.freeze_guard();
    let scanned = super::blocking::run(move || {
        let _freeze = freeze_guard;
        let out = super::mounts::with_frozen(id, || scan_workspace_fingerprint(&repo, stable_gate));
        drop(_freeze);
        out
    })
    .await?;
    commit_reconciled(state, id, expected_revision, expected_epoch, None, &scanned).await
}

async fn commit_reconciled(
    state: &AppState,
    id: Uuid,
    expected_revision: i64,
    expected_epoch: i64,
    scan_token: Option<&super::blocking::ScanToken>,
    scanned: &str,
) -> Result<bool, Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx
        .query_opt(
            "SELECT revision,lease_epoch FROM workspaces \
             WHERE id=$1 AND host_id=$2 AND state='ready' AND lease_until>clock_timestamp() FOR UPDATE",
            &[&id, &state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let revision: i64 = row.get(0);
    let epoch: i64 = row.get(1);
    if !scan_is_current(expected_revision, expected_epoch, revision, epoch)
        || scan_token.is_some_and(|token| !token.is_unchanged())
    {
        return Ok(false);
    }
    let previous = tx
        .query_opt("SELECT fingerprint FROM workspace_capture_state WHERE workspace_id=$1 FOR UPDATE", &[&id])
        .await
        .map_err(Error::internal)?;
    let changed = capture_changes(previous.as_ref().map(|row| row.get::<_, String>(0)).as_deref(), scanned);
    tx.execute(
        "INSERT INTO workspace_capture_state(workspace_id,fingerprint) VALUES($1,$2) \
         ON CONFLICT(workspace_id) DO UPDATE SET fingerprint=$2,scanned_at=clock_timestamp()",
        &[&id, &scanned],
    )
    .await
    .map_err(Error::internal)?;
    if changed {
        let next = revision + 1;
        let updated = tx
            .execute(
                "UPDATE workspaces SET revision=$2 \
                 WHERE id=$1 AND revision=$3 AND lease_epoch=$4 AND host_id=$5",
                &[&id, &next, &revision, &epoch, &state.storage.volume_id],
            )
            .await
            .map_err(Error::internal)?;
        if updated != 1 {
            return Ok(false);
        }
        let payload = json!({
            "revision": next,
            "lease_epoch": epoch,
            "fingerprint": scanned,
            "source": "native_scan"
        });
        tx.execute(
            "INSERT INTO workspace_events(workspace_id,revision,kind,payload) \
             VALUES($1,$2,'external_capture',$3)",
            &[&id, &next, &payload],
        )
        .await
        .map_err(Error::internal)?;
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok(changed)
}

async fn process_page(state: &AppState, ids: Vec<Uuid>, operation: &OperationContext) {
    futures_util::stream::iter(ids)
        .map(|id| {
            let operation = operation.clone();
            async move {
                let _ = observability::worker::run(&operation, Phase::Reconcile, reconcile_one(state, id)).await;
            }
        })
        .buffer_unordered(scan::concurrency())
        .collect::<Vec<_>>()
        .await;
}

pub async fn run(state: Arc<AppState>, stop: CancellationToken) {
    let remote_operation = OperationContext::new(WorkerKind::WorkspaceRemoteGc);
    observability::worker::spawn(
        &remote_operation,
        Phase::Round,
        super::remote_gc::run(state.clone(), stop.child_token()),
    );
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! { _=stop.cancelled()=>break, _=interval.tick()=>{} }
        let operation = OperationContext::new(WorkerKind::WorkspaceCapture);
        let _ = observability::worker::run(&operation, Phase::Scan, super::mounts::refresh_leases(&state)).await;
        let mut cursor = None;
        let mut pages = futures_util::stream::FuturesUnordered::new();
        loop {
            if stop.is_cancelled() {
                return;
            }
            let rows = match observability::worker::run(&operation, Phase::Scan, eligible_page(&state, cursor)).await {
                Ok(rows) => rows,
                Err(_) => break,
            };
            if rows.is_empty() {
                break;
            }
            let complete = (rows.len() as i64) < PAGE;
            let last = rows.last().map(|row| row.0);
            let ids: Vec<Uuid> = rows
                .into_iter()
                .map(|(id, epoch, deadline)| {
                    super::mounts::update_lease(id, epoch, deadline);
                    id
                })
                .collect();
            // Pages are processed independently instead of waiting for the
            // previous 100 IDs. A slow or permanently bad early workspace then
            // cannot delay the fair scan of later UUIDs.
            pages.push(process_page(&state, ids, &operation));
            if pages.len() >= 2 {
                let _ = pages.next().await;
            }
            cursor = last;
            if complete {
                break;
            }
        }
        while pages.next().await.is_some() {
            if stop.is_cancelled() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn workspace(contents: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        let repo = dir.path().join("ws");
        fs::create_dir_all(repo.join(".git")).expect("git dir");
        fs::write(repo.join(".git/HEAD"), b"ref: refs/heads/main\n").expect("head");
        for (name, bytes) in contents {
            fs::write(repo.join(name), bytes).expect("fixture file");
        }
        dir
    }

    fn scan_of(dir: &tempfile::TempDir) -> String {
        fingerprint(&dir.path().join("ws")).expect("fingerprint")
    }

    #[test]
    fn api_write_baseline_is_never_replayed_as_an_external_capture() {
        let dir = workspace(&[("a.txt", b"one")]);
        let before = scan_of(&dir);
        // The API mutation writes the file and records the post-write baseline
        // inside the same transaction.
        fs::write(dir.path().join("ws/a.txt"), b"two").expect("api write");
        let baseline = scan_of(&dir);
        assert_ne!(before, baseline);
        // Repeating the scan must reproduce exactly the recorded baseline even
        // though the file mtime changed, otherwise every round would emit an
        // external_capture revision.
        fs::write(dir.path().join("ws/a.txt"), b"two").expect("rewrite same bytes");
        assert_eq!(scan_of(&dir), baseline);
        assert!(!capture_changes(Some(&baseline), &scan_of(&dir)));
        // A later native edit is still detected.
        fs::write(dir.path().join("ws/native.txt"), b"editor save").expect("native write");
        let native = scan_of(&dir);
        assert!(capture_changes(Some(&baseline), &native));
        // Without a stored baseline the scanner only records one.
        assert!(!capture_changes(None, &native));
    }

    #[test]
    fn stale_scans_are_discarded_for_revision_and_lease_epoch_changes() {
        assert!(scan_is_current(7, 3, 7, 3));
        // An API edit, checkpoint or external capture bumped the revision while
        // the scan was running.
        assert!(!scan_is_current(7, 3, 8, 3));
        // A lease handoff replaced this host's authority while scanning.
        assert!(!scan_is_current(7, 3, 7, 4));
        assert!(!scan_is_current(7, 3, 8, 4));
    }

    #[test]
    fn fingerprint_is_stable_across_unordered_filesystem_events() {
        let dir = workspace(&[("b.txt", b"b"), ("a.txt", b"a")]);
        let first = scan_of(&dir);
        // Touching an existing file without changing bytes is not a capture.
        let touched = dir.path().join("ws/a.txt");
        let bytes = fs::read(&touched).expect("read");
        fs::write(&touched, bytes).expect("touch");
        assert_eq!(scan_of(&dir), first);
        // Adding a file below a subdirectory is a capture.
        fs::create_dir(dir.path().join("ws/sub")).expect("dir");
        fs::write(dir.path().join("ws/sub/c.txt"), b"c").expect("file");
        assert_ne!(scan_of(&dir), first);
    }

    /// A failure raised on a real scan-pool thread must still be reported as the
    /// `workspace_capture`/`reconcile` operation, not as a detached event. The
    /// scope is installed by `scan::frozen`; nothing here enters a context by
    /// hand, and the assertion inspects the event `Error::internal` builds from
    /// that thread.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_scan_failure_is_observed_in_the_reconcile_worker_scope() {
        use crate::observability::worker::{self, OperationContext, Phase, WorkerKind};

        let context = OperationContext::new(WorkerKind::WorkspaceCapture);
        let async_thread = std::thread::current().id();
        let observed = Arc::new(std::sync::Mutex::new(None));
        let (caller, outcome) = worker::run(&context, Phase::Reconcile, {
            let observed = observed.clone();
            async move {
                let caller = worker::current().expect("reconcile worker scope");
                let outcome = scan::frozen(Uuid::new_v4(), Duration::from_secs(5), move || {
                    let error = std::io::Error::other("SECRET-scan-thread-text");
                    let event = crate::observability::event_for_test(&error);
                    *observed.lock().expect("observation slot") =
                        Some((worker::current(), event, std::thread::current().id()));
                    Err::<(), _>(Error::internal(error))
                })
                .await;
                (caller, outcome)
            }
        })
        .await;
        let scan::ScanFailure::Failed(error) = outcome.expect_err("scan failure is returned to the caller") else {
            panic!("expected the filesystem failure from the scan worker");
        };
        assert_eq!(error.0, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let (scope, event, thread) =
            observed.lock().expect("observation slot").clone().expect("scan thread recorded no observation");
        assert_ne!(thread, async_thread, "failure was built on the async thread");
        let scope = scope.expect("scan thread lost the reconcile scope");
        assert_eq!(scope.worker, WorkerKind::WorkspaceCapture);
        assert_eq!(scope.phase, Phase::Reconcile);
        assert_eq!(scope.operation_id, caller.operation_id);
        assert!(!event.contains("SECRET"), "event formatted the source text");
        let value: serde_json::Value = serde_json::from_str(&event).expect("event is valid JSON");
        assert_eq!(value["scope"].as_str(), Some("worker"));
        assert_eq!(value["worker"].as_str(), Some("workspace_capture"));
        assert_eq!(value["phase"].as_str(), Some("reconcile"));
        assert_eq!(value["kind"].as_str(), Some("io"));
        assert_eq!(value["operation_id"].as_str(), Some(scope.operation_id.to_string().as_str()));
        for forbidden in ["request_id", "route", "path", "contents"] {
            assert!(value.get(forbidden).is_none(), "event leaked {forbidden}");
        }
    }
}
