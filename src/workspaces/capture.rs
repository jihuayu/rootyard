//! Mandatory full reconciliation for edits made by normal editors and Git.
//!
//! The background scanner is split into three phases:
//! 1. a short eligibility read with no row lock and no filesystem work;
//! 2. a bounded off-thread, frozen fingerprint scan;
//! 3. a short `FOR UPDATE` transaction that revalidates host, lease epoch and
//!    revision, then commits the fingerprint, revision bump and event together.
//!
//! API mutations retain the established synchronous `record_current` baseline:
//! it runs inside their existing workspace-lock transaction so their revision
//! and capture baseline are never split across commits. A pending-marker scheme
//! that recorded the baseline after the API commit was rejected: it could adopt
//! a racing native edit as the API baseline, or replay the API write as a
//! spurious external capture when the deferred baseline failed. Removing the
//! remaining API-side hash is a follow-up; the long background scan is already
//! off-thread and out of the transaction.
use super::{scan, service};
use crate::{AppState, Error, workspace_lab::core};
use futures_util::StreamExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const PAGE: i64 = 100;

pub(super) fn fingerprint(repo: &Path) -> Result<String, Error> {
    if let Some(fingerprint) = super::lazy::fingerprint(repo)? {
        return Ok(fingerprint);
    }
    let entries = core::inventory(repo).map_err(Error::internal)?;
    let raw = serde_json::to_vec(&entries).map_err(Error::internal)?;
    Ok(hex::encode(Sha256::digest(&raw)))
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

/// API mutations record the exact post-write fingerprint in their transaction.
/// This preserves the original revision/event contract: a subsequent scan must
/// not report the API write as an external edit, and it must still detect a
/// genuinely later native edit.
pub async fn record_current(tx: &deadpool_postgres::Transaction<'_>, state: &AppState, id: Uuid) -> Result<(), Error> {
    record_current_at(tx, id, &service::workspace_repo(state, id)).await
}

pub async fn record_current_at(tx: &deadpool_postgres::Transaction<'_>, id: Uuid, path: &Path) -> Result<(), Error> {
    let value = fingerprint(path)?;
    tx.execute(
        "INSERT INTO workspace_capture_state(workspace_id,fingerprint) VALUES($1,$2) \
         ON CONFLICT(workspace_id) DO UPDATE SET fingerprint=$2,scanned_at=clock_timestamp()",
        &[&id, &value],
    )
    .await
    .map_err(Error::internal)?;
    Ok(())
}

async fn eligible_page(state: &AppState, cursor: Option<Uuid>) -> Result<Vec<(Uuid, i64)>, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT id,EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces \
             WHERE host_id=$1 AND state='ready' AND lease_until>clock_timestamp() \
             AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT $3",
            &[&state.storage.volume_id, &cursor, &PAGE],
        )
        .await
        .map_err(Error::internal)?;
    Ok(rows.iter().map(|row| (row.get(0), row.get(1))).collect())
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

pub async fn reconcile_one(state: &AppState, id: Uuid) -> Result<bool, Error> {
    // In FUSE mode the mutation gate only exists while the workspace is
    // mounted; without it no stable snapshot can be taken.
    if !super::mounts::mounted(id) {
        return Ok(false);
    }
    let Some((expected_revision, expected_epoch)) = eligible(state, id).await? else {
        return Ok(false);
    };
    let repo = service::workspace_repo(state, id);
    // The FUSE gate gives a stable snapshot for one pass. Direct mode keeps the
    // second pass to detect an editor write racing an unfenced scan.
    let stable_gate = super::mounts::enabled();
    let scanned = match scan::frozen(id, scan::timeout(), move || {
        let before = fingerprint(&repo)?;
        if stable_gate {
            return Ok(before);
        }
        let after = fingerprint(&repo)?;
        if before != after {
            return Err(service::conflict());
        }
        Ok(after)
    })
    .await
    {
        Ok(value) => value,
        // A busy bounded pool or an in-progress slow scan is skipped; the fair
        // cursor keeps this workspace eligible on the next round.
        Err(scan::ScanFailure::Busy | scan::ScanFailure::Timeout) => return Ok(false),
        Err(scan::ScanFailure::Failed(error)) => return Err(error),
    };
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
    // A stale scan must never overwrite a newer API edit, checkpoint or lease
    // handoff. Discarding the result is safe: the next round scans current bytes.
    if !scan_is_current(expected_revision, expected_epoch, revision, epoch) {
        return Ok(false);
    }
    let previous = tx
        .query_opt("SELECT fingerprint FROM workspace_capture_state WHERE workspace_id=$1 FOR UPDATE", &[&id])
        .await
        .map_err(Error::internal)?;
    let changed = capture_changes(previous.as_ref().map(|row| row.get::<_, String>(0)).as_deref(), &scanned);
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

async fn process_page(state: &AppState, ids: Vec<Uuid>) {
    futures_util::stream::iter(ids)
        .map(|id| async move {
            let _ = reconcile_one(state, id).await;
        })
        .buffer_unordered(scan::concurrency())
        .collect::<Vec<_>>()
        .await;
}

pub async fn run(state: Arc<AppState>, stop: CancellationToken) {
    tokio::spawn(super::remote_gc::run(state.clone(), stop.child_token()));
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! { _=stop.cancelled()=>break, _=interval.tick()=>{} }
        let _ = super::mounts::refresh_leases(&state).await;
        let mut cursor = None;
        let mut pages = futures_util::stream::FuturesUnordered::new();
        loop {
            if stop.is_cancelled() {
                return;
            }
            let rows = match eligible_page(&state, cursor).await {
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
                .map(|(id, deadline)| {
                    super::mounts::update_lease(id, deadline);
                    id
                })
                .collect();
            // Pages are processed independently instead of waiting for the
            // previous 100 IDs. A slow or permanently bad early workspace then
            // cannot delay the fair scan of later UUIDs.
            pages.push(process_page(&state, ids));
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
}
