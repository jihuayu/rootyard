//! Post-commit snapshot retention, envelope digest validation, and bounded pause-guard tests.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::time::Duration;

use openraft::entry::RaftEntry;
use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};

use rootyard_refcas_log::EntryOf;
use rootyard_refcas_log::fault::{FaultController, FaultMode, FaultPoint, FaultSpec};
use rootyard_refcas_log::fixture::{DEFAULT_MIN_FREE_BYTES, qualify_store_dir};
use rootyard_refcas_log::state_machine::{PersistentStateMachine, SmCommand, SnapshotEnvelope};

fn lid(term: u64, node: u64, index: u64) -> LogId<u64> {
    LogId::new(CommittedLeaderId::new(term, node), index)
}

fn blank(term: u64, index: u64) -> EntryOf {
    Entry::new_blank(lid(term, 1, index))
}

fn kv_entry(term: u64, index: u64, key: &str, value: &str) -> EntryOf {
    let payload = SmCommand::Put { key: key.to_owned(), value: value.to_owned() }.encode().unwrap();
    Entry { log_id: lid(term, 1, index), payload: EntryPayload::Normal(payload) }
}

#[test]
fn snapshot_post_commit_error_preserves_active_and_invalid_digest_reopens() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let dir_src = tempfile::tempdir().unwrap();
        let dir_dst = tempfile::tempdir().unwrap();
        qualify_store_dir(dir_src.path(), true, DEFAULT_MIN_FREE_BYTES).unwrap();
        qualify_store_dir(dir_dst.path(), true, DEFAULT_MIN_FREE_BYTES).unwrap();

        let f_src = std::sync::Arc::new(FaultController::default());
        let mut src = PersistentStateMachine::open_with_faults(dir_src.path(), 1, true, f_src.clone()).await.unwrap();
        src.apply(vec![blank(1, 0), kv_entry(1, 1, "b", "post-commit")]).await.unwrap();
        f_src.arm(FaultSpec { point: FaultPoint::SnapshotBuildPostCommitSync, mode: FaultMode::Once });
        assert!(src.get_snapshot_builder().await.build_snapshot().await.is_err());
        drop(src);
        let mut src2 = PersistentStateMachine::open(dir_src.path(), 1, true).await.unwrap();
        let committed_snap = src2.get_current_snapshot().await.unwrap().expect("post-commit build snapshot preserved");
        let snap_bytes = committed_snap.snapshot.into_inner();

        let f_dst = std::sync::Arc::new(FaultController::default());
        let mut dst = PersistentStateMachine::open_with_faults(dir_dst.path(), 2, true, f_dst.clone()).await.unwrap();
        dst.apply(vec![blank(1, 0), kv_entry(1, 1, "keep", "prior")]).await.unwrap();
        let prior = dst.get_snapshot_builder().await.build_snapshot().await.unwrap();
        let snap_files = || -> BTreeSet<_> {
            std::fs::read_dir(dir_dst.path().join("snapshots")).unwrap().map(|e| e.unwrap().file_name()).collect()
        };
        let before_files = snap_files();

        // Self-signed invalid digest / boundary envelopes MUST fail before staging or DB mutation.
        let mut bad_digest: SnapshotEnvelope = serde_json::from_slice(&snap_bytes).unwrap();
        bad_digest.state_digest_hex = "not-64-hex".to_owned();
        bad_digest.payload_sha256_hex = bad_digest.compute_payload_sha256().unwrap();
        let mut missing_boundary: SnapshotEnvelope = serde_json::from_slice(&snap_bytes).unwrap();
        missing_boundary.boundary_entry_digest_hex = None;
        missing_boundary.payload_sha256_hex = missing_boundary.compute_payload_sha256().unwrap();
        let mut bad_boundary: SnapshotEnvelope = serde_json::from_slice(&snap_bytes).unwrap();
        bad_boundary.boundary_entry_digest_hex = Some("zz".repeat(32));
        bad_boundary.payload_sha256_hex = bad_boundary.compute_payload_sha256().unwrap();
        let mut empty_with_boundary: SnapshotEnvelope = serde_json::from_slice(&snap_bytes).unwrap();
        empty_with_boundary.meta.last_log_id = None;
        empty_with_boundary.last_applied = None;
        empty_with_boundary.payload_sha256_hex = empty_with_boundary.compute_payload_sha256().unwrap();
        for bad in [bad_digest, missing_boundary, bad_boundary, empty_with_boundary] {
            let bytes = serde_json::to_vec(&bad).unwrap();
            assert!(dst.install_snapshot(&bad.meta, Box::new(Cursor::new(bytes))).await.is_err());
            assert_eq!(snap_files(), before_files, "rejected invalid digest staged snapshot files");
        }
        drop(dst);
        let mut dst = PersistentStateMachine::open_with_faults(dir_dst.path(), 2, true, f_dst.clone()).await.unwrap();
        assert_eq!(dst.get_current_snapshot().await.unwrap().unwrap().meta, prior.meta);
        assert_eq!(dst.kv_get("keep").await.unwrap().as_deref(), Some("prior"));

        // Actual SQLite COMMIT succeeded before post-commit error -> active snapshot stays on disk & reopens cleanly.
        let mut next_env: SnapshotEnvelope = serde_json::from_slice(&snap_bytes).unwrap();
        next_env.meta.last_log_id = Some(lid(2, 1, 2));
        next_env.last_applied = next_env.meta.last_log_id;
        next_env.payload_sha256_hex = next_env.compute_payload_sha256().unwrap();
        let next_bytes = serde_json::to_vec(&next_env).unwrap();
        f_dst.arm(FaultSpec { point: FaultPoint::SnapshotInstallPostCommitSync, mode: FaultMode::Once });
        assert!(dst.install_snapshot(&next_env.meta, Box::new(Cursor::new(next_bytes))).await.is_err());
        drop(dst);
        let mut dst_reopened = PersistentStateMachine::open(dir_dst.path(), 2, true).await.unwrap();
        assert_eq!(dst_reopened.get_current_snapshot().await.unwrap().unwrap().meta, next_env.meta);
        assert_eq!(dst_reopened.kv_get("b").await.unwrap().as_deref(), Some("post-commit"));
    });
}

#[test]
fn install_pause_guard_drops_and_times_out_boundedly() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let dir_src = tempfile::tempdir().unwrap();
        let dir_dst = tempfile::tempdir().unwrap();
        let mut src = PersistentStateMachine::open(dir_src.path(), 1, true).await.unwrap();
        src.apply(vec![kv_entry(1, 0, "a", "1")]).await.unwrap();
        let snap1 = src.get_snapshot_builder().await.build_snapshot().await.unwrap();
        let bytes1 = snap1.snapshot.into_inner();
        src.apply(vec![kv_entry(1, 1, "b", "2")]).await.unwrap();
        let snap2 = src.get_snapshot_builder().await.build_snapshot().await.unwrap();
        let bytes2 = snap2.snapshot.into_inner();

        let fault = std::sync::Arc::new(FaultController::default());
        let mut dst = PersistentStateMachine::open_with_faults(dir_dst.path(), 2, true, fault.clone()).await.unwrap();
        let mut drop_guard = fault.arm_install_pause();
        let entered1 = drop_guard.take_entered().unwrap();
        let mut dst1 = dst.clone();
        let m1 = snap1.meta.clone();
        let t1 = tokio::spawn(async move { dst1.install_snapshot(&m1, Box::new(Cursor::new(bytes1))).await });
        tokio::task::spawn_blocking(move || entered1.recv_timeout(Duration::from_secs(5)).unwrap()).await.unwrap();
        drop(drop_guard);
        tokio::time::timeout(Duration::from_secs(1), t1).await.expect("drop auto-release").unwrap().unwrap();
        assert_eq!(dst.kv_get("a").await.unwrap().as_deref(), Some("1"));

        let mut guard = fault.arm_install_pause_with_timeout(Duration::from_millis(80));
        let entered = guard.take_entered().unwrap();
        let mut dst2 = dst.clone();
        let meta = snap2.meta.clone();
        let task = tokio::spawn(async move { dst2.install_snapshot(&meta, Box::new(Cursor::new(bytes2))).await });
        tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(5)).unwrap()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), task).await.expect("pause leaked wait").unwrap().unwrap();
        drop(guard);
        assert_eq!(dst.applied_state().await.unwrap().0, Some(lid(1, 1, 1)));
        assert_eq!(dst.kv_get("b").await.unwrap().as_deref(), Some("2"));
    });
}
