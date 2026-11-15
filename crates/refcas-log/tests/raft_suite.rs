//! Openraft `Suite` storage conformance plus snapshot serialization, rollback, and replay tests.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::time::Duration;

use openraft::entry::RaftEntry as _;
use openraft::storage::{RaftLogStorage, RaftSnapshotBuilder, RaftStateMachine};
use openraft::testing::{StoreBuilder, Suite};
use openraft::{BasicNode, CommittedLeaderId, Entry, EntryPayload, LogId, Membership, Vote};
use tempfile::TempDir;

use rootyard_refcas_log::fault::{FaultController, FaultMode, FaultPoint, FaultSpec};
use rootyard_refcas_log::fixture::{DEFAULT_MIN_FREE_BYTES, qualify_store_dir};
use rootyard_refcas_log::state_machine::{PersistentStateMachine, SmCommand, SnapshotEnvelope};
use rootyard_refcas_log::{EntryOf, LogTypeConfig, PersistentLog};

struct SqliteStoreBuilder;

impl StoreBuilder<LogTypeConfig, PersistentLog, PersistentStateMachine, TempDir> for SqliteStoreBuilder {
    async fn build(&self) -> Result<(TempDir, PersistentLog, PersistentStateMachine), openraft::StorageError<u64>> {
        let dir = tempfile::tempdir().expect("tempdir");
        qualify_store_dir(dir.path(), true, DEFAULT_MIN_FREE_BYTES).expect("qualify fixture");
        let log = PersistentLog::open(dir.path(), 0, true).await.expect("open log");
        let sm = PersistentStateMachine::open(dir.path(), 0, true).await.expect("open sm");
        Ok((dir, log, sm))
    }
}

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

fn mem_entry(term: u64, index: u64, voters: BTreeSet<u64>) -> EntryOf {
    Entry::new_membership(lid(term, 1, index), Membership::new(vec![voters], ()))
}

async fn append_sync(log: &mut PersistentLog, entries: Vec<EntryOf>) -> rootyard_refcas_log::Res<()> {
    log.append_durable(entries).await
}

#[test]
fn openraft_storage_suite_compatible_cases_pass() {
    let builder = SqliteStoreBuilder;
    let rt = tokio::runtime::Runtime::new().unwrap();
    type SuiteTy = Suite<LogTypeConfig, PersistentLog, PersistentStateMachine, SqliteStoreBuilder, TempDir>;
    macro_rules! assert_ok {
        ($name:ident) => {{
            let (_g, store, sm) = rt.block_on(builder.build()).unwrap();
            rt.block_on(SuiteTy::$name(store, sm))
                .unwrap_or_else(|e| panic!("Suite::{} failed unexpectedly: {e}", stringify!($name)));
        }};
    }
    assert_ok!(last_membership_in_log_initial);
    assert_ok!(get_membership_initial);
    assert_ok!(get_membership_from_empty_log_and_sm);
    assert_ok!(get_membership_from_log_le_sm_last_applied);
    assert_ok!(get_membership_from_log_gt_sm_last_applied_1);
    assert_ok!(get_membership_from_log_gt_sm_last_applied_2);
    assert_ok!(get_initial_state_without_init);
    assert_ok!(get_initial_state_with_state);
    assert_ok!(get_initial_state_last_log_gt_sm);
    assert_ok!(get_initial_state_last_log_lt_sm);
    assert_ok!(get_initial_state_log_ids);
    assert_ok!(get_initial_state_re_apply_committed);
    assert_ok!(save_vote);
    assert_ok!(get_log_entries);
    assert_ok!(limited_get_log_entries);
    assert_ok!(try_get_log_entry);
    assert_ok!(initial_logs);
    assert_ok!(get_log_state);
    assert_ok!(get_log_id);
    assert_ok!(last_id_in_log);
    assert_ok!(last_applied_state);
    assert_ok!(purge_logs_upto_0);
    assert_ok!(purge_logs_upto_5);
    assert_ok!(purge_logs_upto_20);
    assert_ok!(delete_logs_since_11);
    assert_ok!(delete_logs_since_0);
    assert_ok!(append_to_log);
    assert_ok!(snapshot_meta);
    assert_ok!(apply_single);
    assert_ok!(apply_multiple);
    rt.block_on(SuiteTy::transfer_snapshot(&builder))
        .unwrap_or_else(|e| panic!("Suite::transfer_snapshot failed unexpectedly: {e}"));
}

#[test]
fn refcas_log_fail_closed_prefix_and_purge_boundaries() {
    let builder = SqliteStoreBuilder;
    let rt = tokio::runtime::Runtime::new().unwrap();
    type SuiteTy = Suite<LogTypeConfig, PersistentLog, PersistentStateMachine, SqliteStoreBuilder, TempDir>;
    macro_rules! assert_refused {
        ($name:ident, $needle:expr) => {{
            let (_g, store, sm) = rt.block_on(builder.build()).unwrap();
            let err = rt
                .block_on(SuiteTy::$name(store, sm))
                .expect_err(&format!("Suite::{} unexpectedly bypassed fail-closed guard", stringify!($name)));
            let msg = format!("{err:#}");
            assert!(msg.contains($needle), "Suite::{} error {msg:?} missing {:?}", stringify!($name), $needle);
        }};
    }
    // PersistentLog fail-closed contract: positive first retained index without a purge boundary cannot serve 0.. reads.
    assert_refused!(last_membership_in_log, "unavailable prefix cannot be served");
    assert_refused!(last_membership_in_log_multi_step, "unavailable prefix cannot be served");
    assert_refused!(get_membership_from_log_and_empty_sm, "unavailable prefix cannot be served");
    // PersistentLog fail-closed contract: appending at or below a persisted purge boundary is refused.
    assert_refused!(get_initial_state_membership_from_log_and_sm, "append would revive a purged prefix");
}

#[test]
fn qualify_store_dir_rejects_outside_temp_when_required() {
    let cwd = std::env::current_dir().unwrap();
    let err = qualify_store_dir(&cwd, true, DEFAULT_MIN_FREE_BYTES).unwrap_err();
    assert!(err.to_string().contains("outside the temp directory"), "unexpected error: {err}");
}

#[test]
fn install_snapshot_and_membership_change_are_strictly_serialized() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let dir_src = tempfile::tempdir().unwrap();
        let dir_dst = tempfile::tempdir().unwrap();
        qualify_store_dir(dir_src.path(), true, DEFAULT_MIN_FREE_BYTES).unwrap();
        qualify_store_dir(dir_dst.path(), true, DEFAULT_MIN_FREE_BYTES).unwrap();

        let mut src = PersistentStateMachine::open(dir_src.path(), 1, true).await.unwrap();
        src.apply(vec![
            blank(1, 0),
            kv_entry(1, 1, "alpha", "one"),
            mem_entry(1, 2, BTreeSet::from([1, 2])),
            kv_entry(1, 3, "beta", "two"),
        ])
        .await
        .unwrap();
        let snap2 = src.get_snapshot_builder().await.build_snapshot().await.unwrap();

        let fault = std::sync::Arc::new(FaultController::default());
        let mut dst = PersistentStateMachine::open_with_faults(dir_dst.path(), 2, true, fault.clone()).await.unwrap();
        dst.apply(vec![blank(1, 0), mem_entry(1, 1, BTreeSet::from([1]))]).await.unwrap();
        let _snap1 = dst.get_snapshot_builder().await.build_snapshot().await.unwrap();

        let (entered_rx, release_tx) = fault.arm_install_pause();
        let mut dst_install = dst.clone();
        let meta = snap2.meta.clone();
        let raw = snap2.snapshot.into_inner();
        let install_task =
            tokio::spawn(async move { dst_install.install_snapshot(&meta, Box::new(Cursor::new(raw))).await });

        tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5)).unwrap()).await.unwrap();

        let mut dst_apply = dst.clone();
        let mut apply_task =
            tokio::spawn(async move { dst_apply.apply(vec![mem_entry(2, 4, BTreeSet::from([1, 2, 3]))]).await });

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(!apply_task.is_finished(), "membership apply bypassed op_gate during install_snapshot");
        let mid_summary = tokio::time::timeout(Duration::from_millis(80), dst.summary()).await;
        assert!(mid_summary.is_err(), "concurrent reader observed unlocked state mid-install");

        release_tx.send(()).unwrap();
        install_task.await.unwrap().unwrap();
        let replies = (&mut apply_task).await.unwrap().unwrap();
        assert_eq!(replies.len(), 1);

        let (applied, mem) = dst.applied_state().await.unwrap();
        assert_eq!(applied, Some(lid(2, 1, 4)));
        let voters: Vec<u64> = mem.membership().voter_ids().collect();
        assert_eq!(voters, vec![1, 2, 3]);
        assert_eq!(dst.kv_get("beta").await.unwrap().as_deref(), Some("two"));
    });
}

#[test]
fn failed_install_snapshot_rolls_back_state_membership_and_prior_snapshot() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let dir_src = tempfile::tempdir().unwrap();
        let dir_dst = tempfile::tempdir().unwrap();
        qualify_store_dir(dir_src.path(), true, DEFAULT_MIN_FREE_BYTES).unwrap();
        qualify_store_dir(dir_dst.path(), true, DEFAULT_MIN_FREE_BYTES).unwrap();

        let mut src = PersistentStateMachine::open(dir_src.path(), 1, true).await.unwrap();
        src.apply(vec![
            blank(1, 0),
            kv_entry(1, 1, "base", "src"),
            mem_entry(2, 2, BTreeSet::from([1, 2, 3])),
            kv_entry(2, 3, "new", "from-src"),
        ])
        .await
        .unwrap();
        let snap_src = src.get_snapshot_builder().await.build_snapshot().await.unwrap();
        let src_bytes = snap_src.snapshot.into_inner();

        let fault = std::sync::Arc::new(FaultController::default());
        let mut dst = PersistentStateMachine::open_with_faults(dir_dst.path(), 2, true, fault.clone()).await.unwrap();
        dst.apply(vec![blank(1, 0), kv_entry(1, 1, "keep", "original"), mem_entry(1, 2, BTreeSet::from([1]))])
            .await
            .unwrap();
        let snap_prior = dst.get_snapshot_builder().await.build_snapshot().await.unwrap();

        for point in [
            FaultPoint::SnapshotInstallWriteEnospc,
            FaultPoint::SnapshotInstallStageSync,
            FaultPoint::SnapshotInstallCommitSync,
        ] {
            fault.arm(FaultSpec { point, mode: FaultMode::Once });
            let err = dst.install_snapshot(&snap_src.meta, Box::new(Cursor::new(src_bytes.clone()))).await.unwrap_err();
            assert!(!err.to_string().is_empty());
        }

        // Corrupt payload, wrong sha256 digest, mismatched SnapshotMeta, and regressive snapshot all fail closed.
        assert!(dst.install_snapshot(&snap_src.meta, Box::new(Cursor::new(b"{bad".to_vec()))).await.is_err());

        let mut tampered_env: SnapshotEnvelope = serde_json::from_slice(&src_bytes).unwrap();
        tampered_env.kv.insert("injected".to_owned(), "evil".to_owned());
        let tampered_raw = serde_json::to_vec(&tampered_env).unwrap();
        assert!(dst.install_snapshot(&snap_src.meta, Box::new(Cursor::new(tampered_raw))).await.is_err());

        let mut wrong_meta = snap_src.meta.clone();
        wrong_meta.snapshot_id = "other-id".to_owned();
        assert!(dst.install_snapshot(&wrong_meta, Box::new(Cursor::new(src_bytes.clone()))).await.is_err());

        let regressive = SnapshotEnvelope {
            format: tampered_env.format.clone(),
            node_id: 9,
            generation: 1,
            meta: snap_prior.meta.clone(),
            last_applied: snap_prior.meta.last_log_id,
            last_membership: snap_prior.meta.last_membership.clone(),
            state_digest_hex: "00".repeat(32),
            applied_count: 1,
            boundary_entry_digest_hex: None,
            kv: BTreeMap::new(),
            payload_sha256_hex: String::new(),
        };
        let mut reg_signed = regressive;
        reg_signed.payload_sha256_hex = reg_signed.compute_payload_sha256().unwrap();
        let mut older_meta = snap_prior.meta.clone();
        older_meta.last_log_id = Some(lid(1, 1, 0));
        reg_signed.meta = older_meta.clone();
        reg_signed.last_applied = older_meta.last_log_id;
        reg_signed.payload_sha256_hex = reg_signed.compute_payload_sha256().unwrap();
        let reg_bytes = serde_json::to_vec(&reg_signed).unwrap();
        assert!(dst.install_snapshot(&older_meta, Box::new(Cursor::new(reg_bytes))).await.is_err());

        // Real SQLITE_FULL during install_snapshot when inserting large KV payload rolls back cleanly.
        let big_src_dir = tempfile::tempdir().unwrap();
        let mut big_src = PersistentStateMachine::open(big_src_dir.path(), 3, true).await.unwrap();
        let mut entries = vec![blank(1, 0)];
        for i in 1..=25u64 {
            entries.push(kv_entry(2, i, &format!("k-{i:02}"), &"x".repeat(2048)));
        }
        big_src.apply(entries).await.unwrap();
        let big_snap = big_src.get_snapshot_builder().await.build_snapshot().await.unwrap();
        let _cap = dst.set_max_page_count(1).await.unwrap();
        assert!(
            dst.install_snapshot(&big_snap.meta, Box::new(Cursor::new(big_snap.snapshot.into_inner()))).await.is_err(),
            "SQLITE_FULL should abort install_snapshot"
        );
        let _ = big_src_dir.close();

        // Prior SM state, membership, and live snapshot must all remain completely intact.
        let (applied, mem) = dst.applied_state().await.unwrap();
        assert_eq!(applied, Some(lid(1, 1, 2)));
        assert_eq!(mem.membership().voter_ids().collect::<Vec<_>>(), vec![1]);
        assert_eq!(dst.kv_get("keep").await.unwrap().as_deref(), Some("original"));
        assert_eq!(dst.kv_get("new").await.unwrap(), None);
        let cur_snap = dst.get_current_snapshot().await.unwrap().expect("prior snapshot preserved");
        assert_eq!(cur_snap.meta, snap_prior.meta);
        drop(dst);

        let mut reopened = PersistentStateMachine::open(dir_dst.path(), 2, true).await.unwrap();
        assert_eq!(reopened.applied_state().await.unwrap().0, Some(lid(1, 1, 2)));
        assert_eq!(reopened.get_current_snapshot().await.unwrap().unwrap().meta, snap_prior.meta);
    });
}

#[test]
fn idempotent_replay_and_conflicting_replay_fail_closed() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        qualify_store_dir(dir1.path(), true, DEFAULT_MIN_FREE_BYTES).unwrap();
        qualify_store_dir(dir2.path(), true, DEFAULT_MIN_FREE_BYTES).unwrap();

        let unknown = br#"{"Put":{"key":"k","value":"v","unexpected":true}}"#;
        assert!(SmCommand::decode_strict(unknown).is_err(), "deny_unknown_fields must reject extra field");

        let mut sm1 = PersistentStateMachine::open(dir1.path(), 1, true).await.unwrap();
        let b0 = blank(1, 0);
        let k1 = kv_entry(1, 1, "k", "v1");
        let m2 = mem_entry(1, 2, BTreeSet::from([1, 2]));
        sm1.apply(vec![b0.clone(), k1.clone(), m2.clone()]).await.unwrap();
        // Replay locally applied entries -> idempotent no-op.
        sm1.apply(vec![k1.clone(), m2.clone()]).await.unwrap();
        assert!(sm1.apply(vec![kv_entry(1, 1, "k", "TAMPERED")]).await.is_err());

        let snap = sm1.get_snapshot_builder().await.build_snapshot().await.unwrap();
        let snap_bytes = snap.snapshot.into_inner();

        let mut sm2 = PersistentStateMachine::open(dir2.path(), 2, true).await.unwrap();
        sm2.install_snapshot(&snap.meta, Box::new(Cursor::new(snap_bytes.clone()))).await.unwrap();
        // Identical snapshot replay succeeds.
        sm2.install_snapshot(&snap.meta, Box::new(Cursor::new(snap_bytes.clone()))).await.unwrap();

        // Identical boundary entry replay succeeds; conflicting boundary replay fails closed.
        sm2.apply(vec![m2.clone()]).await.unwrap();
        assert!(sm2.apply(vec![mem_entry(1, 2, BTreeSet::from([1, 99]))]).await.is_err());

        // Conflicting snapshot payload with identical snapshot_id fails closed.
        let mut env: SnapshotEnvelope = serde_json::from_slice(&snap_bytes).unwrap();
        env.kv.insert("diff".to_owned(), "val".to_owned());
        env.state_digest_hex = "ab".repeat(32);
        env.payload_sha256_hex = env.compute_payload_sha256().unwrap();
        let bad_bytes = serde_json::to_vec(&env).unwrap();
        assert!(sm2.install_snapshot(&snap.meta, Box::new(Cursor::new(bad_bytes))).await.is_err());
    });
}

#[test]
fn snapshot_build_faults_and_sqlite_full_apply_rollback() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let dir = tempfile::tempdir().unwrap();
        qualify_store_dir(dir.path(), true, DEFAULT_MIN_FREE_BYTES).unwrap();

        let fault = std::sync::Arc::new(FaultController::default());
        let mut log = PersistentLog::open_with_faults(dir.path(), 1, true, fault.clone()).await.unwrap();
        let mut sm = PersistentStateMachine::open_with_faults(dir.path(), 1, true, fault.clone()).await.unwrap();

        append_sync(&mut log, vec![blank(1, 0), kv_entry(1, 1, "seed", "ok")]).await.unwrap();
        sm.apply(vec![blank(1, 0), kv_entry(1, 1, "seed", "ok")]).await.unwrap();
        let base_snap = sm.get_snapshot_builder().await.build_snapshot().await.unwrap();

        // Build faults leave prior snapshot intact.
        for point in [FaultPoint::SnapshotBuildWriteEnospc, FaultPoint::SnapshotBuildSync] {
            fault.arm(FaultSpec { point, mode: FaultMode::Once });
            assert!(sm.get_snapshot_builder().await.build_snapshot().await.is_err());
            assert_eq!(sm.get_current_snapshot().await.unwrap().unwrap().meta, base_snap.meta);
        }

        // Fault hooks on log vote/append and SM apply roll back without corruption.
        fault.arm(FaultSpec { point: FaultPoint::LogVoteSync, mode: FaultMode::Once });
        assert!(log.save_vote(&Vote::new(2, 1)).await.is_err());
        assert_eq!(log.read_vote().await.unwrap(), None);

        for point in [FaultPoint::LogAppendEnospc, FaultPoint::LogAppendSync] {
            fault.arm(FaultSpec { point, mode: FaultMode::Once });
            assert!(append_sync(&mut log, vec![kv_entry(1, 2, "fail", "log")]).await.is_err());
            assert_eq!(log.get_log_state().await.unwrap().last_log_id, Some(lid(1, 1, 1)));
        }

        for point in [FaultPoint::SmApplyEnospc, FaultPoint::SmApplySync] {
            fault.arm(FaultSpec { point, mode: FaultMode::Once });
            assert!(sm.apply(vec![kv_entry(1, 2, "fail", "sm")]).await.is_err());
            assert_eq!(sm.applied_state().await.unwrap().0, Some(lid(1, 1, 1)));
            assert_eq!(sm.kv_get("fail").await.unwrap(), None);
        }

        // Real SQLITE_FULL rollback on both PersistentLog and PersistentStateMachine.
        let _ = log.set_max_page_count(1).await.unwrap();
        let large_log: Vec<EntryOf> =
            (2..=25).map(|i| kv_entry(1, i, &format!("big-{i}"), &"p".repeat(2048))).collect();
        assert!(append_sync(&mut log, large_log.clone()).await.is_err(), "log SQLITE_FULL expected");
        assert_eq!(log.get_log_state().await.unwrap().last_log_id, Some(lid(1, 1, 1)));

        let _ = sm.set_max_page_count(1).await.unwrap();
        assert!(sm.apply(large_log).await.is_err(), "sm SQLITE_FULL expected");
        assert_eq!(sm.applied_state().await.unwrap().0, Some(lid(1, 1, 1)));
        drop(log);
        drop(sm);

        // Store reopens cleanly with seed state preserved (checking BasicNode default).
        let _node = BasicNode::default();
        let mut log2 = PersistentLog::open(dir.path(), 1, true).await.unwrap();
        let mut sm2 = PersistentStateMachine::open(dir.path(), 1, true).await.unwrap();
        assert_eq!(log2.get_log_state().await.unwrap().last_log_id, Some(lid(1, 1, 1)));
        assert_eq!(sm2.applied_state().await.unwrap().0, Some(lid(1, 1, 1)));
        assert_eq!(sm2.kv_get("seed").await.unwrap().as_deref(), Some("ok"));
    });
}
