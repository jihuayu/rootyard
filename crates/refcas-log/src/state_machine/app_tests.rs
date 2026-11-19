//! Source-level contract tests for the persisted application seam.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::sync::Arc;

use openraft::entry::RaftEntry as _;
use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId, Membership};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::EntryOf;
use crate::fault::{FaultController, FaultMode, FaultPoint, FaultSpec};
use crate::state_machine::app::{
    ApplicationCommand, ApplicationError, ApplicationLogId, ApplicationStateMachine, MAX_APP_PAYLOAD_BYTES,
};
use crate::state_machine::codec::hex_encode;
use crate::state_machine::{PersistentStateMachine, SmCommand};

const DOMAIN: &str = "test.refcas.app";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct TestState {
    last_applied: Option<ApplicationLogId>,
    values: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
struct TestReducer {
    state: TestState,
}

impl TestReducer {
    fn new() -> Self {
        Self::default()
    }
}

impl ApplicationStateMachine for TestReducer {
    fn domain(&self) -> &'static str {
        DOMAIN
    }

    fn version(&self) -> u16 {
        1
    }

    fn apply(&mut self, log_id: ApplicationLogId, payload: &[u8]) -> Result<(), ApplicationError> {
        let (key, value): (String, String) =
            serde_json::from_slice(payload).map_err(|e| ApplicationError::new(format!("bad test command: {e}")))?;
        if key.is_empty() || key.len() > 64 || value.len() > 1024 {
            return Err(ApplicationError::new("test command out of bounds"));
        }
        self.state.values.insert(key, value);
        self.state.last_applied = Some(log_id);
        Ok(())
    }

    fn advance_applied(&mut self, log_id: ApplicationLogId) -> Result<(), ApplicationError> {
        self.state.last_applied = Some(log_id);
        Ok(())
    }

    fn export_state(&self) -> Result<Vec<u8>, ApplicationError> {
        serde_json::to_vec(&self.state).map_err(|e| ApplicationError::new(format!("test export: {e}")))
    }

    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), ApplicationError> {
        let state: TestState =
            serde_json::from_slice(bytes).map_err(|e| ApplicationError::new(format!("test restore: {e}")))?;
        self.state = state;
        Ok(())
    }

    fn last_applied(&self) -> Option<ApplicationLogId> {
        self.state.last_applied
    }

    fn state_digest_hex(&self) -> Result<String, ApplicationError> {
        let bytes = self.export_state()?;
        Ok(hex_encode(&Sha256::digest(&bytes)))
    }

    fn clone_box(&self) -> Box<dyn ApplicationStateMachine> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn lid(term: u64, node: u64, index: u64) -> LogId<u64> {
    LogId::new(CommittedLeaderId::new(term, node), index)
}

fn blank(term: u64, index: u64) -> EntryOf {
    Entry::new_blank(lid(term, 1, index))
}

fn app_entry(term: u64, index: u64, key: &str, value: &str) -> EntryOf {
    let payload = serde_json::to_vec(&(key, value)).unwrap();
    let command = ApplicationCommand::new(DOMAIN, 1, payload).unwrap().encode().unwrap();
    Entry { log_id: lid(term, 1, index), payload: EntryPayload::Normal(command) }
}

fn membership(term: u64, index: u64, voters: BTreeSet<u64>) -> EntryOf {
    Entry::new_membership(lid(term, 1, index), Membership::new(vec![voters], ()))
}

async fn reducer_values(sm: &PersistentStateMachine) -> BTreeMap<String, String> {
    let snapshot = sm.application_snapshot().await.unwrap().unwrap();
    snapshot.reducer.as_any().downcast_ref::<TestReducer>().unwrap().state.values.clone()
}

#[test]
fn application_apply_blank_membership_snapshot_and_reopen() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let mut sm =
            PersistentStateMachine::open_application(dir.path(), 1, true, Box::new(TestReducer::new())).await.unwrap();
        sm.apply(vec![blank(1, 1), app_entry(1, 2, "alpha", "one"), membership(1, 3, BTreeSet::from([1, 2, 3]))])
            .await
            .unwrap();
        let summary = sm.summary().await.unwrap();
        assert_eq!(summary.last_applied, Some(lid(1, 1, 3)));
        let app_summary = sm.application_summary().await.unwrap().unwrap();
        assert_eq!(app_summary.domain, DOMAIN);
        assert_eq!(app_summary.version, 1);
        assert_eq!(app_summary.last_applied, Some(ApplicationLogId::new(1, 3)));
        assert_eq!(reducer_values(&sm).await.get("alpha").map(String::as_str), Some("one"));

        let snapshot = sm.get_snapshot_builder().await.build_snapshot().await.unwrap();
        let snap_meta = snapshot.meta.clone();
        let snap_bytes = snapshot.snapshot.into_inner();
        assert!(String::from_utf8_lossy(&snap_bytes).contains("rootyard-refcas-snapshot/2"));

        let fresh = tempfile::tempdir().unwrap();
        let mut installed =
            PersistentStateMachine::open_application(fresh.path(), 2, true, Box::new(TestReducer::new()))
                .await
                .unwrap();
        installed.install_snapshot(&snap_meta, Box::new(Cursor::new(snap_bytes))).await.unwrap();
        assert_eq!(reducer_values(&installed).await.get("alpha").map(String::as_str), Some("one"));
        assert_eq!(
            installed.application_summary().await.unwrap().unwrap().last_applied,
            Some(ApplicationLogId::new(1, 3))
        );

        drop(sm);
        let reopened =
            PersistentStateMachine::open_application(dir.path(), 1, true, Box::new(TestReducer::new())).await.unwrap();
        assert_eq!(reducer_values(&reopened).await.get("alpha").map(String::as_str), Some("one"));
        assert_eq!(
            reopened.application_summary().await.unwrap().unwrap().last_applied,
            Some(ApplicationLogId::new(1, 3))
        );
    });
}

#[test]
fn mixed_modes_and_malformed_commands_fail_closed_without_coordinate_advance() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let mut sm =
            PersistentStateMachine::open_application(dir.path(), 1, true, Box::new(TestReducer::new())).await.unwrap();
        sm.apply(vec![blank(1, 1), app_entry(1, 2, "alpha", "one")]).await.unwrap();
        let before = sm.application_summary().await.unwrap().unwrap();

        let kv_payload = SmCommand::Put { key: "k".into(), value: "v".into() }.encode().unwrap();
        let bad_kv = Entry { log_id: lid(1, 1, 3), payload: EntryPayload::Normal(kv_payload) };
        assert!(sm.apply(vec![bad_kv]).await.is_err());
        assert_eq!(sm.application_summary().await.unwrap().unwrap(), before);

        let wrong_domain = ApplicationCommand::new("other.domain", 1, b"x".to_vec()).unwrap().encode().unwrap();
        let bad_domain = Entry { log_id: lid(1, 1, 3), payload: EntryPayload::Normal(wrong_domain) };
        assert!(sm.apply(vec![bad_domain]).await.is_err());
        assert_eq!(sm.application_summary().await.unwrap().unwrap(), before);

        let oversize = ApplicationCommand::new(DOMAIN, 1, vec![0; MAX_APP_PAYLOAD_BYTES + 1]);
        assert!(oversize.is_err());
        drop(sm);

        // Opening an application database in KV mode or a legacy KV database in application mode
        // must fail closed rather than silently dropping the other state.
        assert!(PersistentStateMachine::open(dir.path(), 1, true).await.is_err());

        let kv_dir = tempfile::tempdir().unwrap();
        let mut kv = PersistentStateMachine::open(kv_dir.path(), 3, true).await.unwrap();
        kv.apply(vec![blank(1, 1), {
            let payload = SmCommand::Put { key: "legacy".into(), value: "yes".into() }.encode().unwrap();
            Entry { log_id: lid(1, 1, 2), payload: EntryPayload::Normal(payload) }
        }])
        .await
        .unwrap();
        assert!(
            PersistentStateMachine::open_application(kv_dir.path(), 3, true, Box::new(TestReducer::new()))
                .await
                .is_err()
        );
    });
}

#[test]
fn failed_storage_commit_never_advances_in_memory_reducer() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let fault = Arc::new(FaultController::default());
        let mut sm = PersistentStateMachine::open_application_with_faults(
            dir.path(),
            1,
            true,
            Box::new(TestReducer::new()),
            fault.clone(),
        )
        .await
        .unwrap();
        sm.apply(vec![blank(1, 1), app_entry(1, 2, "alpha", "one")]).await.unwrap();
        let before_summary = sm.application_summary().await.unwrap().unwrap();
        let before_values = reducer_values(&sm).await;

        fault.arm(FaultSpec { point: FaultPoint::SmApplySync, mode: FaultMode::Once });
        assert!(sm.apply(vec![app_entry(1, 3, "beta", "two")]).await.is_err());
        assert_eq!(sm.application_summary().await.unwrap().unwrap(), before_summary);
        assert_eq!(reducer_values(&sm).await, before_values);
        assert_eq!(sm.summary().await.unwrap().last_applied, Some(lid(1, 1, 2)));
    });
}
