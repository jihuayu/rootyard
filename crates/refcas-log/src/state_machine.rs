//! Persistent `openraft` 0.9.26 `RaftStateMachine` and `RaftSnapshotBuilder` over SQLite.

pub mod app;
mod app_store;
#[cfg(test)]
mod app_tests;
mod codec;
mod snapshot;
mod snapshot_app;
mod snapshot_stage;
mod snapshot_v1;
mod store;

use std::collections::BTreeMap;
use std::io::{self, Cursor};
use std::path::Path;
use std::sync::Arc;

use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use openraft::{ErrorSubject, ErrorVerb, LogId, OptionalSend, Snapshot, SnapshotMeta, StorageError, StoredMembership};
use tokio::sync::Mutex;

use crate::fault::FaultController;
use crate::{E, EntryOf, LogTypeConfig, Res, ioerr, with_inner};

pub use app::{
    APP_COMMAND_MAGIC, ApplicationCommand, ApplicationError, ApplicationLogId, ApplicationStateMachine,
    MAX_APP_COMMAND_BYTES, MAX_APP_DOMAIN_BYTES, MAX_APP_PAYLOAD_BYTES, MAX_APP_STATE_BYTES, is_application_wire,
};
pub use app_store::ApplicationSummary;
pub use codec::SmCommand;
pub use snapshot::SnapshotEnvelope;
pub use store::StateMachineSummary;

/// Persistent Raft state machine stored in `sm.sqlite3` plus atomic `snapshots/` files.
#[derive(Clone)]
pub struct PersistentStateMachine {
    inner: Arc<Mutex<store::SmInner>>,
    op_gate: Arc<Mutex<()>>,
    fault: Arc<FaultController>,
}

/// Local reducer clone plus the persisted consensus coordinate it materializes.
pub struct ApplicationRuntimeSnapshot {
    pub reducer: Box<dyn ApplicationStateMachine>,
    pub applied: Option<LogId<u64>>,
    pub summary: ApplicationSummary,
}

/// Snapshot builder serialized under the state machine's operation gate.
pub struct PersistentSnapshotBuilder {
    inner: Arc<Mutex<store::SmInner>>,
    op_gate: Arc<Mutex<()>>,
}

impl PersistentStateMachine {
    /// Opens or initializes `sm.sqlite3` under `path` for `node_id`.
    pub async fn open(path: impl AsRef<Path>, node_id: u64, check_on_open: bool) -> Res<Self> {
        Self::open_with_faults(path, node_id, check_on_open, FaultController::noop()).await
    }

    /// Opens or initializes the state machine with an attached fault-injection controller.
    pub async fn open_with_faults(
        path: impl AsRef<Path>,
        node_id: u64,
        check_on_open: bool,
        fault: Arc<FaultController>,
    ) -> Res<Self> {
        Self::open_inner(path.as_ref().to_path_buf(), node_id, check_on_open, fault, None).await
    }

    /// Opens or initializes an application-mode state machine with a deterministic reducer.
    pub async fn open_application(
        path: impl AsRef<Path>,
        node_id: u64,
        check_on_open: bool,
        reducer: Box<dyn ApplicationStateMachine>,
    ) -> Res<Self> {
        Self::open_application_with_faults(path, node_id, check_on_open, reducer, FaultController::noop()).await
    }

    /// Opens an application-mode state machine with an attached fault controller.
    pub async fn open_application_with_faults(
        path: impl AsRef<Path>,
        node_id: u64,
        check_on_open: bool,
        reducer: Box<dyn ApplicationStateMachine>,
        fault: Arc<FaultController>,
    ) -> Res<Self> {
        Self::open_inner(path.as_ref().to_path_buf(), node_id, check_on_open, fault, Some(reducer)).await
    }

    async fn open_inner(
        dir: std::path::PathBuf,
        node_id: u64,
        check_on_open: bool,
        fault: Arc<FaultController>,
        app: Option<Box<dyn ApplicationStateMachine>>,
    ) -> Res<Self> {
        let inner_fault = fault.clone();
        let inner =
            tokio::task::spawn_blocking(move || store::SmInner::open(&dir, node_id, check_on_open, inner_fault, app))
                .await
                .map_err(|e| E::Io(io::Error::other(format!("sm open task failed: {e}"))))??;
        Ok(Self { inner: Arc::new(Mutex::new(inner)), op_gate: Arc::new(Mutex::new(())), fault })
    }

    /// Returns the attached fault controller.
    pub fn fault_controller(&self) -> &Arc<FaultController> {
        &self.fault
    }

    /// Limits SQLite page allocations on this connection (used to force real `SQLITE_FULL` in tests).
    pub async fn set_max_page_count(&self, max_pages: u64) -> Res<u64> {
        let _gate = self.op_gate.lock().await;
        with_inner(self.inner.clone(), move |i| {
            let capped = i.conn.pragma_update_and_check(None, "max_page_count", max_pages, |r| r.get::<_, u64>(0))?;
            Ok(capped)
        })
        .await
    }

    /// Reads the value associated with `key`, if present. Application mode fails closed because
    /// its semantic state is not a KV table.
    pub async fn kv_get(&self, key: impl Into<String>) -> Res<Option<String>> {
        let key = key.into();
        let _gate = self.op_gate.lock().await;
        with_inner(self.inner.clone(), move |i| {
            if i.app.is_some() {
                return Err(E::Refused("KV reads are unavailable in application state-machine mode".into()));
            }
            Ok(store::read_kv_map(&i.conn)?.remove(&key))
        })
        .await
    }

    /// Reads a consistent copy of the full KV table. Application mode fails closed.
    pub async fn kv_snapshot(&self) -> Res<BTreeMap<String, String>> {
        let _gate = self.op_gate.lock().await;
        with_inner(self.inner.clone(), |i| {
            if i.app.is_some() {
                return Err(E::Refused("KV snapshot is unavailable in application state-machine mode".into()));
            }
            store::read_kv_map(&i.conn)
        })
        .await
    }

    /// Reads the persisted summary (applied index, membership, running state digest, snapshot id).
    pub async fn summary(&self) -> Res<StateMachineSummary> {
        let _gate = self.op_gate.lock().await;
        with_inner(self.inner.clone(), |i| store::read_summary(i)).await
    }

    /// Reads application identity/digest when opened in application mode.
    pub async fn application_summary(&self) -> Res<Option<ApplicationSummary>> {
        let _gate = self.op_gate.lock().await;
        with_inner(self.inner.clone(), |i| store::read_application_summary_row(i)).await
    }

    /// Clones the live reducer with the persisted coordinate it materializes.
    ///
    /// This is a local consistency snapshot, not an authoritative read. Callers must still run
    /// an actual Raft quorum ReadIndex barrier before minting any committed view.
    pub async fn application_snapshot(&self) -> Res<Option<ApplicationRuntimeSnapshot>> {
        let _gate = self.op_gate.lock().await;
        let snapshot = with_inner(self.inner.clone(), |i| store::read_application_runtime_snapshot(i)).await?;
        Ok(snapshot.map(|runtime| ApplicationRuntimeSnapshot {
            reducer: runtime.reducer,
            applied: runtime.applied,
            summary: runtime.summary,
        }))
    }
}

impl RaftSnapshotBuilder<LogTypeConfig> for PersistentSnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<LogTypeConfig>, StorageError<u64>> {
        let _gate = self.op_gate.lock().await;
        with_inner(self.inner.clone(), snapshot::build_snapshot_blocking)
            .await
            .map_err(|e| ioerr(ErrorSubject::Snapshot(None), ErrorVerb::Write, &e))
    }
}

impl RaftStateMachine<LogTypeConfig> for PersistentStateMachine {
    type SnapshotBuilder = PersistentSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, openraft::BasicNode>), StorageError<u64>> {
        let _gate = self.op_gate.lock().await;
        with_inner(self.inner.clone(), |i| store::read_applied_state(&i.conn))
            .await
            .map_err(|e| ioerr(ErrorSubject::StateMachine, ErrorVerb::Read, &e))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<()>, StorageError<u64>>
    where
        I: IntoIterator<Item = EntryOf> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let batch: Vec<EntryOf> = entries.into_iter().collect();
        let _gate = self.op_gate.lock().await;
        with_inner(self.inner.clone(), move |i| store::apply_entries(i, batch))
            .await
            .map_err(|e| ioerr(ErrorSubject::StateMachine, ErrorVerb::Write, &e))
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        PersistentSnapshotBuilder { inner: self.inner.clone(), op_gate: self.op_gate.clone() }
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, openraft::BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let snap_meta = meta.clone();
        let subject_meta = meta.clone();
        let raw = snapshot.into_inner();
        let _gate = self.op_gate.lock().await;
        with_inner(self.inner.clone(), move |i| snapshot::install_snapshot_blocking(i, snap_meta, raw))
            .await
            .map_err(|e| ioerr(ErrorSubject::Snapshot(Some(subject_meta.signature())), ErrorVerb::Write, &e))
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<LogTypeConfig>>, StorageError<u64>> {
        let _gate = self.op_gate.lock().await;
        with_inner(self.inner.clone(), |i| snapshot::read_current_snapshot_blocking(i))
            .await
            .map_err(|e| ioerr(ErrorSubject::Snapshot(None), ErrorVerb::Read, &e))
    }
}
