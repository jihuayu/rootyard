//! Production DistributedRefCas cutpoint capture for the scheduled `storage_lifecycle` worker (#122).
//!
//! The scheduled worker must mint a fresh [`RefCasReconciledCut`] from an authoritative
//! `RefCasStateMachine` on every maintenance pass; a PostgreSQL `ref_store_core_refs.revision`
//! sequence or a stale journal-embedded cut can never authorize `DistributedRefCas` deletion.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::ref_store::core::state_machine::{RefCasLogEntry, RefCasSnapshot, RefCasStateMachine};

use super::{
    SafeGcError,
    model::{AuthorityLane, GcMode, SafeGcArmReceipt},
    refcas_cut::{RefCasReconciledCut, reconcile_refcas_cut_with_pg},
    store::DurableSafeGcAuthority,
};

/// Sealed on-volume Ref-CAS quorum state-machine envelope consumed by the
/// scheduled maintenance worker (`<storage_root>/safe-gc/refcas/<repo_id>.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedRefCasCutpointEnvelope {
    pub group_id: i64,
    pub snapshot: RefCasSnapshot,
    #[serde(default)]
    pub wal_tail: Vec<RefCasLogEntry>,
}

/// Canonical on-volume path of the sealed Ref-CAS cutpoint envelope for one repository.
pub fn safe_gc_refcas_cutpoint_path(storage_root: &Path, repo_id: Uuid) -> PathBuf {
    storage_root.join("safe-gc").join("refcas").join(format!("{repo_id}.json"))
}

/// Atomically persist a sealed `RefCasSnapshot` plus any WAL tail for worker cutpoint capture.
pub fn persist_refcas_cutpoint_snapshot(
    storage_root: &Path,
    repo_id: Uuid,
    group_id: i64,
    sm: &RefCasStateMachine,
    wal_tail: &[RefCasLogEntry],
) -> Result<PathBuf, SafeGcError> {
    if group_id < 0 {
        return Err(SafeGcError::InvalidInput("Ref-CAS cutpoint group_id must be non-negative".into()));
    }
    let Ok(snapshot) = sm.snapshot() else {
        return Err(SafeGcError::IncompleteProof("failed sealing RefCasSnapshot"));
    };
    if snapshot.verify_integrity().is_err() {
        return Err(SafeGcError::IncompleteProof("failed verifying RefCasSnapshot"));
    }
    let path = safe_gc_refcas_cutpoint_path(storage_root, repo_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SafeGcError::Io(e.to_string()))?;
    }
    let envelope = PersistedRefCasCutpointEnvelope { group_id, snapshot, wal_tail: wal_tail.to_vec() };
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| SafeGcError::Serialization(e.to_string()))?;
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    std::fs::write(&tmp, &bytes).map_err(|e| SafeGcError::Io(e.to_string()))?;
    std::fs::rename(&tmp, &path).map_err(|e| SafeGcError::Io(e.to_string()))?;
    Ok(path)
}

/// Authoritative source of quorum-committed `RefCasStateMachine` state used by
/// the scheduled `storage_lifecycle` worker to mint fresh `RefCasReconciledCut`s.
pub trait RefCasCutpointSource: Send + Sync {
    fn capture_state_machine(&self, repo_id: Uuid) -> Result<Option<(i64, RefCasStateMachine)>, SafeGcError>;
}

/// Volume-sealed default production source backed by [`persist_refcas_cutpoint_snapshot`].
pub struct FsSealedRefCasCutpointSource {
    storage_root: PathBuf,
}

impl FsSealedRefCasCutpointSource {
    pub fn new(storage_root: impl Into<PathBuf>) -> Self {
        Self { storage_root: storage_root.into() }
    }
}

impl RefCasCutpointSource for FsSealedRefCasCutpointSource {
    fn capture_state_machine(&self, repo_id: Uuid) -> Result<Option<(i64, RefCasStateMachine)>, SafeGcError> {
        let path = safe_gc_refcas_cutpoint_path(&self.storage_root, repo_id);
        if !path.is_file() {
            return Ok(None);
        }
        let raw = std::fs::read(&path).map_err(|e| SafeGcError::Io(e.to_string()))?;
        let env: PersistedRefCasCutpointEnvelope = serde_json::from_slice(&raw)
            .map_err(|_| SafeGcError::IncompleteProof("corrupted Ref-CAS cutpoint snapshot"))?;
        if env.snapshot.verify_integrity().is_err() {
            return Err(SafeGcError::IncompleteProof("corrupted Ref-CAS cutpoint snapshot"));
        }
        let Ok(mut sm) = RefCasStateMachine::restore(&env.snapshot) else {
            return Err(SafeGcError::IncompleteProof("corrupted Ref-CAS cutpoint snapshot"));
        };
        if !env.wal_tail.is_empty() && sm.recover_entries(env.wal_tail).is_err() {
            return Err(SafeGcError::IncompleteProof("Ref-CAS cutpoint WAL replay failed"));
        }
        Ok(Some((env.group_id, sm)))
    }
}

/// Explicit in-process source for callers that already hold a verified quorum state machine.
#[derive(Default)]
pub struct InMemoryRefCasCutpointSource {
    entries: Mutex<BTreeMap<Uuid, (i64, RefCasStateMachine)>>,
}

impl InMemoryRefCasCutpointSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&self, repo_id: Uuid, group_id: i64, sm: RefCasStateMachine) {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).insert(repo_id, (group_id, sm));
    }
}

impl RefCasCutpointSource for InMemoryRefCasCutpointSource {
    fn capture_state_machine(&self, repo_id: Uuid) -> Result<Option<(i64, RefCasStateMachine)>, SafeGcError> {
        Ok(self.entries.lock().unwrap_or_else(|e| e.into_inner()).get(&repo_id).cloned())
    }
}

/// Mint a fresh cut for the current pass; `DistributedRefCas` fails closed without one.
pub(super) async fn reconcile_worker_refcas_cut_if_needed<C: GenericClient + Sync>(
    pg_client: &C,
    repo_id: Uuid,
    storage_root: &Path,
    explicit_source: Option<&dyn RefCasCutpointSource>,
    authority: &DurableSafeGcAuthority,
    destructive_env: bool,
) -> Result<Option<RefCasReconciledCut>, anyhow::Error> {
    let snap = authority.snapshot();
    let is_armed_dist = destructive_env
        && matches!(
            snap.gc_mode,
            GcMode::ArmedDestructive(SafeGcArmReceipt { lane: AuthorityLane::DistributedRefCas { .. }, .. })
        );
    let fs_default = FsSealedRefCasCutpointSource::new(storage_root);
    let source: &dyn RefCasCutpointSource = explicit_source.unwrap_or(&fs_default);
    let captured =
        source.capture_state_machine(repo_id).map_err(|e| anyhow::anyhow!("capture Ref-CAS state machine: {e}"))?;
    match (is_armed_dist, captured) {
        (true, None) => bail!(
            "DistributedRefCas scheduled Safe GC requires an authoritative RefCasCutpointSource; \
             PG ref sequence cannot prove Ref-CAS cut"
        ),
        (true, Some((group_id, sm))) => {
            let cut = reconcile_refcas_cut_with_pg(pg_client, &sm, repo_id, group_id, authority)
                .await
                .map_err(|e| anyhow::anyhow!("reconcile_refcas_cut_with_pg: {e}"))?;
            Ok(Some(cut))
        }
        (false, Some((group_id, sm))) => {
            Ok(reconcile_refcas_cut_with_pg(pg_client, &sm, repo_id, group_id, authority).await.ok())
        }
        (false, None) => Ok(None),
    }
}

/// Re-seal the armed authority lane against this pass's live PG fence and fresh cut.
pub(super) fn upgrade_armed_lane_for_worker(
    existing_lane: AuthorityLane,
    gate_revision: u64,
    fence_epoch: u64,
    fresh_cut: Option<&RefCasReconciledCut>,
) -> Result<AuthorityLane> {
    match existing_lane {
        AuthorityLane::SingleNodePg { pg_authority_id, pg_tx_seq, .. } => Ok(AuthorityLane::SingleNodePg {
            pg_authority_id,
            pg_tx_seq: pg_tx_seq.max(gate_revision),
            pg_gc_fence_epoch: fence_epoch,
            reader_barrier_epoch: fence_epoch,
        }),
        AuthorityLane::DistributedRefCas {
            ref_cas_authority_id,
            quorum_epoch,
            raft_commit_index,
            quorum_verified,
            global_hold_bridge_verified,
            global_hold_bridge_seq,
            remote_backup_root_verified,
            remote_backup_root_epoch,
            async_projection_only,
        } => {
            let cut =
                fresh_cut.ok_or_else(|| anyhow::anyhow!("DistributedRefCas requires fresh RefCasReconciledCut"))?;
            ensure!(
                quorum_epoch == cut.group_epoch,
                "DistributedRefCas quorum_epoch {quorum_epoch} != RefCasReconciledCut group_epoch {}",
                cut.group_epoch
            );
            ensure!(
                cut.sm_applied_log_index >= raft_commit_index,
                "RefCasReconciledCut log_index {} < armed raft_commit_index {raft_commit_index}",
                cut.sm_applied_log_index
            );
            Ok(AuthorityLane::DistributedRefCas {
                ref_cas_authority_id,
                quorum_epoch,
                raft_commit_index: raft_commit_index.max(cut.sm_applied_log_index),
                quorum_verified,
                global_hold_bridge_verified,
                global_hold_bridge_seq: global_hold_bridge_seq.max(cut.sm_applied_log_index),
                remote_backup_root_verified,
                remote_backup_root_epoch,
                async_projection_only,
            })
        }
    }
}
