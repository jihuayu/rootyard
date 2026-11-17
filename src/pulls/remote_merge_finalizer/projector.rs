//! Idempotent Ref-CAS merge receipt projector, in-memory store, and crash finalizer (`Refs #156`).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use super::coordinator::{AuthorityCommitOutcome, MergeAuthorityBackend};
use super::types::{
    CommittedMergeReceipt, PendingMergeRecord, ProjectedPullRecord, ProjectionOutcome, PullMergeState,
    RejectedMergeReceipt, RemoteMergeError,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileReport {
    pub inspected: usize,
    pub committed: usize,
    pub rejected: usize,
    pub aborted_before_cas: usize,
    pub still_pending: usize,
}

pub trait MergeReceiptStore: Send + Sync {
    fn insert_pending<'a>(&'a self, record: &'a PendingMergeRecord) -> BoxFuture<'a, Result<(), RemoteMergeError>>;

    fn project_committed<'a>(
        &'a self,
        receipt: &'a CommittedMergeReceipt,
        storage_generation: i64,
        expected_version: i64,
        update_forge_pulls: bool,
    ) -> BoxFuture<'a, Result<ProjectionOutcome, RemoteMergeError>>;

    fn project_rejected<'a>(
        &'a self,
        receipt: &'a RejectedMergeReceipt,
    ) -> BoxFuture<'a, Result<ProjectionOutcome, RemoteMergeError>>;

    fn project_aborted_before_cas<'a>(
        &'a self,
        repository_id: Uuid,
        operation_id: Uuid,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<ProjectionOutcome, RemoteMergeError>>;

    fn list_pending<'a>(
        &'a self,
        repository_id: Uuid,
    ) -> BoxFuture<'a, Result<Vec<PendingMergeRecord>, RemoteMergeError>>;

    fn load_attempt<'a>(
        &'a self,
        repository_id: Uuid,
        operation_id: Uuid,
    ) -> BoxFuture<'a, Result<Option<PendingMergeRecord>, RemoteMergeError>>;
}

/// Monotonic, idempotent projector translating authoritative Ref-CAS outcomes into PG/authority rows.
#[derive(Clone, Copy)]
pub struct PullMergeReceiptProjector<'a, S: MergeReceiptStore> {
    store: &'a S,
}

impl<'a, S: MergeReceiptStore> PullMergeReceiptProjector<'a, S> {
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }

    pub async fn record_pending(&self, record: &PendingMergeRecord) -> Result<(), RemoteMergeError> {
        if record.state != PullMergeState::PendingMerge {
            return Err(RemoteMergeError::InvalidInput("pending record must carry PendingMerge state".into()));
        }
        self.store.insert_pending(record).await
    }

    pub async fn project_committed(
        &self,
        receipt: &CommittedMergeReceipt,
        storage_generation: i64,
        expected_version: i64,
        update_forge_pulls: bool,
    ) -> Result<ProjectionOutcome, RemoteMergeError> {
        if receipt.merged_oid.is_empty() || receipt.commit_log_index == 0 || receipt.terminal_digest.is_empty() {
            return Err(RemoteMergeError::InvalidInput("committed receipt requires merged_oid/log_index/digest".into()));
        }
        self.store.project_committed(receipt, storage_generation, expected_version, update_forge_pulls).await
    }

    pub async fn project_rejected(
        &self,
        receipt: &RejectedMergeReceipt,
    ) -> Result<ProjectionOutcome, RemoteMergeError> {
        self.store.project_rejected(receipt).await
    }

    pub async fn project_aborted_before_cas(
        &self,
        repository_id: Uuid,
        operation_id: Uuid,
        reason: &str,
    ) -> Result<ProjectionOutcome, RemoteMergeError> {
        self.store.project_aborted_before_cas(repository_id, operation_id, reason).await
    }
}

/// Deterministic crash/disconnect reconciler resolving unresolved `PendingMerge` rows
/// strictly from authoritative Raft/RefCas state rather than local PG speculation.
pub struct RecoverablePullMergeFinalizer<'a, A: MergeAuthorityBackend, S: MergeReceiptStore> {
    authority: &'a A,
    store: &'a S,
    projector: PullMergeReceiptProjector<'a, S>,
}

impl<'a, A: MergeAuthorityBackend, S: MergeReceiptStore> RecoverablePullMergeFinalizer<'a, A, S> {
    pub fn new(authority: &'a A, store: &'a S) -> Self {
        Self { authority, store, projector: PullMergeReceiptProjector::new(store) }
    }

    pub async fn reconcile_pending(
        &self,
        repository_id: Uuid,
        update_forge_pulls: bool,
    ) -> Result<ReconcileReport, RemoteMergeError> {
        let pending_list = self.store.list_pending(repository_id).await?;
        let mut report = ReconcileReport::default();
        for rec in pending_list {
            report.inspected += 1;
            match self.authority.query_operation_outcome(repository_id, rec.operation_id, &rec.base_ref).await? {
                Some(AuthorityCommitOutcome::Committed {
                    log_index,
                    log_term,
                    gate_revision,
                    merged_oid,
                    terminal_digest,
                    replayed,
                }) => {
                    if merged_oid != rec.candidate_target_oid {
                        return Err(RemoteMergeError::Equivocation(format!(
                            "reconciled OID {merged_oid} disagrees with pending candidate {}",
                            rec.candidate_target_oid
                        )));
                    }
                    let receipt = CommittedMergeReceipt {
                        operation_id: rec.operation_id,
                        decision_id: rec.decision_id,
                        tenant_id: rec.tenant_id,
                        repository_id: rec.repository_id,
                        pull_number: rec.pull_number,
                        base_ref: rec.base_ref,
                        previous_base_oid: rec.expected_base_oid,
                        merged_oid,
                        commit_log_index: log_index,
                        commit_log_term: log_term,
                        gate_revision,
                        terminal_digest,
                        replayed,
                    };
                    self.projector
                        .project_committed(
                            &receipt,
                            rec.expected_storage_generation,
                            rec.expected_version,
                            update_forge_pulls,
                        )
                        .await?;
                    report.committed += 1;
                }
                Some(AuthorityCommitOutcome::Rejected { log_index, log_term, terminal_digest, reason, .. }) => {
                    self.projector
                        .project_rejected(&RejectedMergeReceipt {
                            operation_id: rec.operation_id,
                            repository_id: rec.repository_id,
                            pull_number: rec.pull_number,
                            commit_log_index: log_index,
                            commit_log_term: log_term,
                            state: PullMergeState::RejectedMerge,
                            reason,
                            terminal_digest,
                        })
                        .await?;
                    report.rejected += 1;
                }
                Some(AuthorityCommitOutcome::Cancelled { log_index, log_term, reason }) => {
                    self.projector
                        .project_rejected(&RejectedMergeReceipt {
                            operation_id: rec.operation_id,
                            repository_id: rec.repository_id,
                            pull_number: rec.pull_number,
                            commit_log_index: log_index,
                            commit_log_term: log_term,
                            state: PullMergeState::RejectedMerge,
                            reason,
                            terminal_digest: None,
                        })
                        .await?;
                    report.rejected += 1;
                }
                Some(AuthorityCommitOutcome::UnknownPending { .. }) => {
                    report.still_pending += 1;
                }
                None => {
                    let live = self.authority.read_ref_oid(repository_id, &rec.base_ref).await?;
                    let reason = match live {
                        Some(oid) if oid != rec.expected_base_oid => {
                            format!("aborted before Ref-CAS commit; base ref moved to {oid}")
                        }
                        _ => "aborted before Ref-CAS log entry persisted".to_owned(),
                    };
                    self.projector.project_aborted_before_cas(repository_id, rec.operation_id, &reason).await?;
                    report.aborted_before_cas += 1;
                }
            }
        }
        Ok(report)
    }
}

#[derive(Clone, Debug, Default)]
struct MemState {
    attempts: BTreeMap<(Uuid, Uuid), PendingMergeRecord>,
    pulls: BTreeMap<(Uuid, i64), ProjectedPullRecord>,
}

/// Thread-safe in-memory durable mirror enforcing identical constraints to [`super::PgMergeStore`].
#[derive(Clone, Debug, Default)]
pub struct InMemoryMergeStore {
    inner: Arc<Mutex<MemState>>,
}

impl InMemoryMergeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed_pull(&self, pull: ProjectedPullRecord) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.pulls.insert((pull.repository_id, pull.pull_number), pull);
    }

    pub fn get_pull(&self, repository_id: Uuid, pull_number: i64) -> Option<ProjectedPullRecord> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).pulls.get(&(repository_id, pull_number)).cloned()
    }

    pub fn all_attempts(&self, repository_id: Uuid) -> Vec<PendingMergeRecord> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .attempts
            .iter()
            .filter(|((r, _), _)| *r == repository_id)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

impl MergeReceiptStore for InMemoryMergeStore {
    fn insert_pending<'a>(&'a self, record: &'a PendingMergeRecord) -> BoxFuture<'a, Result<(), RemoteMergeError>> {
        Box::pin(async move {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(committed) = g.attempts.values().find(|a| {
                a.repository_id == record.repository_id
                    && a.pull_number == record.pull_number
                    && a.state == PullMergeState::CommittedMerge
                    && a.operation_id != record.operation_id
            }) {
                return Err(RemoteMergeError::AlreadyMerged {
                    pull_number: committed.pull_number,
                    committed_oid: committed.merged_oid.clone().unwrap_or_default(),
                    commit_log_index: committed.commit_log_index.unwrap_or(0),
                });
            }
            if let Some(existing) = g.attempts.get(&(record.repository_id, record.operation_id)) {
                if existing.state == PullMergeState::CommittedMerge {
                    return Err(RemoteMergeError::ReceiptRegression(
                        "cannot re-insert PendingMerge over CommittedMerge".into(),
                    ));
                }
                if existing == record {
                    return Ok(());
                }
                return Err(RemoteMergeError::Equivocation(
                    "conflicting PendingMergeRecord for same operation_id".into(),
                ));
            }
            g.attempts.insert((record.repository_id, record.operation_id), record.clone());
            Ok(())
        })
    }

    fn project_committed<'a>(
        &'a self,
        receipt: &'a CommittedMergeReceipt,
        storage_generation: i64,
        expected_version: i64,
        update_forge_pulls: bool,
    ) -> BoxFuture<'a, Result<ProjectionOutcome, RemoteMergeError>> {
        Box::pin(async move {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(other) = g.attempts.values().find(|a| {
                a.repository_id == receipt.repository_id
                    && a.pull_number == receipt.pull_number
                    && a.state == PullMergeState::CommittedMerge
                    && a.operation_id != receipt.operation_id
            }) {
                return Err(RemoteMergeError::AlreadyMerged {
                    pull_number: other.pull_number,
                    committed_oid: other.merged_oid.clone().unwrap_or_default(),
                    commit_log_index: other.commit_log_index.unwrap_or(0),
                });
            }

            let replayed = if let Some(existing) = g.attempts.get_mut(&(receipt.repository_id, receipt.operation_id)) {
                match existing.state {
                    PullMergeState::CommittedMerge => {
                        if existing.merged_oid.as_deref() != Some(receipt.merged_oid.as_str())
                            || existing.commit_log_index != Some(receipt.commit_log_index)
                            || existing.terminal_digest.as_deref() != Some(receipt.terminal_digest.as_str())
                        {
                            return Err(RemoteMergeError::Equivocation(
                                "conflicting CommittedMerge replay payload".into(),
                            ));
                        }
                        true
                    }
                    PullMergeState::RejectedMerge | PullMergeState::AbortedBeforeCas => {
                        return Err(RemoteMergeError::ReceiptRegression(
                            "cannot overwrite Rejected/Aborted attempt with CommittedMerge".into(),
                        ));
                    }
                    PullMergeState::PendingMerge => {
                        existing.state = PullMergeState::CommittedMerge;
                        existing.commit_log_index = Some(receipt.commit_log_index);
                        existing.commit_log_term = Some(receipt.commit_log_term);
                        existing.merged_oid = Some(receipt.merged_oid.clone());
                        existing.terminal_digest = Some(receipt.terminal_digest.clone());
                        false
                    }
                }
            } else {
                return Err(RemoteMergeError::InvalidInput("attempt missing before CommittedMerge projection".into()));
            };

            if update_forge_pulls {
                let pull = g
                    .pulls
                    .get_mut(&(receipt.repository_id, receipt.pull_number))
                    .ok_or_else(|| RemoteMergeError::InvalidInput("pull missing in InMemoryMergeStore".into()))?;
                if pull.state == "merged" {
                    if pull.merge_commit_oid.as_deref() != Some(receipt.merged_oid.as_str()) {
                        return Err(RemoteMergeError::Equivocation(
                            "forge_pulls already merged with different commit OID".into(),
                        ));
                    }
                } else if pull.state == "open" && pull.version == expected_version {
                    pull.state = "merged".to_owned();
                    pull.merge_commit_oid = Some(receipt.merged_oid.clone());
                    pull.merged_storage_generation = Some(storage_generation);
                    pull.version += 1;
                } else {
                    return Err(RemoteMergeError::Equivocation(
                        "pull state/version conflict during CommittedMerge projection".into(),
                    ));
                }
            }
            Ok(ProjectionOutcome::ProjectedCommitted { replayed })
        })
    }

    fn project_rejected<'a>(
        &'a self,
        receipt: &'a RejectedMergeReceipt,
    ) -> BoxFuture<'a, Result<ProjectionOutcome, RemoteMergeError>> {
        Box::pin(async move {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let existing = g
                .attempts
                .get_mut(&(receipt.repository_id, receipt.operation_id))
                .ok_or_else(|| RemoteMergeError::InvalidInput("attempt missing before RejectedMerge".into()))?;
            match existing.state {
                PullMergeState::CommittedMerge => Err(RemoteMergeError::ReceiptRegression(
                    "cannot downgrade CommittedMerge to RejectedMerge".into(),
                )),
                PullMergeState::AbortedBeforeCas => Err(RemoteMergeError::ReceiptRegression(
                    "cannot transition AbortedBeforeCas to RejectedMerge".into(),
                )),
                PullMergeState::RejectedMerge => Ok(ProjectionOutcome::ProjectedRejected { replayed: true }),
                PullMergeState::PendingMerge => {
                    existing.state = PullMergeState::RejectedMerge;
                    existing.commit_log_index = receipt.commit_log_index;
                    existing.commit_log_term = receipt.commit_log_term;
                    existing.terminal_digest = receipt.terminal_digest.clone();
                    existing.reject_reason = Some(receipt.reason.clone());
                    Ok(ProjectionOutcome::ProjectedRejected { replayed: false })
                }
            }
        })
    }

    fn project_aborted_before_cas<'a>(
        &'a self,
        repository_id: Uuid,
        operation_id: Uuid,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<ProjectionOutcome, RemoteMergeError>> {
        Box::pin(async move {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let existing = g
                .attempts
                .get_mut(&(repository_id, operation_id))
                .ok_or_else(|| RemoteMergeError::InvalidInput("attempt missing before AbortedBeforeCas".into()))?;
            match existing.state {
                PullMergeState::CommittedMerge => Err(RemoteMergeError::ReceiptRegression(
                    "cannot downgrade CommittedMerge to AbortedBeforeCas".into(),
                )),
                PullMergeState::RejectedMerge => Err(RemoteMergeError::ReceiptRegression(
                    "cannot transition RejectedMerge to AbortedBeforeCas".into(),
                )),
                PullMergeState::AbortedBeforeCas => Ok(ProjectionOutcome::ProjectedAborted { replayed: true }),
                PullMergeState::PendingMerge => {
                    existing.state = PullMergeState::AbortedBeforeCas;
                    existing.reject_reason = Some(reason.to_owned());
                    Ok(ProjectionOutcome::ProjectedAborted { replayed: false })
                }
            }
        })
    }

    fn list_pending<'a>(
        &'a self,
        repository_id: Uuid,
    ) -> BoxFuture<'a, Result<Vec<PendingMergeRecord>, RemoteMergeError>> {
        Box::pin(async move {
            Ok(self
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .attempts
                .iter()
                .filter(|((r, _), v)| *r == repository_id && v.state == PullMergeState::PendingMerge)
                .map(|(_, v)| v.clone())
                .collect())
        })
    }

    fn load_attempt<'a>(
        &'a self,
        repository_id: Uuid,
        operation_id: Uuid,
    ) -> BoxFuture<'a, Result<Option<PendingMergeRecord>, RemoteMergeError>> {
        Box::pin(async move {
            Ok(self.inner.lock().unwrap_or_else(|e| e.into_inner()).attempts.get(&(repository_id, operation_id)).cloned())
        })
    }
}
