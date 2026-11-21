//! Coordinator orchestration: pre-CAS validation, authoritative Ref-CAS commit, projection (`Refs #156`).

use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use uuid::Uuid;

use crate::ref_store::contract::{OperationLookup, OperationState};
use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, CommitScopedRefsCommand, InstallScopedDecisionCommand, RefCasCommand,
    RefCasStateMachine, SmDecisionState, StateMachineError,
};
use crate::ref_store::core::terminal::{CommitRejectCode, CommitTerminal, RefCommitResult};
use crate::ref_store::projector::DecisionGrantKeyring;
use crate::storage_lifecycle::safe_gc::pg_maintenance_dist::register_live_sm_cutpoint_source;
use crate::storage_lifecycle::safe_gc::{RefCasCommitCutpointPublisher, SafeGcError};

use super::projector::{MergeReceiptStore, PullMergeReceiptProjector};
use super::types::{
    MergeAttemptOutcome, MergeAttemptSpec, MergeFaultInjection, MergePullSnapshot, PendingMergeRecord,
    PullMergeState, RemoteMergeError,
};
use super::validation::{validate_merge_inputs_and_preconditions, verify_pull_remote_authz_grant};

#[path = "coordinator_outcome.rs"]
mod coordinator_outcome;

use coordinator_outcome::canonical_terminal_digest;
pub use coordinator_outcome::{
    AuthorityCommitOutcome, BackendFuture, MergeAuthorityBackend, map_sm_error_to_outcome,
};

/// Maps an immutable [`CommitTerminal`] into [`AuthorityCommitOutcome`] from `terminal.refs`.
pub fn map_commit_receipt_to_outcome(
    log_id: AppliedLogId,
    base_ref: &str,
    terminal: &CommitTerminal,
    replayed: bool,
    diagnostic_live_base_oid: Option<String>,
) -> Result<AuthorityCommitOutcome, RemoteMergeError> {
    let terminal_digest = canonical_terminal_digest(terminal);
    if terminal.is_committed() {
        let merged_oid = terminal
            .refs
            .iter()
            .find_map(|r| match r {
                RefCommitResult::Applied { name, new_oid, .. } if name.as_str() == base_ref => new_oid.clone(),
                _ => None,
            })
            .ok_or_else(|| {
                RemoteMergeError::Equivocation(format!(
                    "committed Ref-CAS terminal missing Applied new_oid for `{base_ref}`"
                ))
            })?;
        return Ok(AuthorityCommitOutcome::Committed {
            log_index: log_id.index, log_term: log_id.term, gate_revision: terminal.revision,
            merged_oid, terminal_digest, replayed,
        });
    }
    let reject_code = terminal.rejection.as_ref().map_or(CommitRejectCode::PolicyDenied, |r| r.code);
    let reason = format!("ref-cas rejected `{base_ref}` with {}", reject_code.as_str());
    Ok(AuthorityCommitOutcome::Rejected {
        log_index: Some(log_id.index), log_term: Some(log_id.term), reject_code,
        actual_base_oid: diagnostic_live_base_oid, terminal_digest: Some(terminal_digest), reason,
    })
}

pub fn original_operation_log_id(
    sm: &RefCasStateMachine,
    repository_id: Uuid,
    operation_id: Uuid,
) -> Option<AppliedLogId> {
    sm.read_events_since(0, usize::MAX)
        .into_iter()
        .find(|ev| {
            ev.repository_id == repository_id
                && ev.operation_id == operation_id
                && (ev.outcome == "committed" || ev.outcome == "rejected")
        })
        .map(|ev| AppliedLogId { term: ev.log_term, index: ev.log_index })
}

/// Deterministic in-process authority backend backed directly by [`RefCasStateMachine`].
#[derive(Clone, Debug)]
pub struct InProcessRefCasBackend {
    sm: Arc<Mutex<RefCasStateMachine>>,
    next_index: Arc<Mutex<u64>>,
    op_log_ids: Arc<Mutex<BTreeMap<(Uuid, Uuid), AppliedLogId>>>,
    cutpoint_publisher: Option<RefCasCommitCutpointPublisher>,
    abort_after_install_once: Arc<AtomicBool>,
}

impl InProcessRefCasBackend {
    pub fn new(sm: RefCasStateMachine) -> Self {
        let next = sm.last_applied().map_or(1, |id| id.index.saturating_add(1));
        Self {
            sm: Arc::new(Mutex::new(sm)),
            next_index: Arc::new(Mutex::new(next)),
            op_log_ids: Arc::new(Mutex::new(BTreeMap::new())),
            cutpoint_publisher: None,
            abort_after_install_once: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn snapshot_refs(&self, repository_id: Uuid) -> std::collections::BTreeMap<String, String> {
        self.sm.lock().unwrap_or_else(|e| e.into_inner()).read_refs(repository_id)
    }

    pub fn state_machine(&self) -> RefCasStateMachine {
        self.sm.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn next_log_id(&self) -> AppliedLogId {
        let mut guard = self.next_index.lock().unwrap_or_else(|e| e.into_inner());
        let idx = *guard;
        *guard = idx.saturating_add(1);
        AppliedLogId { term: 1, index: idx }
    }

    pub fn with_safe_gc_cutpoint_publisher(
        mut self,
        storage_root: impl Into<std::path::PathBuf>,
        group_id: i64,
    ) -> Result<Self, SafeGcError> {
        self.cutpoint_publisher = Some(RefCasCommitCutpointPublisher::new(storage_root, group_id)?);
        Ok(self)
    }

    /// Injects one durable install-to-commit abort so callers can observe the in-flight decision.
    pub fn set_abort_after_install_once(&self, enabled: bool) {
        self.abort_after_install_once.store(enabled, Ordering::SeqCst);
    }

    /// Publish the running state machine as the safe-GC production cutpoint authority.
    pub fn register_safe_gc_repo(&self, repository_id: Uuid) {
        if let Some(publisher) = &self.cutpoint_publisher {
            register_live_sm_cutpoint_source(publisher.storage_root(), repository_id, publisher.group_id(), &self.sm);
        }
    }

    fn publish_cutpoint(&self, repository_id: Uuid, sm: &RefCasStateMachine) -> Result<(), SafeGcError> {
        let Some(publisher) = &self.cutpoint_publisher else {
            return Ok(());
        };
        publisher.publish_committed_state(repository_id, sm, &[])?;
        register_live_sm_cutpoint_source(publisher.storage_root(), repository_id, publisher.group_id(), &self.sm);
        Ok(())
    }

    pub fn apply_repo_command(
        &self,
        repository_id: Uuid,
        cmd: RefCasCommand,
    ) -> Result<ApplyResponse, RemoteMergeError> {
        let log_id = self.next_log_id();
        let mut sm = self.sm.lock().unwrap_or_else(|e| e.into_inner());
        let response =
            sm.apply(log_id, cmd).map_err(|e| RemoteMergeError::RemoteAuthzDenied(e.to_string()))?;
        self.publish_cutpoint(repository_id, &sm)
            .map_err(|e| RemoteMergeError::Io(format!("Ref-CAS apply/publish cutpoint failed: {e}")))?;
        Ok(response)
    }
}

impl MergeAuthorityBackend for InProcessRefCasBackend {
    fn install_and_commit_scoped<'a>(
        &'a self,
        repository_id: Uuid,
        base_ref: &'a str,
        install: InstallScopedDecisionCommand,
        commit: CommitScopedRefsCommand,
    ) -> BackendFuture<'a, AuthorityCommitOutcome> {
        Box::pin(async move {
            self.register_safe_gc_repo(repository_id);
            let dec_id = commit.commit.decision_id;
            let install_idx = self.next_log_id();
            {
                let mut sm = self.sm.lock().unwrap_or_else(|e| e.into_inner());
                match sm.apply(install_idx, RefCasCommand::InstallScopedDecision(install)) {
                    Ok(_) => {}
                    Err(StateMachineError::DecisionConflict {
                        decision_id,
                        state: SmDecisionState::Consumed | SmDecisionState::Rejected,
                    }) if Some(decision_id) == dec_id => {}
                    Err(err) => {
                        let actual_base_oid = sm.read_refs(repository_id).get(base_ref).cloned();
                        let _ = self.publish_cutpoint(repository_id, &sm);
                        return Ok(map_sm_error_to_outcome(Some(install_idx), err, actual_base_oid));
                    }
                }
            }
            // Seal the installed-but-not-committed decision before the commit point so a
            // process crash in this window can never leave Safe GC reading an older cut.
            {
                let sm = self.sm.lock().unwrap_or_else(|e| e.into_inner());
                self.publish_cutpoint(repository_id, &sm).map_err(|e| {
                    RemoteMergeError::Io(format!("publish install-to-commit cutpoint failed: {e}"))
                })?;
            }
            if self.abort_after_install_once.swap(false, Ordering::SeqCst) {
                return Ok(AuthorityCommitOutcome::UnknownPending {
                    reason: "injected abort after install before Ref-CAS commit".into(),
                });
            }
            let op_id = commit.commit.request.identity.operation_id;
            let commit_idx = self.next_log_id();
            let mut sm = self.sm.lock().unwrap_or_else(|e| e.into_inner());
            match sm.apply(commit_idx, RefCasCommand::CommitScopedRefs(commit)) {
                Ok(ApplyResponse::RefsCommitted(receipt)) => {
                    let stored_idx = match original_operation_log_id(&sm, repository_id, op_id) {
                        Some(orig) => {
                            self.op_log_ids
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .entry((repository_id, op_id))
                                .or_insert(orig);
                            orig
                        }
                        None if receipt.replayed => {
                            return Err(RemoteMergeError::Equivocation(
                                "replayed Ref-CAS commit missing original state-machine AppliedLogId".into(),
                            ));
                        }
                        None => {
                            self.op_log_ids
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert((repository_id, op_id), commit_idx);
                            commit_idx
                        }
                    };
                    let diag_base = sm.read_refs(repository_id).get(base_ref).cloned();
                    self.publish_cutpoint(repository_id, &sm)
                        .map_err(|e| RemoteMergeError::Io(format!("publish Ref-CAS cutpoint snapshot failed: {e}")))?;
                    map_commit_receipt_to_outcome(stored_idx, base_ref, &receipt.terminal, receipt.replayed, diag_base)
                }
                Ok(other) => Err(RemoteMergeError::Equivocation(format!("unexpected RefCas response: {other:?}"))),
                Err(err) => {
                    let diag_base = sm.read_refs(repository_id).get(base_ref).cloned();
                    let _ = self.publish_cutpoint(repository_id, &sm);
                    Ok(map_sm_error_to_outcome(Some(commit_idx), err, diag_base))
                }
            }
        })
    }

    fn query_operation_outcome<'a>(
        &'a self,
        repository_id: Uuid,
        operation_id: Uuid,
        base_ref: &'a str,
    ) -> BackendFuture<'a, Option<AuthorityCommitOutcome>> {
        Box::pin(async move {
            let sm = self.sm.lock().unwrap_or_else(|e| e.into_inner());
            let lookup = sm
                .query_operation(repository_id, operation_id)
                .map_err(|e| RemoteMergeError::RemoteAuthzDenied(e.to_string()))?;
            let log_id = original_operation_log_id(&sm, repository_id, operation_id).unwrap_or_else(|| {
                self.op_log_ids
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&(repository_id, operation_id))
                    .copied()
                    .unwrap_or_else(|| sm.last_applied().unwrap_or(AppliedLogId { term: 1, index: 1 }))
            });
            if sm.has_cancel_tombstone(repository_id, operation_id)
                && !matches!(&lookup, OperationLookup::Known(record) if record.state() == OperationState::Committed)
            {
                return Ok(Some(AuthorityCommitOutcome::Cancelled {
                    log_index: Some(log_id.index),
                    log_term: Some(log_id.term),
                    reason: "operation cancelled by tombstone in RefCasStateMachine".into(),
                }));
            }
            match lookup {
                OperationLookup::Unknown => {
                    let snapshot = sm.snapshot().map_err(|e| RemoteMergeError::RemoteAuthzDenied(e.to_string()))?;
                    let installed = snapshot.body.decisions.iter().any(|decision| {
                        decision.repository_id == repository_id
                            && decision.operation_id == operation_id
                            && decision.state == SmDecisionState::Open
                    });
                    if installed {
                        return Ok(Some(AuthorityCommitOutcome::UnknownPending {
                            reason: "decision installed but Ref-CAS commit not applied".into(),
                        }));
                    }
                    Ok(None)
                }
                OperationLookup::Known(record) => {
                    let diag_base = sm.read_refs(repository_id).get(base_ref).cloned();
                    match record.state() {
                        OperationState::Pending => Ok(Some(AuthorityCommitOutcome::UnknownPending {
                            reason: "operation pending in RefCasStateMachine".into(),
                        })),
                        OperationState::Cancelled => Ok(Some(AuthorityCommitOutcome::Cancelled {
                            log_index: Some(log_id.index),
                            log_term: Some(log_id.term),
                            reason: "operation cancelled in RefCasStateMachine".into(),
                        })),
                        OperationState::Committed | OperationState::Rejected => {
                            let res = record
                                .terminal_result()
                                .ok_or_else(|| RemoteMergeError::Equivocation("missing terminal_result".into()))?;
                            let terminal: CommitTerminal = serde_json::from_value(res.value().clone())
                                .map_err(|e| RemoteMergeError::Equivocation(e.to_string()))?;
                            Ok(Some(map_commit_receipt_to_outcome(log_id, base_ref, &terminal, true, diag_base)?))
                        }
                    }
                }
            }
        })
    }

    fn read_ref_oid<'a>(&'a self, repository_id: Uuid, ref_name: &'a str) -> BackendFuture<'a, Option<String>> {
        Box::pin(async move {
            let sm = self.sm.lock().unwrap_or_else(|e| e.into_inner());
            Ok(sm.read_refs(repository_id).get(ref_name).cloned())
        })
    }
}

/// Producer orchestrating validation -> durable `PendingMerge` intent -> Raft Ref-CAS sole
/// commit point -> monotonic receipt projection without PG ref fallbacks.
pub struct PullRemoteMergeProducer<'a, A: MergeAuthorityBackend, S: MergeReceiptStore> {
    authority: &'a A,
    projector: PullMergeReceiptProjector<'a, S>,
    keyring: &'a DecisionGrantKeyring,
}

impl<'a, A: MergeAuthorityBackend, S: MergeReceiptStore> PullRemoteMergeProducer<'a, A, S> {
    pub fn new(authority: &'a A, store: &'a S, keyring: &'a DecisionGrantKeyring) -> Self {
        Self { authority, projector: PullMergeReceiptProjector::new(store), keyring }
    }

    pub async fn execute_merge(
        &self,
        spec: &MergeAttemptSpec,
        pull: &MergePullSnapshot,
        update_forge_pulls: bool,
        fault: MergeFaultInjection,
    ) -> Result<MergeAttemptOutcome, RemoteMergeError> {
        validate_merge_inputs_and_preconditions(spec, pull)?;
        let validated = verify_pull_remote_authz_grant(spec, pull, self.keyring)?;
        if matches!(fault, MergeFaultInjection::DisconnectBeforePendingInsert) {
            return Err(RemoteMergeError::PgDatabase("injected PG disconnect before pending merge insert".into()));
        }
        let pending = PendingMergeRecord {
            attempt_id: spec.attempt_id, operation_id: spec.operation_id, decision_id: spec.decision_id,
            tenant_id: spec.tenant_id, repository_id: spec.repository_id, pull_number: spec.pull_number,
            base_ref: spec.base_ref.clone(), expected_head_oid: spec.expected_head_oid.clone(),
            expected_base_oid: spec.expected_base_oid.clone(), candidate_target_oid: spec.candidate_target_oid.clone(),
            expected_version: spec.expected_version, expected_storage_generation: spec.expected_storage_generation,
            strategy: spec.strategy, authz_epoch: spec.grant.payload.authz_epoch, pack_sha256: spec.pack_sha256.clone(),
            facts_digest: validated.binding_digest, state: PullMergeState::PendingMerge, commit_log_index: None,
            commit_log_term: None, merged_oid: None, terminal_digest: None, reject_reason: None,
        };
        self.projector.record_pending(&pending).await?;
        if matches!(fault, MergeFaultInjection::DisconnectAfterPendingBeforeCas) {
            return Err(RemoteMergeError::UnknownOutcome(
                "coordinator disconnected after recording PendingMerge before Ref-CAS submit".into(),
            ));
        }
        let cas_outcome = self
            .authority
            .install_and_commit_scoped(spec.repository_id, &spec.base_ref, validated.install_cmd, validated.commit_cmd)
            .await?;
        if matches!(
            fault,
            MergeFaultInjection::CoordinatorTimeoutAfterCasBeforeProjection
                | MergeFaultInjection::DisconnectDuringProjectionCommit
        ) {
            return Err(RemoteMergeError::UnknownOutcome(
                "coordinator timeout / PG disconnect after Ref-CAS submit before projection commit".into(),
            ));
        }
        self.apply_cas_outcome(spec, &pending, cas_outcome, update_forge_pulls).await
    }

    pub(super) async fn apply_cas_outcome(
        &self,
        spec: &MergeAttemptSpec,
        pending: &PendingMergeRecord,
        outcome: AuthorityCommitOutcome,
        update_forge_pulls: bool,
    ) -> Result<MergeAttemptOutcome, RemoteMergeError> {
        match outcome {
            AuthorityCommitOutcome::Committed {
                log_index, log_term, gate_revision, merged_oid, terminal_digest, replayed,
            } => {
                if merged_oid != spec.candidate_target_oid {
                    return Err(RemoteMergeError::Equivocation(format!(
                        "committed OID {merged_oid} disagrees with candidate {}",
                        spec.candidate_target_oid
                    )));
                }
                let receipt = pending.into_committed_receipt(
                    merged_oid, log_index, log_term, gate_revision, terminal_digest, replayed,
                );
                self.projector.project_committed(
                    &receipt, pending.expected_storage_generation, pending.expected_version, update_forge_pulls,
                ).await?;
                Ok(MergeAttemptOutcome::Committed(receipt))
            }
            AuthorityCommitOutcome::Cancelled { log_index, log_term, reason } => {
                let rej = pending.into_rejected_receipt(log_index, log_term, reason.clone(), None);
                self.projector.project_rejected(&rej).await?;
                Err(RemoteMergeError::RevokedAuthorization(reason))
            }
            AuthorityCommitOutcome::Rejected {
                log_index, log_term, reject_code, actual_base_oid, terminal_digest, reason,
            } => {
                let rej = pending.into_rejected_receipt(log_index, log_term, reason.clone(), terminal_digest);
                self.projector.project_rejected(&rej).await?;
                if matches!(reject_code, CommitRejectCode::OldOidMismatch | CommitRejectCode::RevisionMismatch) {
                    return Err(RemoteMergeError::TargetRefMoved {
                        ref_name: spec.base_ref.clone(), expected_base_oid: spec.expected_base_oid.clone(),
                        actual_base_oid,
                    });
                }
                Err(RemoteMergeError::RemoteAuthzDenied(reason))
            }
            AuthorityCommitOutcome::UnknownPending { reason } => Err(RemoteMergeError::UnknownOutcome(reason)),
        }
    }
}
