//! Coordinator orchestration separating pre-CAS validation/pending intent persistence
//! from authoritative Ref-CAS commit execution and monotonic receipt projection (`Refs #156`).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::contract::{OperationLookup, OperationState};
use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, CommitScopedRefsCommand, InstallScopedDecisionCommand, RefCasCommand,
    RefCasStateMachine, StateMachineError,
};
use crate::ref_store::core::terminal::{CommitRejectCode, CommitTerminal, RefCommitResult};
use crate::ref_store::projector::DecisionGrantKeyring;

use super::projector::{MergeReceiptStore, PullMergeReceiptProjector};
use super::types::{
    CommittedMergeReceipt, MergeAttemptOutcome, MergeAttemptSpec, MergeFaultInjection, MergePullSnapshot,
    PendingMergeRecord, PullMergeState, RejectedMergeReceipt, RemoteMergeError,
};
use super::validation::{validate_merge_inputs_and_preconditions, verify_pull_remote_authz_grant};

pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RemoteMergeError>> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityCommitOutcome {
    Committed {
        log_index: u64,
        log_term: u64,
        gate_revision: i64,
        merged_oid: String,
        terminal_digest: String,
        replayed: bool,
    },
    Rejected {
        log_index: Option<u64>,
        log_term: Option<u64>,
        reject_code: CommitRejectCode,
        actual_base_oid: Option<String>,
        terminal_digest: Option<String>,
        reason: String,
    },
    Cancelled {
        log_index: Option<u64>,
        log_term: Option<u64>,
        reason: String,
    },
    UnknownPending {
        reason: String,
    },
}

pub trait MergeAuthorityBackend: Send + Sync {
    fn install_and_commit_scoped<'a>(
        &'a self,
        repository_id: Uuid,
        base_ref: &'a str,
        install: InstallScopedDecisionCommand,
        commit: CommitScopedRefsCommand,
    ) -> BackendFuture<'a, AuthorityCommitOutcome>;

    fn query_operation_outcome<'a>(
        &'a self,
        repository_id: Uuid,
        operation_id: Uuid,
        base_ref: &'a str,
    ) -> BackendFuture<'a, Option<AuthorityCommitOutcome>>;

    fn read_ref_oid<'a>(
        &'a self,
        repository_id: Uuid,
        ref_name: &'a str,
    ) -> BackendFuture<'a, Option<String>>;
}

/// Deterministic in-process authority backend backed directly by [`RefCasStateMachine`].
#[derive(Clone, Debug)]
pub struct InProcessRefCasBackend {
    sm: Arc<Mutex<RefCasStateMachine>>,
    next_index: Arc<Mutex<u64>>,
    op_log_ids: Arc<Mutex<BTreeMap<(Uuid, Uuid), AppliedLogId>>>,
}

impl InProcessRefCasBackend {
    pub fn new(sm: RefCasStateMachine) -> Self {
        let next = sm.last_applied().map_or(1, |id| id.index.saturating_add(1));
        Self {
            sm: Arc::new(Mutex::new(sm)),
            next_index: Arc::new(Mutex::new(next)),
            op_log_ids: Arc::new(Mutex::new(BTreeMap::new())),
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
            let install_idx = self.next_log_id();
            {
                let mut sm = self.sm.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(err) = sm.apply(install_idx, RefCasCommand::InstallScopedDecision(install)) {
                    let actual_base_oid = sm.read_refs(repository_id).get(base_ref).cloned();
                    return Ok(map_sm_error_to_outcome(Some(install_idx), err, actual_base_oid));
                }
            }
            let op_id = commit.commit.request.operation_id;
            let commit_idx = self.next_log_id();
            let mut sm = self.sm.lock().unwrap_or_else(|e| e.into_inner());
            match sm.apply(commit_idx, RefCasCommand::CommitScopedRefs(commit)) {
                Ok(ApplyResponse::RefsCommitted(receipt)) => {
                    let stored_idx = {
                        let mut map = self.op_log_ids.lock().unwrap_or_else(|e| e.into_inner());
                        if receipt.replayed {
                            *map.get(&(repository_id, op_id)).unwrap_or(&commit_idx)
                        } else {
                            map.insert((repository_id, op_id), commit_idx);
                            commit_idx
                        }
                    };
                    let diag_base = sm.read_refs(repository_id).get(base_ref).cloned();
                    map_commit_receipt_to_outcome(stored_idx, base_ref, &receipt.terminal, receipt.replayed, diag_base)
                }
                Ok(other) => Err(RemoteMergeError::Equivocation(format!("unexpected RefCas response: {other:?}"))),
                Err(err) => {
                    let diag_base = sm.read_refs(repository_id).get(base_ref).cloned();
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
            let log_id = self
                .op_log_ids
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&(repository_id, operation_id))
                .copied()
                .unwrap_or_else(|| sm.last_applied().unwrap_or(AppliedLogId { term: 1, index: 1 }));
            match lookup {
                OperationLookup::Unknown => {
                    if sm.has_cancel_tombstone(repository_id, operation_id) {
                        return Ok(Some(AuthorityCommitOutcome::Cancelled {
                            log_index: Some(log_id.index),
                            log_term: Some(log_id.term),
                            reason: "operation cancelled by tombstone in RefCasStateMachine".into(),
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

    fn read_ref_oid<'a>(
        &'a self,
        repository_id: Uuid,
        ref_name: &'a str,
    ) -> BackendFuture<'a, Option<String>> {
        Box::pin(async move {
            let sm = self.sm.lock().unwrap_or_else(|e| e.into_inner());
            Ok(sm.read_refs(repository_id).get(ref_name).cloned())
        })
    }
}

/// Maps an immutable [`CommitTerminal`] receipt into [`AuthorityCommitOutcome`].
/// For committed terminals, `merged_oid` is always extracted from `terminal.refs`
/// rather than mutable live ref state so recovery and replay survive later advances.
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
                RefCommitResult::Applied { name, new_oid, .. } if name == base_ref => new_oid.clone(),
                _ => None,
            })
            .ok_or_else(|| {
                RemoteMergeError::Equivocation(format!(
                    "committed Ref-CAS terminal missing Applied new_oid for `{base_ref}`"
                ))
            })?;
        return Ok(AuthorityCommitOutcome::Committed {
            log_index: log_id.index,
            log_term: log_id.term,
            gate_revision: terminal.revision,
            merged_oid,
            terminal_digest,
            replayed,
        });
    }
    let reject_code = terminal
        .rejection
        .as_ref()
        .map_or(CommitRejectCode::PolicyDenied, |r| r.code);
    let reason = format!("ref-cas rejected `{base_ref}` with {}", reject_code.as_str());
    Ok(AuthorityCommitOutcome::Rejected {
        log_index: Some(log_id.index),
        log_term: Some(log_id.term),
        reject_code,
        actual_base_oid: diagnostic_live_base_oid,
        terminal_digest: Some(terminal_digest),
        reason,
    })
}

pub fn map_sm_error_to_outcome(
    log_id: Option<AppliedLogId>,
    err: StateMachineError,
    actual_base_oid: Option<String>,
) -> AuthorityCommitOutcome {
    let idx = log_id.map(|id| id.index);
    let term = log_id.map(|id| id.term);
    match err {
        StateMachineError::AuthzFloorViolation { .. }
        | StateMachineError::ScopeClosingOrClosed { .. }
        | StateMachineError::DecisionExpired { .. } => AuthorityCommitOutcome::Cancelled {
            log_index: idx,
            log_term: term,
            reason: err.to_string(),
        },
        StateMachineError::DecisionDigestMismatch { reason, .. } => AuthorityCommitOutcome::Rejected {
            log_index: idx,
            log_term: term,
            reject_code: CommitRejectCode::RevisionMismatch,
            actual_base_oid,
            terminal_digest: None,
            reason: reason.to_owned(),
        },
        StateMachineError::Store(crate::ref_store::contract::RefStoreError::Cancelled { .. }) => {
            AuthorityCommitOutcome::Cancelled {
                log_index: idx,
                log_term: term,
                reason: err.to_string(),
            }
        }
        other => AuthorityCommitOutcome::Rejected {
            log_index: idx,
            log_term: term,
            reject_code: CommitRejectCode::PolicyDenied,
            actual_base_oid,
            terminal_digest: None,
            reason: other.to_string(),
        },
    }
}

fn canonical_terminal_digest(terminal: &CommitTerminal) -> String {
    let bytes = serde_json::to_vec(terminal).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
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
            return Err(RemoteMergeError::PgDatabase(
                "injected PG disconnect before pending merge insert".into(),
            ));
        }

        let pending = PendingMergeRecord {
            attempt_id: spec.attempt_id,
            operation_id: spec.operation_id,
            decision_id: spec.decision_id,
            tenant_id: spec.tenant_id,
            repository_id: spec.repository_id,
            pull_number: spec.pull_number,
            base_ref: spec.base_ref.clone(),
            expected_head_oid: spec.expected_head_oid.clone(),
            expected_base_oid: spec.expected_base_oid.clone(),
            candidate_target_oid: spec.candidate_target_oid.clone(),
            expected_version: spec.expected_version,
            expected_storage_generation: spec.expected_storage_generation,
            strategy: spec.strategy,
            authz_epoch: spec.grant.payload.authz_epoch,
            pack_sha256: spec.pack_sha256.clone(),
            facts_digest: validated.binding_digest,
            state: PullMergeState::PendingMerge,
            commit_log_index: None,
            commit_log_term: None,
            merged_oid: None,
            terminal_digest: None,
            reject_reason: None,
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
                log_index,
                log_term,
                gate_revision,
                merged_oid,
                terminal_digest,
                replayed,
            } => {
                if merged_oid != spec.candidate_target_oid {
                    return Err(RemoteMergeError::Equivocation(format!(
                        "committed OID {merged_oid} disagrees with candidate {}",
                        spec.candidate_target_oid
                    )));
                }
                let receipt = CommittedMergeReceipt {
                    operation_id: spec.operation_id,
                    decision_id: spec.decision_id,
                    tenant_id: spec.tenant_id,
                    repository_id: spec.repository_id,
                    pull_number: spec.pull_number,
                    base_ref: spec.base_ref.clone(),
                    previous_base_oid: spec.expected_base_oid.clone(),
                    merged_oid,
                    commit_log_index: log_index,
                    commit_log_term: log_term,
                    gate_revision,
                    terminal_digest,
                    replayed,
                };
                self.projector
                    .project_committed(&receipt, pending.expected_storage_generation, pending.expected_version, update_forge_pulls)
                    .await?;
                Ok(MergeAttemptOutcome::Committed(receipt))
            }
            AuthorityCommitOutcome::Cancelled { log_index, log_term, reason } => {
                let rej = RejectedMergeReceipt {
                    operation_id: spec.operation_id,
                    repository_id: spec.repository_id,
                    pull_number: spec.pull_number,
                    commit_log_index: log_index,
                    commit_log_term: log_term,
                    state: PullMergeState::RejectedMerge,
                    reason: reason.clone(),
                    terminal_digest: None,
                };
                self.projector.project_rejected(&rej).await?;
                Err(RemoteMergeError::RevokedAuthorization(reason))
            }
            AuthorityCommitOutcome::Rejected {
                log_index,
                log_term,
                reject_code,
                actual_base_oid,
                terminal_digest,
                reason,
            } => {
                let rej = RejectedMergeReceipt {
                    operation_id: spec.operation_id,
                    repository_id: spec.repository_id,
                    pull_number: spec.pull_number,
                    commit_log_index: log_index,
                    commit_log_term: log_term,
                    state: PullMergeState::RejectedMerge,
                    reason: reason.clone(),
                    terminal_digest,
                };
                self.projector.project_rejected(&rej).await?;
                if matches!(reject_code, CommitRejectCode::OldOidMismatch | CommitRejectCode::RevisionMismatch) {
                    return Err(RemoteMergeError::TargetRefMoved {
                        ref_name: spec.base_ref.clone(),
                        expected_base_oid: spec.expected_base_oid.clone(),
                        actual_base_oid,
                    });
                }
                Err(RemoteMergeError::RemoteAuthzDenied(reason))
            }
            AuthorityCommitOutcome::UnknownPending { reason } => Err(RemoteMergeError::UnknownOutcome(reason)),
        }
    }
}
