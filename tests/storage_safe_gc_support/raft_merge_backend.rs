//! `MergeAuthorityBackend` implemented over the live 3-node mTLS Raft cluster (#122).
//!
//! The Ref-CAS sole commit point is the OpenRaft log: every install/commit command is appended
//! through `ClientWrite` and only becomes visible after a majority of replicas apply it.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Result;
use rootyard::pulls::remote_merge_finalizer::coordinator::{
    BackendFuture, map_commit_receipt_to_outcome, map_sm_error_to_outcome, original_operation_log_id,
};
use rootyard::pulls::remote_merge_finalizer::{AuthorityCommitOutcome, MergeAuthorityBackend, RemoteMergeError};
use rootyard::ref_store::contract::{OperationLookup, OperationState};
use rootyard::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, CommitScopedRefsCommand, InstallScopedDecisionCommand, RefCasCommand,
    RefCasStateMachine, SmDecisionState, StateMachineError,
};
use rootyard::ref_store::core::terminal::CommitTerminal;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use super::LiveRaftVoterCluster;

/// Live production-shaped Ref-CAS authority whose sole commit point is the Raft log.
pub struct LiveRaft3MergeBackend {
    cluster: Arc<AsyncMutex<LiveRaftVoterCluster>>,
    op_log_ids: Mutex<BTreeMap<(Uuid, Uuid), AppliedLogId>>,
    abort_after_install_once: AtomicBool,
}

impl LiveRaft3MergeBackend {
    pub fn new(cluster: Arc<AsyncMutex<LiveRaftVoterCluster>>) -> Self {
        Self { cluster, op_log_ids: Mutex::new(BTreeMap::new()), abort_after_install_once: AtomicBool::new(false) }
    }

    pub fn set_abort_after_install_once(&self, value: bool) {
        self.abort_after_install_once.store(value, Ordering::SeqCst);
    }

    pub async fn apply_repo_command(&self, command: RefCasCommand) -> Result<ApplyResponse, RemoteMergeError> {
        let mut cluster = self.cluster.lock().await;
        let (_, _, last) =
            cluster.append(&command).await.map_err(|err| RemoteMergeError::UnknownOutcome(err.to_string()))?;
        match last {
            Some(Ok(response)) => Ok(response),
            Some(Err(err)) => Err(RemoteMergeError::RemoteAuthzDenied(err.to_string())),
            None => Err(RemoteMergeError::UnknownOutcome("raft append replayed no command result".into())),
        }
    }

    pub async fn state_machine(&self) -> Result<RefCasStateMachine> {
        let cluster = self.cluster.lock().await;
        cluster.state_machine().await
    }
}

impl MergeAuthorityBackend for LiveRaft3MergeBackend {
    fn install_and_commit_scoped<'a>(
        &'a self,
        repository_id: Uuid,
        base_ref: &'a str,
        install: InstallScopedDecisionCommand,
        commit: CommitScopedRefsCommand,
    ) -> BackendFuture<'a, AuthorityCommitOutcome> {
        Box::pin(async move {
            let (dec_id, op_id) = (commit.commit.decision_id, commit.commit.request.identity.operation_id);
            let mut cluster = self.cluster.lock().await;
            let (install_id, sm, installed) = cluster
                .append(&RefCasCommand::InstallScopedDecision(install))
                .await
                .map_err(|err| RemoteMergeError::UnknownOutcome(err.to_string()))?;
            match installed {
                Some(Ok(_)) | None => {}
                Some(Err(StateMachineError::DecisionConflict {
                    decision_id,
                    state: SmDecisionState::Consumed | SmDecisionState::Rejected,
                })) if Some(decision_id) == dec_id => {}
                Some(Err(err)) => {
                    let actual_base_oid = sm.read_refs(repository_id).get(base_ref).cloned();
                    return Ok(map_sm_error_to_outcome(Some(install_id), err, actual_base_oid));
                }
            }
            // The install is already durable in the Raft log, so Safe GC always observes the
            // installed-but-maybe-uncommitted decision and can never read an older cut.
            if self.abort_after_install_once.swap(false, Ordering::SeqCst) {
                return Ok(AuthorityCommitOutcome::UnknownPending {
                    reason: "injected abort after install before Ref-CAS commit".into(),
                });
            }
            let (commit_id, sm, committed) = cluster
                .append(&RefCasCommand::CommitScopedRefs(commit))
                .await
                .map_err(|err| RemoteMergeError::UnknownOutcome(err.to_string()))?;
            match committed {
                Some(Ok(ApplyResponse::RefsCommitted(receipt))) => {
                    let stored_idx = match original_operation_log_id(&sm, repository_id, op_id) {
                        Some(original) => {
                            self.op_log_ids
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .entry((repository_id, op_id))
                                .or_insert(original);
                            original
                        }
                        None if receipt.replayed => {
                            return Err(RemoteMergeError::Equivocation(
                                "replayed Ref-CAS commit missing original state-machine AppliedLogId".into(),
                            ));
                        }
                        None => {
                            self.op_log_ids
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .insert((repository_id, op_id), commit_id);
                            commit_id
                        }
                    };
                    let diagnostic_live_base_oid = sm.read_refs(repository_id).get(base_ref).cloned();
                    map_commit_receipt_to_outcome(
                        stored_idx,
                        base_ref,
                        &receipt.terminal,
                        receipt.replayed,
                        diagnostic_live_base_oid,
                    )
                }
                Some(Ok(other)) => {
                    Err(RemoteMergeError::Equivocation(format!("unexpected RefCas response: {other:?}")))
                }
                Some(Err(err)) => {
                    let diagnostic_live_base_oid = sm.read_refs(repository_id).get(base_ref).cloned();
                    Ok(map_sm_error_to_outcome(Some(commit_id), err, diagnostic_live_base_oid))
                }
                None => Err(RemoteMergeError::UnknownOutcome("raft commit replayed no command result".into())),
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
            let sm = {
                let cluster = self.cluster.lock().await;
                cluster.state_machine().await.map_err(|err| RemoteMergeError::UnknownOutcome(err.to_string()))?
            };
            let lookup = sm
                .query_operation(repository_id, operation_id)
                .map_err(|err| RemoteMergeError::RemoteAuthzDenied(err.to_string()))?;
            let log_id = original_operation_log_id(&sm, repository_id, operation_id).unwrap_or_else(|| {
                self.op_log_ids
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(&(repository_id, operation_id))
                    .copied()
                    .unwrap_or_else(|| sm.last_applied().unwrap_or(AppliedLogId { term: 1, index: 1 }))
            });
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
                    let diagnostic_live_base_oid = sm.read_refs(repository_id).get(base_ref).cloned();
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
                            let terminal_result = record
                                .terminal_result()
                                .ok_or_else(|| RemoteMergeError::Equivocation("missing terminal_result".into()))?;
                            let terminal: CommitTerminal = serde_json::from_value(terminal_result.value().clone())
                                .map_err(|err| RemoteMergeError::Equivocation(err.to_string()))?;
                            Ok(Some(map_commit_receipt_to_outcome(
                                log_id,
                                base_ref,
                                &terminal,
                                true,
                                diagnostic_live_base_oid,
                            )?))
                        }
                    }
                }
            }
        })
    }

    fn read_ref_oid<'a>(&'a self, repository_id: Uuid, ref_name: &'a str) -> BackendFuture<'a, Option<String>> {
        Box::pin(async move {
            let sm = {
                let cluster = self.cluster.lock().await;
                cluster.state_machine().await.map_err(|err| RemoteMergeError::UnknownOutcome(err.to_string()))?
            };
            Ok(sm.read_refs(repository_id).get(ref_name).cloned())
        })
    }
}
