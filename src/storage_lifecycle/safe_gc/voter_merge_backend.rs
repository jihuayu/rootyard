//! Production `MergeAuthorityBackend` over the committed `pm/*` Raft transcript (#122/#156).
use super::super::SafeGcError;
use super::super::voter_writer::{RaftCommitApplyOutcome, SafeGcRaftCommitWriter};
use crate::pulls::remote_merge_finalizer::coordinator::{BackendFuture, map_commit_receipt_to_outcome};
use crate::pulls::remote_merge_finalizer::coordinator::{map_sm_error_to_outcome, original_operation_log_id};
use crate::pulls::remote_merge_finalizer::{AuthorityCommitOutcome, MergeAuthorityBackend, RemoteMergeError};
use crate::ref_store::contract::{OperationLookup, OperationState};
use crate::ref_store::core::state_machine::{AppliedLogId, ApplyResponse, CommitScopedRefsCommand};
use crate::ref_store::core::state_machine::{InstallScopedDecisionCommand, RefCasCommand, RefCasStateMachine};
use crate::ref_store::core::state_machine::{SmDecisionState, StateMachineError};
use crate::ref_store::core::terminal::CommitTerminal;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;
type CommitOutcome = (AppliedLogId, RefCasStateMachine, RaftCommitApplyOutcome);
/// Production `MergeAuthorityBackend` over the committed `pm/*` Raft transcript (#122/#156).
#[derive(Clone)]
pub struct SafeGcRaftMergeBackend {
    writer: SafeGcRaftCommitWriter,
    op_log_ids: Arc<Mutex<BTreeMap<(Uuid, Uuid), AppliedLogId>>>,
    abort_after_install_once: Arc<AtomicBool>,
}
impl SafeGcRaftMergeBackend {
    pub fn new(writer: SafeGcRaftCommitWriter) -> Self {
        Self {
            writer,
            op_log_ids: Arc::new(Mutex::new(BTreeMap::new())),
            abort_after_install_once: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn from_config_file(path: &Path) -> Result<Self, SafeGcError> {
        Ok(Self::new(SafeGcRaftCommitWriter::from_config_file(path)?))
    }
    pub fn writer(&self) -> &SafeGcRaftCommitWriter {
        &self.writer
    }
    #[doc(hidden)]
    pub fn set_abort_after_install_once(&self, value: bool) {
        self.abort_after_install_once.store(value, Ordering::SeqCst);
    }
    pub async fn apply_repo_command(&self, command: RefCasCommand) -> Result<ApplyResponse, RemoteMergeError> {
        match self.commit(command).await?.2 {
            Some(Ok(response)) => Ok(response),
            Some(Err(err)) => Err(RemoteMergeError::RemoteAuthzDenied(err.to_string())),
            None => Err(RemoteMergeError::UnknownOutcome("raft append replayed no command result".into())),
        }
    }
    pub async fn state_machine(&self) -> Result<RefCasStateMachine, SafeGcError> {
        self.writer.replay_committed_state().await
    }
    async fn replay(&self) -> Result<RefCasStateMachine, RemoteMergeError> {
        self.writer.replay_committed_state().await.map_err(|err| RemoteMergeError::UnknownOutcome(err.to_string()))
    }
    async fn commit(&self, command: RefCasCommand) -> Result<CommitOutcome, RemoteMergeError> {
        self.writer.commit_command(&command).await.map_err(|err| RemoteMergeError::UnknownOutcome(err.to_string()))
    }
    fn op_log_ids(&self) -> MutexGuard<'_, BTreeMap<(Uuid, Uuid), AppliedLogId>> {
        self.op_log_ids.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    fn stored_log_id(
        &self,
        repository_id: Uuid,
        operation_id: Uuid,
        sm: &RefCasStateMachine,
        commit_id: AppliedLogId,
        replayed: bool,
    ) -> Result<AppliedLogId, RemoteMergeError> {
        match original_operation_log_id(sm, repository_id, operation_id) {
            Some(original) => {
                self.op_log_ids().entry((repository_id, operation_id)).or_insert(original);
                Ok(original)
            }
            None if replayed => Err(RemoteMergeError::Equivocation(
                "replayed Ref-CAS commit missing original state-machine AppliedLogId".into(),
            )),
            None => {
                self.op_log_ids().insert((repository_id, operation_id), commit_id);
                Ok(commit_id)
            }
        }
    }
}
impl MergeAuthorityBackend for SafeGcRaftMergeBackend {
    fn install_and_commit_scoped<'a>(
        &'a self,
        repository_id: Uuid,
        base_ref: &'a str,
        install: InstallScopedDecisionCommand,
        commit: CommitScopedRefsCommand,
    ) -> BackendFuture<'a, AuthorityCommitOutcome> {
        Box::pin(async move {
            let (dec_id, op_id) = (commit.commit.decision_id, commit.commit.request.identity.operation_id);
            let (install_id, sm, installed) = self.commit(RefCasCommand::InstallScopedDecision(install)).await?;
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
            if self.abort_after_install_once.swap(false, Ordering::SeqCst) {
                return Ok(AuthorityCommitOutcome::UnknownPending {
                    reason: "injected abort after install before Ref-CAS commit".into(),
                });
            }
            let (commit_id, sm, committed) = self.commit(RefCasCommand::CommitScopedRefs(commit)).await?;
            match committed {
                Some(Ok(ApplyResponse::RefsCommitted(receipt))) => {
                    let stored_idx = self.stored_log_id(repository_id, op_id, &sm, commit_id, receipt.replayed)?;
                    let base_oid = sm.read_refs(repository_id).get(base_ref).cloned();
                    map_commit_receipt_to_outcome(stored_idx, base_ref, &receipt.terminal, receipt.replayed, base_oid)
                }
                Some(Ok(other)) => {
                    Err(RemoteMergeError::Equivocation(format!("unexpected RefCas response: {other:?}")))
                }
                Some(Err(err)) => {
                    let base_oid = sm.read_refs(repository_id).get(base_ref).cloned();
                    Ok(map_sm_error_to_outcome(Some(commit_id), err, base_oid))
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
            let sm = self.replay().await?;
            let lookup = sm
                .query_operation(repository_id, operation_id)
                .map_err(|err| RemoteMergeError::RemoteAuthzDenied(err.to_string()))?;
            let log_id = original_operation_log_id(&sm, repository_id, operation_id).unwrap_or_else(|| {
                self.op_log_ids()
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
                    let snapshot = sm.snapshot().map_err(|err| RemoteMergeError::RemoteAuthzDenied(err.to_string()))?;
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
                    let base_oid = sm.read_refs(repository_id).get(base_ref).cloned();
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
                            Ok(Some(map_commit_receipt_to_outcome(log_id, base_ref, &terminal, true, base_oid)?))
                        }
                    }
                }
            }
        })
    }
    fn read_ref_oid<'a>(&'a self, repository_id: Uuid, ref_name: &'a str) -> BackendFuture<'a, Option<String>> {
        Box::pin(async move {
            let sm = self.replay().await?;
            Ok(sm.read_refs(repository_id).get(ref_name).cloned())
        })
    }
}
#[cfg(test)]
mod tests {
    use super::super::SafeGcRaftCommitWriterConfig;
    fn config() -> SafeGcRaftCommitWriterConfig {
        serde_json::from_value(serde_json::json!({
            "ca_cert_pem": "ca.crt",
            "client_cert_pem": "cli.crt",
            "client_key_pem": "cli.key",
            "write_timeout_ms": 20_000,
            "replicas": [
                {"replica_id": 1, "addr": "127.0.0.1:7001", "server_name": "raft-node-1.refcas.internal"},
                {"replica_id": 2, "addr": "127.0.0.1:7002", "server_name": "raft-node-2.refcas.internal"},
                {"replica_id": 3, "addr": "127.0.0.1:7003", "server_name": "raft-node-3.refcas.internal"},
            ],
        }))
        .unwrap()
    }
    #[test]
    fn writer_config_rejects_invalid_deployments_and_unknown_fields() {
        config().validate().unwrap();
        let mut empty = config();
        empty.replicas.clear();
        assert!(empty.validate().is_err());
        let mut duplicate = config();
        duplicate.replicas[1].replica_id = 1;
        assert!(duplicate.validate().is_err());
        let mut timeout = config();
        timeout.write_timeout_ms = 99;
        assert!(timeout.validate().is_err());
        let mut cert = config();
        cert.ca_cert_pem = std::path::PathBuf::new();
        assert!(cert.validate().is_err());
        let mut doc = serde_json::to_value(config()).unwrap();
        doc["unknown_field"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SafeGcRaftCommitWriterConfig>(doc).is_err());
    }
}
