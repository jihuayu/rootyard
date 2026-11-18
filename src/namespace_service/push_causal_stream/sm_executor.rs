//! Deterministic Ref-CAS Raft state machine executor enforcing `#112`, `#113`, `#152`, and `#183`.

use std::collections::BTreeMap;
use std::time::Instant;

use tokio::io::AsyncRead;
use uuid::Uuid;

use crate::ref_store::contract::{OperationLookup, OperationState};
use crate::ref_store::core::contract::{CommitMode, CoreGateInit};
use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, BeginOperationCommand, CloseAuthScopeCommand, CommitRefsCommand,
    CommitScopedRefsCommand, InitializeGateCommand, RefCasCommand, RefCasStateMachine, RepositoryLane, ScopeLifecycle,
    SmPackMode, WireCommitRefsRequest, WireGateInit, WireOperationIdentity,
};
use crate::ref_store::core::terminal::{CommitRefsReceipt, CommitTerminal, RefCommitResult, TerminalKind};
use crate::ref_store::core::types::RefName;

use super::closure_prove::{ProvedPushBundle, StreamingProofParams, prove_streaming_push};
use super::commit_gate::{
    PushExecutionInput, PushExecutionOutput, REF_CHANGED_REASON, build_pg_commit_request, evaluate_push_auth_precheck,
    report_status_from_pg_receipt,
};
use super::quarantine::OperationHoldGuard;
use super::receipt::commit_mode_from_capabilities;
use super::reclaim::{QuarantineReclaimLedger, UploadReclaimState};
use super::sm_commands::{
    ScopedDecisionCtx, build_acquire_holds_cmd, build_bootstrap_commands, build_mark_consumed_cmd,
    build_scoped_decision_cmd,
};
use super::types::{
    AuthorizedSnapshotState, FaultInjectionHook, OperationTicket, PushAuthContext, PushCausalError, ReceiveCapabilities,
};

/// Deterministic Raft state-machine coordinator implementing causal push commitment.
#[derive(Clone, Debug)]
pub struct StateMachinePushExecutor {
    sm: RefCasStateMachine,
    next_log_index: u64,
    logical_tick: u64,
    holds: BTreeMap<Uuid, OperationHoldGuard>,
}

impl Default for StateMachinePushExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachinePushExecutor {
    pub fn new() -> Self {
        Self { sm: RefCasStateMachine::new(), next_log_index: 1, logical_tick: 1, holds: BTreeMap::new() }
    }

    pub fn sm(&self) -> &RefCasStateMachine {
        &self.sm
    }

    pub fn hold_guard(&self, operation_id: Uuid) -> Option<&OperationHoldGuard> {
        self.holds.get(&operation_id)
    }

    pub fn initialize_repo_gate(
        &mut self,
        snapshot: &AuthorizedSnapshotState,
        head_branch: &str,
        initial_refs: BTreeMap<String, String>,
    ) -> Result<(), PushCausalError> {
        let head = RefName::branch(head_branch).map_err(|e| PushCausalError::MalformedProtocol(e.to_string()))?;
        let init = CoreGateInit::new(
            snapshot.repository_id,
            snapshot.tenant_id,
            snapshot.object_format,
            snapshot.history_incarnation,
            snapshot.authority_epoch,
            snapshot.group_epoch,
            head,
        )?;
        self.apply(RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&init),
            lane: RepositoryLane::ServingRefStore,
            pack_mode: SmPackMode::PackVerified,
            authz_floor: 1,
        }))?;
        if !initial_refs.is_empty() {
            let gate_ver = self
                .sm
                .read_gate_version(snapshot.repository_id)
                .map_err(|e| PushCausalError::StateMachine(format!("{e:?}")))?
                .ok_or_else(|| PushCausalError::StateMachine("missing initialized gate".into()))?;
            self.logical_tick += 1;
            let (install, commit) =
                build_bootstrap_commands(snapshot, gate_ver.revision(), self.logical_tick, initial_refs)?;
            self.apply(install)?;
            self.apply(commit)?;
        }
        Ok(())
    }

    pub fn close_auth_scope(
        &mut self,
        scope_kind: &str,
        scope_id: Uuid,
        repository_id: Option<Uuid>,
        tenant_id: Option<Uuid>,
        authz_floor: i64,
    ) -> Result<(), PushCausalError> {
        self.logical_tick += 1;
        self.apply(RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
            scope_kind: scope_kind.to_owned(),
            scope_id,
            repository_id,
            tenant_id,
            lifecycle: ScopeLifecycle::Closed,
            authz_floor,
            change_id: Uuid::new_v4(),
            logical_tick: self.logical_tick,
        }))?;
        Ok(())
    }

    pub async fn execute_streaming_push<R>(
        &mut self,
        input: PushExecutionInput<'_, R>,
    ) -> Result<PushExecutionOutput, PushCausalError>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let auth = input.auth;
        let snapshot = input.snapshot;
        let ticket = input.ticket;
        let reclaim_ledger = input.reclaim_ledger;
        let fault_hook = input.fault_hook;
        let backend_hex = input.store.backend_identity().as_hex().to_owned();

        let bundle = prove_streaming_push(StreamingProofParams {
            reader: input.reader,
            gzipped: input.gzipped,
            store: input.store,
            carrier: input.carrier,
            snapshot,
            version_graph: input.version_graph,
            auth,
            branch_policy: input.branch_policy,
            lfs_policy: input.lfs_policy,
            ticket,
            pipeline_mode: input.pipeline_mode,
            ingest_limits: input.ingest_limits,
            proc_limits: input.proc_limits,
            reclaim_ledger,
            fault_hook,
            deadline: input.deadline,
        })
        .await?;

        self.commit_proved_bundle(CommitBundleCtx {
            bundle,
            snapshot,
            ticket,
            auth,
            backend_hex: &backend_hex,
            reclaim_ledger,
            fault_hook,
        })
    }

    pub fn commit_proved_bundle(
        &mut self,
        mut ctx: CommitBundleCtx<'_>,
    ) -> Result<PushExecutionOutput, PushCausalError> {
        let t_commit = Instant::now();
        let req = build_pg_commit_request(
            &ctx.bundle.receipt,
            ctx.snapshot,
            ctx.ticket,
            &ctx.bundle.capabilities,
            ctx.backend_hex,
        )?;
        let gate_ver = self
            .sm
            .read_gate_version(ctx.snapshot.repository_id)
            .map_err(|e| PushCausalError::StateMachine(format!("{e:?}")))?
            .ok_or_else(|| PushCausalError::StateMachine("repository gate not initialized".into()))?;

        let (hold_ids, hold_req_pair, mut hold_guard) = match build_acquire_holds_cmd(
            &ctx.bundle.receipt,
            ctx.snapshot,
            ctx.ticket,
            ctx.auth,
            ctx.backend_hex,
            &gate_ver.digest().as_hex(),
        ) {
            Some((cmd, ids, pair, guard)) => {
                self.apply(cmd)?;
                (ids, Some(pair), guard)
            }
            None => (Vec::new(), None, OperationHoldGuard::acquire(ctx.ticket.operation_id, Vec::new(), Vec::new())),
        };

        if let Err(err) =
            evaluate_push_auth_precheck(ctx.auth, ctx.snapshot.repository_id, Some(&self.sm), ctx.fault_hook)
        {
            let _ = hold_guard.release_on_proven_abort();
            transition_reclaim_if_present(
                ctx.reclaim_ledger,
                ctx.ticket.operation_id,
                UploadReclaimState::AbortUnpromoted,
            );
            self.holds.insert(ctx.ticket.operation_id, hold_guard);
            return Err(err);
        }

        let decision_id = Uuid::new_v4();
        self.logical_tick += 1;
        let (decision_cmd, commitment) = build_scoped_decision_cmd(ScopedDecisionCtx {
            receipt: &ctx.bundle.receipt,
            snapshot: ctx.snapshot,
            ticket: ctx.ticket,
            auth: ctx.auth,
            req: &req,
            decision_id,
            gate_digest: &gate_ver.digest().as_hex(),
            hold_ids: &hold_ids,
            logical_tick: self.logical_tick,
        });
        self.apply(decision_cmd)?;

        self.logical_tick += 1;
        let _ = self.apply(RefCasCommand::BeginOperation(BeginOperationCommand {
            identity: WireOperationIdentity::from(req.identity()),
            logical_tick: self.logical_tick,
        }));

        let resp = self.apply(RefCasCommand::CommitScopedRefs(CommitScopedRefsCommand {
            commit: CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req),
                decision_id: Some(decision_id),
                required_holds: hold_ids.clone(),
                policy_rejects: BTreeMap::new(),
                logical_tick: self.logical_tick,
            },
            expected_commitment: commitment,
        }));

        let ApplyResponse::RefsCommitted(commit_receipt) = resp.inspect_err(|_| {
            let _ = hold_guard.release_on_proven_abort();
            transition_reclaim_if_present(
                ctx.reclaim_ledger,
                ctx.ticket.operation_id,
                UploadReclaimState::AbortUnpromoted,
            );
            self.holds.insert(ctx.ticket.operation_id, hold_guard.clone());
        })?
        else {
            return Err(PushCausalError::StateMachine("expected RefsCommitted response".into()));
        };

        if ctx.fault_hook == FaultInjectionHook::SimulateUnknownAckAfterCommit {
            hold_guard.mark_unknown_outcome();
            transition_reclaim_if_present(
                ctx.reclaim_ledger,
                ctx.ticket.operation_id,
                UploadReclaimState::OutcomeUnknown,
            );
            self.holds.insert(ctx.ticket.operation_id, hold_guard);
            return Err(PushCausalError::CommitUnknown {
                operation_id: ctx.ticket.operation_id,
                detail: "simulated transport drop after commit; holds pinned ActiveHeld until recovery".into(),
            });
        }

        ctx.bundle.receipt.rebind_final_cas_terminal(
            ctx.snapshot,
            ctx.ticket,
            ctx.backend_hex,
            Some(commit_receipt.terminal.revision),
            &commit_receipt.terminal.refs,
        )?;

        let has_applied = commit_receipt.is_committed()
            || commit_receipt.terminal.refs.iter().any(|r| matches!(r, RefCommitResult::Applied { .. }));
        if has_applied {
            if let Some((batch_req_id, consume_req_id)) = hold_req_pair
                && !hold_ids.is_empty()
            {
                self.apply(build_mark_consumed_cmd(ctx.snapshot, batch_req_id, consume_req_id, &hold_ids))?;
            }
            hold_guard.mark_committed()?;
            transition_reclaim_if_present(
                ctx.reclaim_ledger,
                ctx.ticket.operation_id,
                UploadReclaimState::VerifiedPromoted,
            );
        } else {
            hold_guard.release_on_proven_abort()?;
            transition_reclaim_if_present(
                ctx.reclaim_ledger,
                ctx.ticket.operation_id,
                UploadReclaimState::AbortUnpromoted,
            );
        }

        if commit_receipt.terminal.kind == TerminalKind::Rejected
            && commit_mode_from_capabilities(&ctx.bundle.capabilities) == CommitMode::Atomic
        {
            let rejected_refs: Vec<String> = ctx.bundle.commands.iter().map(|c| c.ref_name.clone()).collect();
            self.holds.insert(ctx.ticket.operation_id, hold_guard);
            return Err(PushCausalError::AtomicBatchRejected { rejected_refs, reason: REF_CHANGED_REASON.into() });
        }

        let wire = report_status_from_pg_receipt(&ctx.bundle.capabilities, &commit_receipt)?;
        ctx.bundle.telemetry.commit_ms = t_commit.elapsed().as_millis() as u64;
        self.holds.insert(ctx.ticket.operation_id, hold_guard.clone());
        Ok(PushExecutionOutput {
            proof: ctx.bundle.receipt,
            commit_receipt,
            report_status_wire: wire,
            telemetry: ctx.bundle.telemetry,
            hold_guard,
        })
    }

    pub fn recover_unknown_operation(
        &mut self,
        repository_id: Uuid,
        _tenant_id: Uuid,
        operation_id: Uuid,
        capabilities: &ReceiveCapabilities,
    ) -> Result<(CommitRefsReceipt, Vec<u8>), PushCausalError> {
        let lookup = self
            .sm
            .query_operation(repository_id, operation_id)
            .map_err(|e| PushCausalError::StateMachine(format!("{e:?}")))?;
        let OperationLookup::Known(record) = lookup else {
            return Err(PushCausalError::CommitUnknown {
                operation_id,
                detail: "operation still unknown; hold remains ActiveHeld".into(),
            });
        };
        if record.state() == OperationState::Pending {
            return Err(PushCausalError::CommitUnknown {
                operation_id,
                detail: "operation still pending; hold remains ActiveHeld".into(),
            });
        }
        let terminal_val =
            record.terminal_result().ok_or_else(|| PushCausalError::StateMachine("missing terminal result".into()))?;
        let terminal: CommitTerminal = serde_json::from_value(terminal_val.value().clone())
            .map_err(|e| PushCausalError::StateMachine(e.to_string()))?;
        let receipt = CommitRefsReceipt { record, replayed: true, terminal };
        if let Some(guard) = self.holds.get_mut(&operation_id) {
            if receipt.is_committed()
                || receipt.terminal.refs.iter().any(|r| matches!(r, RefCommitResult::Applied { .. }))
            {
                guard.mark_committed()?;
            } else {
                guard.unknown_outcome_pinned = false;
                guard.release_on_proven_abort()?;
            }
        }
        let wire = report_status_from_pg_receipt(capabilities, &receipt)?;
        Ok((receipt, wire))
    }

    fn apply(&mut self, command: RefCasCommand) -> Result<ApplyResponse, PushCausalError> {
        let log_id = AppliedLogId { term: 1, index: self.next_log_index };
        self.next_log_index += 1;
        self.sm.apply(log_id, command).map_err(|e| PushCausalError::StateMachine(format!("{e:?}")))
    }
}

/// Context bundle passed into [`StateMachinePushExecutor::commit_proved_bundle`].
pub struct CommitBundleCtx<'a> {
    pub bundle: ProvedPushBundle,
    pub snapshot: &'a AuthorizedSnapshotState,
    pub ticket: &'a OperationTicket,
    pub auth: &'a PushAuthContext,
    pub backend_hex: &'a str,
    pub reclaim_ledger: Option<&'a QuarantineReclaimLedger>,
    pub fault_hook: FaultInjectionHook,
}

fn transition_reclaim_if_present(ledger: Option<&QuarantineReclaimLedger>, op_id: Uuid, state: UploadReclaimState) {
    if let Some(ledger) = ledger
        && matches!(ledger.load(op_id), Ok(Some(_)))
    {
        let _ = ledger.transition(op_id, state, Vec::new(), 0, state.as_str());
    }
}
