use axum::{
    body::Body,
    http::{StatusCode, header},
    response::Response,
};
use uuid::Uuid;

use super::{ReceiveContext, ReceiveInput};
use crate::{
    blob_git_gateway::{
        error::GatewayError,
        operation,
        protocol::{self, PushRequest},
        publish,
        repo_session::CommittedWriteSessionProof,
        serving::lookup,
        state::BlobGitState,
    },
    db::Identity,
    namespace_service::push_causal_stream::{
        DurableGatewayReceiptArgs, materialize_durable_gateway_receipt, materialize_historical_gateway_receipt,
    },
    ref_store::{
        CommitRejectCode, RefCommitResult,
        core::pack_commit::PackCommitTerminal,
        pg::{
            public_attempt::PublicAttemptEvidence,
            public_terminal::{PublicAttemptRetirement, PublicAttemptTerminalOutcome},
        },
    },
};

pub(super) enum ReceiveDisposition {
    Fresh,
    Respond(Response),
    Retire(PublicAttemptEvidence, PublicAttemptRetirement),
}

impl ReceiveContext<'_> {
    pub(super) async fn probe(&self, receive: &ReceiveInput<'_>) -> Result<ReceiveDisposition, GatewayError> {
        let outcome = operation::probe_public(
            self.state,
            self.serving,
            receive.actor,
            receive.operation,
            receive.request(),
            receive.digest(),
            receive.mode,
            operation::ReplayBoundary::EarlyReceive,
            self.deadline,
        )
        .await?;
        let (terminal, private_id) = match outcome {
            operation::Probe::Fresh => return Ok(ReceiveDisposition::Fresh),
            operation::Probe::Pending => return Err(GatewayError::OutcomeUnknown),
            operation::Probe::Cancelled { reason } => {
                return cancelled_response(receive.request(), reason, receive.operation)
                    .map(ReceiveDisposition::Respond);
            }
            operation::Probe::Replay { terminal, private_id } => (terminal, private_id),
            operation::Probe::HistoricalReplay { terminal, private_id, restore } => {
                // The archived effect is already complete. Reconstruct its
                // causal proof and report without mirroring or issuing a session.
                materialize_historical_gateway_receipt(
                    DurableGatewayReceiptArgs {
                        pool: self.state.pool(),
                        store: self.state.store(),
                        git_binary: self.state.git_binary(),
                        scratch_root: None,
                        sandbox_root: Some(self.state.scratch_root()),
                        repository_id: receive.repository_id,
                        operation_id: receive.operation,
                        private_operation_id: Some(private_id),
                        deadline: self.deadline,
                    },
                    restore,
                )
                .await?;
                let results = report_results(receive.request(), &terminal)?;
                return git_response(
                    StatusCode::OK,
                    "application/x-git-receive-pack-result",
                    protocol::report_status(receive.request().wants_report(), &results),
                    receive.operation,
                )
                .map(ReceiveDisposition::Respond);
            }
            operation::Probe::Finish { terminal, private_id, evidence, record } => {
                paired_write_raft_gate(self.state, receive.repository_id, false).await?;
                match publish::finish_public_terminal(
                    self.state,
                    self.serving,
                    receive.actor,
                    receive.operation,
                    receive.digest(),
                    receive.mode,
                    &record,
                    self.deadline,
                )
                .await?
                {
                    PublicAttemptTerminalOutcome::Mirrored(_) => (terminal, Some(private_id)),
                    PublicAttemptTerminalOutcome::RetirementRequired(retirement) => {
                        return Ok(ReceiveDisposition::Retire(evidence, retirement));
                    }
                }
            }
            operation::Probe::FinishCancelled => {
                return Err(GatewayError::Conflict("operation cancellation requires reconciliation"));
            }
        };
        self.render_terminal(receive.actor, receive.request(), receive.operation, &terminal, private_id, false)
            .await
            .map(ReceiveDisposition::Respond)
    }

    pub(super) async fn render_terminal(
        &self,
        actor: &Identity,
        request: &PushRequest,
        operation: Uuid,
        terminal: &PackCommitTerminal,
        private_id: Option<Uuid>,
        settle_reclaim: bool,
    ) -> Result<Response, GatewayError> {
        materialize_durable_gateway_receipt(DurableGatewayReceiptArgs {
            pool: self.state.pool(),
            store: self.state.store(),
            git_binary: self.state.git_binary(),
            scratch_root: settle_reclaim.then(|| self.state.scratch_root()),
            sandbox_root: Some(self.state.scratch_root()),
            repository_id: self.serving.gate.repository_id(),
            operation_id: operation,
            private_operation_id: private_id,
            deadline: self.deadline,
        })
        .await?;
        let results = report_results(request, terminal)?;
        let body = protocol::report_status(request.wants_report(), &results);
        self.respond_to_terminal(actor, terminal, body, operation).await
    }
}

pub(super) fn cancelled_response(
    request: &PushRequest,
    reason: &'static str,
    operation: Uuid,
) -> Result<Response, GatewayError> {
    let results = request.commands.iter().map(|command| (command.name.clone(), Err(reason))).collect::<Vec<_>>();
    let body = protocol::report_status(request.wants_report(), &results);
    git_response(StatusCode::OK, "application/x-git-receive-pack-result", body, operation)
}

/// Refuse a paired write while frozen; once the durable terminal is committed, mirror the exact PostgreSQL -> Raft delta into the database-bound live cluster before responding.
pub(super) async fn paired_write_raft_gate(
    state: &BlobGitState,
    repository_id: Uuid,
    committed: bool,
) -> Result<(), GatewayError> {
    let outcome = if committed {
        crate::maintenance::paired_raft_backup::startup_wiring::mirror_gateway_push_to_paired_raft(
            state.pool(),
            repository_id,
        )
        .await
    } else {
        crate::maintenance::paired_raft_backup::startup_wiring::check_paired_write_unfrozen(state.pool()).await
    };
    outcome.map_err(|_| GatewayError::OutcomeUnknown)
}

fn report_results(
    request: &PushRequest,
    terminal: &crate::ref_store::core::pack_commit::PackCommitTerminal,
) -> Result<Vec<(String, Result<(), &'static str>)>, GatewayError> {
    if terminal.refs.len() != request.commands.len() {
        return Err(GatewayError::Internal("durable terminal does not cover every pushed ref"));
    }
    let mut results = Vec::with_capacity(request.commands.len());
    for command in &request.commands {
        match terminal.refs.iter().find(|result| operation::result_name(result) == command.name) {
            Some(RefCommitResult::Applied { name, .. }) => results.push((name.clone(), Ok(()))),
            Some(RefCommitResult::NotApplied { name, reason }) => {
                results.push((name.clone(), Err(reason_text(*reason))))
            }
            None => return Err(GatewayError::Internal("durable terminal is missing a pushed ref")),
        }
    }
    Ok(results)
}

/// The single generic, retryable failure for a committed push whose session
/// could not be issued after the durable commit. It names no repository,
/// incarnation or underlying error; the request middleware re-attaches the
/// same `x-rootyard-operation` so the client resolves that exact operation.
const COMMITTED_SESSION_UNAVAILABLE: &str = "push committed but its repository session could not be issued; resolve this same operation and retry against the authoritative store";

/// Collapse any failure after the commit into the single generic retryable
/// [`COMMITTED_SESSION_UNAVAILABLE`]: the final lookup's own differentiated
/// error, a proof refusal, an issue refusal and the outer timeout all map here.
fn refused<E>(_: E) -> GatewayError {
    GatewayError::Unavailable(COMMITTED_SESSION_UNAVAILABLE)
}

impl ReceiveContext<'_> {
    /// Use the exact durable terminal to mirror and, when configured, issue
    /// a repository session after a fresh writable lookup.
    async fn respond_to_terminal(
        &self,
        actor: &Identity,
        terminal: &PackCommitTerminal,
        body: Vec<u8>,
        operation: Uuid,
    ) -> Result<Response, GatewayError> {
        paired_write_raft_gate(self.state, self.serving.gate.repository_id(), terminal.is_committed()).await?;
        let mut response = git_response(StatusCode::OK, "application/x-git-receive-pack-result", body, operation)?;
        let Some(tokens) = self.state.sessions() else { return Ok(response) };
        if !terminal.is_committed() {
            return Ok(response);
        }
        let issue = async {
            let final_lookup = lookup(
                self.state.pool(),
                actor,
                self.owner,
                self.name,
                true,
                self.state.store().backend_identity(),
                self.deadline,
            )
            .await
            .map_err(refused)?;
            let proof = CommittedWriteSessionProof::new(terminal, self.serving, &final_lookup).map_err(refused)?;
            let issued = tokens.issue_from_committed_write(&proof).map_err(refused)?;
            Ok::<_, GatewayError>(issued)
        };
        let issued = tokio::time::timeout_at(self.deadline, issue).await.map_err(refused)??;
        issued.apply(&mut response);
        Ok(response)
    }
}

/// Git wire reason literals; fixed text only, never a SQL/native message.
fn reason_text(reason: CommitRejectCode) -> &'static str {
    match reason {
        CommitRejectCode::OldOidMismatch => "stale info",
        CommitRejectCode::MissingTarget => "missing necessary objects",
        CommitRejectCode::BadObjectType => "bad object type",
        CommitRejectCode::PrefixConflict => "funny refname",
        CommitRejectCode::HeadDeletedWithoutRetarget => "deletion of the current branch prohibited",
        CommitRejectCode::HeadTargetMissing => "head target missing",
        CommitRejectCode::NoRefApplied => "no refs applied",
        CommitRejectCode::PolicyDenied
        | CommitRejectCode::ProtectedBranch
        | CommitRejectCode::MissingApprovals
        | CommitRejectCode::RequiredCheckFailed
        | CommitRejectCode::LfsLocked
        | CommitRejectCode::RefNotWritable
        | CommitRejectCode::HeadDependencyMissing => "policy denied",
        CommitRejectCode::GateNotFound
        | CommitRejectCode::TenantMismatch
        | CommitRejectCode::ObjectFormatMismatch
        | CommitRejectCode::HistoryIncarnationMismatch
        | CommitRejectCode::AuthorityEpochMismatch
        | CommitRejectCode::GroupEpochMismatch
        | CommitRejectCode::RevisionMismatch => "internal error",
    }
}

pub(super) fn git_response(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    operation: Uuid,
) -> Result<Response, GatewayError> {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    headers.insert(
        header::HeaderName::from_static("x-rootyard-operation"),
        header::HeaderValue::from_str(&operation.to_string())
            .map_err(|_| GatewayError::Internal("operation header is invalid"))?,
    );
    Ok(response)
}
