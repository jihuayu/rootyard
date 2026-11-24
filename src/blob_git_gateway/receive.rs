//! Smart-HTTP `git-receive-pack`: immutable operation probe, quarantine, real native ingestion, then the durable PostgreSQL commit.
//!
//! Ordering is deliberate: spool the bounded body and parse the prefix; compute the producer digest and query the
//! migration-138 operation registry **before** any native child or A3/A4 write (a durable terminal replays from its
//! persisted receipt, a pending operation is an unknown `503`, only an unknown one proceeds); build the sealed view,
//! run native `receive-pack`, stage pairs; then `prepare -> select -> verify -> commit`, rendering `report-status` only from the terminal.
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
};
use uuid::Uuid;

use super::{
    error::GatewayError,
    native, operation,
    protocol::{self, PushRequest},
    publish::{self, Pair, PrivatePushOutcome},
    repo_session::CommittedWriteSessionProof,
    serving::{ServingRepository, lookup},
    session::{authenticate, authorize_write, operation_id, validate_git_protocol},
    snapshot,
    state::BlobGitState,
};
use crate::{
    db::Identity,
    namespace_service::push_causal_stream::{
        DurableGatewayReceiptArgs, GatewayIncomingProofArgs, GatewayPairSummary, UploadReclaimState,
        classify_gateway_reclaim_error, materialize_durable_gateway_receipt, prove_gateway_incoming_pack_closure,
        record_gateway_staging_inflight, settle_aborted_gateway_reclaim, spool_receive_stream_shared_deadline,
        sweep_gateway_reclaim_ledger, verify_gateway_authority_closure,
    },
    ref_store::{
        CommitMode, CommitRejectCode, GitObjectFormat, RefCommitResult, RequestDigest,
        pg::{
            public_attempt::PublicAttemptEvidence,
            public_terminal::{PublicAttemptRetirement, PublicAttemptTerminalOutcome},
        },
    },
};

const MAX_NEW_PACKS: usize = 8;

/// Producer-owned receive identity created exactly where the parsed request,
/// commit mode and producer digest are derived from the same spooled body.
///
/// The type is private to this module, so only the normal receive path can
/// create it. Its fields are moved into [`VerifiedReceive`] only after the
/// native receive-pack stage has produced the ordered staged pair set.
struct ReceiveInput<'a> {
    actor: &'a Identity,
    operation: Uuid,
    repository_id: Uuid,
    object_format: GitObjectFormat,
    request: PushRequest,
    mode: CommitMode,
    digest: RequestDigest,
}

/// The completed receive input. Only [`ReceiveInput::complete`] can build this
/// value, and that method is private to the producer module; sibling modules can
/// borrow it but cannot construct an alternate request/mode/digest/pair set.
#[allow(dead_code)] // The private slot-one handoff is not selected by this route yet.
pub(super) struct VerifiedReceive<'a> {
    actor: &'a Identity,
    operation: Uuid,
    repository_id: Uuid,
    object_format: GitObjectFormat,
    request: PushRequest,
    mode: CommitMode,
    digest: RequestDigest,
    pairs: Vec<Pair>,
}

impl<'a> ReceiveInput<'a> {
    /// Complete the same receive value with the pairs produced from this exact
    /// staged native view. Consuming `self` makes a second completion or a
    /// different pair set impossible.
    fn complete(self, pairs: Vec<Pair>) -> VerifiedReceive<'a> {
        VerifiedReceive {
            actor: self.actor,
            operation: self.operation,
            repository_id: self.repository_id,
            object_format: self.object_format,
            request: self.request,
            mode: self.mode,
            digest: self.digest,
            pairs,
        }
    }

    fn request(&self) -> &PushRequest {
        &self.request
    }

    fn digest(&self) -> RequestDigest {
        self.digest
    }
}

impl<'a> VerifiedReceive<'a> {
    pub(super) fn actor(&self) -> &Identity {
        self.actor
    }

    pub(super) fn operation_id(&self) -> Uuid {
        self.operation
    }

    pub(super) fn repository_id(&self) -> Uuid {
        self.repository_id
    }

    pub(super) fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }

    pub(super) fn request(&self) -> &PushRequest {
        &self.request
    }

    pub(super) fn mode(&self) -> CommitMode {
        self.mode
    }

    pub(super) fn digest(&self) -> RequestDigest {
        self.digest
    }

    pub(super) fn pairs(&self) -> &[Pair] {
        &self.pairs
    }
}

/// Every refusal of this route is rendered with `GatewayError::git`, so the
/// push endpoint keeps its Smart HTTP `Basic` challenge; only the success and
/// `report-status` answers below are built directly.
pub(super) async fn receive_pack(
    state: State<Arc<BlobGitState>>,
    path: AxumPath<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    receive_pack_authorized(state, path, uri, headers, body).await.unwrap_or_else(GatewayError::git)
}

async fn receive_pack_authorized(
    State(state): State<Arc<BlobGitState>>,
    AxumPath((owner, raw_name)): AxumPath<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, GatewayError> {
    let name = repository_name(&raw_name)?;
    let deadline = state.deadline();
    let _slot = state.slot().await?;
    let identity = authenticate(&state, &headers).await?;
    authorize_write(&identity)?;
    validate_git_protocol(&headers)?;
    require_receive_content_type(&headers)?;
    let operation = operation_id(&headers, &uri)?;
    let serving = lookup(state.pool(), &identity, &owner, name, true, state.store().backend_identity(), deadline)
        .await
        .map_err(GatewayError::from)?;
    let repository_id = serving.gate.repository_id();
    let format = serving.gate.object_format();

    // Worst-case inbound reservation, also the decoded gzip ceiling, held until this handler returns.
    let _lease = state.reserve_bytes(state.limits().max_request_bytes)?;
    let _workspace = state.reserve_workspace(state.limits().max_request_bytes)?;
    let work = state.temp_dir("receive")?;
    let request_path = work.path().join("request.bin");
    let encoding = content_encoding(&headers)?;
    let (received, streamed_prefix) = spool_receive_stream_shared_deadline(
        body,
        &request_path,
        state.limits().max_request_bytes,
        state.limits().max_request_bytes,
        encoding,
        deadline,
    )
    .await?;
    if received < 4 {
        return Err(GatewayError::BadRequest("push request is truncated"));
    }
    let prefix = native::read_prefix(&request_path, protocol::MAX_COMMAND_BYTES).await?;
    if !prefix.starts_with(&streamed_prefix) {
        return Err(GatewayError::Internal("spooled push command prefix disagrees with streamed pkt-lines"));
    }
    let parsed_request = protocol::parse_push(&streamed_prefix, format)?;
    let mode = if parsed_request.wants_atomic() { CommitMode::Atomic } else { CommitMode::AcceptedSubset };
    let digest =
        operation::request_digest(repository_id, operation, format, &parsed_request, mode, &request_path, deadline)
            .await?;
    // The only production construction of the receive identity: the digest and
    // mode were just derived from this exact parsed request and spooled body.
    let receive = ReceiveInput {
        actor: &identity,
        operation,
        repository_id,
        object_format: format,
        request: parsed_request,
        mode,
        digest,
    };

    let backend_hex = state.store().backend_identity().as_hex();
    let receipt_args = |settle_reclaim: bool, private_id: Option<Uuid>| DurableGatewayReceiptArgs {
        pool: state.pool(),
        store: state.store(),
        git_binary: state.git_binary(),
        scratch_root: settle_reclaim.then(|| state.scratch_root()),
        sandbox_root: Some(state.scratch_root()),
        repository_id,
        operation_id: operation,
        private_operation_id: private_id,
        deadline,
    };

    // Migration-152 public/private probe before any native child or A3/A4 write.
    // Fresh identifiers continue to the trusted private admission after native
    // ingestion. An existing private wrapper is resolved only through its exact
    // durable evidence, and a pending wrapper whose private attempt is already
    // terminal is finished by the reviewed mirror (never rendered as a false
    // replay). The initial `publish::push` legacy writer is no longer selected.
    let mut pending_retirement: Option<(PublicAttemptEvidence, PublicAttemptRetirement)> = None;
    match operation::probe_public(
        &state,
        &serving,
        receive.actor,
        operation,
        receive.request(),
        receive.digest(),
        receive.mode,
        deadline,
    )
    .await?
    {
        operation::Probe::Fresh => {}
        operation::Probe::Pending => return Err(GatewayError::OutcomeUnknown),
        operation::Probe::Cancelled { reason } => {
            return terminal_response(receive.request(), &cancelled_results(receive.request(), reason), operation);
        }
        operation::Probe::Replay { terminal, private_id } => {
            materialize_durable_gateway_receipt(receipt_args(false, private_id)).await?;
            let results = report_results(receive.request(), &terminal)?;
            let body = protocol::report_status(receive.request().wants_report(), &results);
            return committed_response(CommittedResponse {
                state: &state,
                identity: &identity,
                owner: &owner,
                name,
                authorized: &serving,
                terminal: &terminal,
                body,
                operation,
                deadline,
            })
            .await;
        }
        operation::Probe::Finish { terminal, private_id, evidence, record } => {
            paired_write_raft_gate(&state, repository_id, false).await?;
            // Ask the mirror for the owned disposition before any ACK. It is
            // read-only for a retirement candidate and commits only the exact
            // already-durable terminal for every other rejected/committed case.
            match publish::finish_public_terminal(
                &state,
                &serving,
                receive.actor,
                operation,
                receive.digest(),
                receive.mode,
                &record,
                deadline,
            )
            .await?
            {
                PublicAttemptTerminalOutcome::Mirrored(_) => {
                    materialize_durable_gateway_receipt(receipt_args(false, Some(private_id))).await?;
                    let results = report_results(receive.request(), &terminal)?;
                    let body = protocol::report_status(receive.request().wants_report(), &results);
                    return committed_response(CommittedResponse {
                        state: &state,
                        identity: &identity,
                        owner: &owner,
                        name,
                        authorized: &serving,
                        terminal: &terminal,
                        body,
                        operation,
                        deadline,
                    })
                    .await;
                }
                PublicAttemptTerminalOutcome::RetirementRequired(retirement) => {
                    // The wrapper remains pending. Continue through native
                    // ingestion with the same completed receive value, then
                    // reserve/execute the reviewed slot-one A3/A4/A5 path.
                    pending_retirement = Some((evidence, retirement));
                }
            }
        }
        operation::Probe::FinishCancelled { reason } => {
            // No private cancellation producer is selected by this route. A
            // blind ACK would leave the public wrapper pending, so fail closed
            // with a fixed refusal that names neither UUID.
            let _ = reason;
            return Err(GatewayError::Conflict("operation cancellation requires reconciliation"));
        }
    }
    // A pending, cancelled or replayed claim must never mutate the reclaim ledger or a staging object.
    let _ = sweep_gateway_reclaim_ledger(state.pool(), state.scratch_root(), backend_hex, deadline).await;

    // Sealed read view; the authority snapshot closure is verified before any base pack is used.
    let refs = snapshot::load_ref_view(&state, &serving, deadline).await?;
    let closure_ctx =
        match verify_gateway_authority_closure(&serving.gate, &identity, refs.handle.as_ref(), &refs.refs, backend_hex)
        {
            Ok(ctx) => ctx,
            Err(error) => {
                snapshot::release_view(&state, &refs, deadline).await;
                return Err(error);
            }
        };
    let view = snapshot::build_view(&state, &refs, deadline).await?;
    let before = pack_stems(view.repo())?;
    let target_oids: Vec<String> =
        receive.request().commands.iter().filter(|c| !c.is_delete()).map(|c| c.new.clone()).collect();
    prove_gateway_incoming_pack_closure(GatewayIncomingProofArgs {
        operation_id: operation,
        git_binary: state.git_binary(),
        scratch_root: Some(state.scratch_root()),
        view_repo: view.repo(),
        request_path: &request_path,
        pack_offset: streamed_prefix.len(),
        closure: &closure_ctx,
        target_oids: &target_oids,
        deadline,
    })
    .await?;

    let mut command = view.command(state.git_binary());
    command.arg("receive-pack").arg("--stateless-rpc").arg(view.repo());
    let captured = native::run_capture(command, Some(request_path.as_path()), 4 * 1024 * 1024, deadline).await?;
    if !captured.success {
        // A raw native `unpack ...`/all-`ng` report is only a pre-admission
        // compatibility surface when this public operation is still provably
        // Fresh. A wrapper that is pending, already terminal, cancelled or a
        // retirement candidate must never be closed from raw child output.
        match operation::probe_public(
            &state,
            &serving,
            receive.actor,
            operation,
            receive.request(),
            receive.digest(),
            receive.mode,
            deadline,
        )
        .await?
        {
            operation::Probe::Fresh => {
                if pending_retirement.is_some() {
                    return Err(GatewayError::OutcomeUnknown);
                }
            }
            operation::Probe::Pending => return Err(GatewayError::OutcomeUnknown),
            operation::Probe::Cancelled { reason } => {
                return terminal_response(receive.request(), &cancelled_results(receive.request(), reason), operation);
            }
            operation::Probe::Replay { terminal, private_id } => {
                materialize_durable_gateway_receipt(receipt_args(false, private_id)).await?;
                let results = report_results(receive.request(), &terminal)?;
                let body = protocol::report_status(receive.request().wants_report(), &results);
                return committed_response(CommittedResponse {
                    state: &state,
                    identity: &identity,
                    owner: &owner,
                    name,
                    authorized: &serving,
                    terminal: &terminal,
                    body,
                    operation,
                    deadline,
                })
                .await;
            }
            operation::Probe::Finish { terminal, private_id, record, .. } => {
                paired_write_raft_gate(&state, repository_id, false).await?;
                match publish::finish_public_terminal(
                    &state,
                    &serving,
                    receive.actor,
                    operation,
                    receive.digest(),
                    receive.mode,
                    &record,
                    deadline,
                )
                .await?
                {
                    PublicAttemptTerminalOutcome::Mirrored(_) => {
                        materialize_durable_gateway_receipt(receipt_args(false, Some(private_id))).await?;
                        let results = report_results(receive.request(), &terminal)?;
                        let body = protocol::report_status(receive.request().wants_report(), &results);
                        return committed_response(CommittedResponse {
                            state: &state,
                            identity: &identity,
                            owner: &owner,
                            name,
                            authorized: &serving,
                            terminal: &terminal,
                            body,
                            operation,
                            deadline,
                        })
                        .await;
                    }
                    PublicAttemptTerminalOutcome::RetirementRequired(_) => {
                        // No authoritative terminal exists for the public
                        // operation yet, and this failed native attempt has no
                        // pairs to feed the slot-one retirement path.
                        return Err(GatewayError::OutcomeUnknown);
                    }
                }
            }
            operation::Probe::FinishCancelled { .. } => {
                return Err(GatewayError::Conflict("operation cancellation requires reconciliation"));
            }
        }
        // Unknown when probed, so only an all-`ng`/unpack-failure report passes through.
        if protocol::native_report_is_rejection(&captured.stdout) {
            return response(StatusCode::OK, "application/x-git-receive-pack-result", captured.stdout, operation);
        }
        return Err(GatewayError::BadRequest("push was refused by native Git validation"));
    }

    let new_pairs = collect_pairs(view.repo(), &before)?;
    if new_pairs.len() > MAX_NEW_PACKS {
        return Err(GatewayError::TooLarge);
    }
    let mut pairs = Vec::with_capacity(new_pairs.len());
    let mut pair_summaries = Vec::with_capacity(new_pairs.len());
    for (pack, idx) in new_pairs {
        let staged = Pair::stage(pack, idx, operation).await?;
        pair_summaries.push(GatewayPairSummary {
            pack_sha256: staged.pack_sha.clone(),
            pack_len: staged.pack_len,
            idx_sha256: staged.idx_sha.clone(),
            idx_len: staged.idx_len,
        });
        pairs.push(staged);
    }
    // Only the normal native receive-pack stage of this same receive input can
    // complete the producer value with these ordered staged pairs.
    let receive = receive.complete(pairs);
    record_gateway_staging_inflight(
        state.scratch_root(),
        operation,
        &closure_ctx.snapshot,
        backend_hex,
        &pair_summaries,
    )?;

    paired_write_raft_gate(&state, repository_id, false).await?;
    if let Some((evidence, retirement)) = pending_retirement {
        // Re-authenticate the live serving realm after native ingestion. The
        // gate revision may legitimately have advanced (that is exactly the
        // stale-retirement condition), but tenant/format/history/authority/
        // group/restore/backend may not move. The rotation primitive performs
        // its own final realm/restore proof under the slot-one locks.
        let refreshed = lookup(state.pool(), &identity, &owner, name, true, state.store().backend_identity(), deadline)
            .await
            .map_err(GatewayError::from)?;
        if refreshed.gate.repository_id() != repository_id
            || refreshed.gate.tenant_id() != serving.gate.tenant_id()
            || refreshed.gate.object_format() != serving.gate.object_format()
            || refreshed.gate.history_incarnation() != serving.gate.history_incarnation()
            || refreshed.gate.authority_epoch() != serving.gate.authority_epoch()
            || refreshed.gate.group_epoch() != serving.gate.group_epoch()
            || refreshed.cluster_incarnation != serving.cluster_incarnation
        {
            return Err(GatewayError::Conflict("repository authority changed; retry"));
        }
        let retired = publish::retire_slot_one(&state, &refreshed, &receive, &evidence, &retirement, deadline).await;
        return match retired {
            Ok(retired) => {
                materialize_durable_gateway_receipt(receipt_args(true, Some(retired.private_id))).await?;
                let results = report_results(receive.request(), &retired.terminal)?;
                let body = protocol::report_status(receive.request().wants_report(), &results);
                committed_response(CommittedResponse {
                    state: &state,
                    identity: &identity,
                    owner: &owner,
                    name,
                    authorized: &refreshed,
                    terminal: &retired.terminal,
                    body,
                    operation,
                    deadline,
                })
                .await
            }
            Err(error) => {
                let st = classify_gateway_reclaim_error(&error);
                let _ = settle_aborted_gateway_reclaim(
                    state.pool(),
                    state.scratch_root(),
                    repository_id,
                    operation,
                    backend_hex,
                    st,
                    error.message(),
                )
                .await;
                Err(error)
            }
        };
    }

    let published = publish::push_private(&state, &serving, &receive, deadline).await;
    match published {
        // Only the persisted private/legacy terminal is rendered as a Git
        // report-status. The private durable id is used only as the receipt
        // row key; the public operation header stays unchanged.
        Ok(PrivatePushOutcome::Terminal { terminal, private_id }) => {
            materialize_durable_gateway_receipt(receipt_args(true, private_id)).await?;
            let results = report_results(receive.request(), &terminal)?;
            let body = protocol::report_status(receive.request().wants_report(), &results);
            committed_response(CommittedResponse {
                state: &state,
                identity: &identity,
                owner: &owner,
                name,
                authorized: &serving,
                terminal: &terminal,
                body,
                operation,
                deadline,
            })
            .await
        }
        Ok(PrivatePushOutcome::Cancelled(reason)) => {
            let s = state.scratch_root();
            let _ = settle_aborted_gateway_reclaim(
                state.pool(),
                s,
                repository_id,
                operation,
                backend_hex,
                UploadReclaimState::AbortUnpromoted,
                reason,
            )
            .await;
            terminal_response(receive.request(), &cancelled_results(receive.request(), reason), operation)
        }
        Err(error) => {
            let st = classify_gateway_reclaim_error(&error);
            let s = state.scratch_root();
            let _ = settle_aborted_gateway_reclaim(
                state.pool(),
                s,
                repository_id,
                operation,
                backend_hex,
                st,
                error.message(),
            )
            .await;
            Err(error)
        }
    }
}

/// Refuse a paired write while frozen; once the durable terminal is committed, mirror the exact PostgreSQL -> Raft delta into the database-bound live cluster before responding.
async fn paired_write_raft_gate(
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

fn repository_name(raw: &str) -> Result<&str, GatewayError> {
    let name = raw.strip_suffix(".git").ok_or(GatewayError::NotFound)?;
    if !crate::db::valid_name(name) {
        return Err(GatewayError::NotFound);
    }
    Ok(name)
}

/// The single declared `Content-Encoding` (if any). gzip/x-gzip are decoded by
/// the native spooler under both the wire and expanded byte bounds; an unknown
/// or duplicated encoding is refused before any body byte is buffered.
pub(super) fn content_encoding(headers: &HeaderMap) -> Result<Option<&str>, GatewayError> {
    let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
    let Some(first) = values.next() else { return Ok(None) };
    if values.next().is_some() {
        return Err(GatewayError::BadRequest("duplicate Git request content encoding"));
    }
    first.to_str().map(Some).map_err(|_| GatewayError::BadRequest("Git request content encoding is not text"))
}

fn require_receive_content_type(headers: &HeaderMap) -> Result<(), GatewayError> {
    match headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()) {
        Some("application/x-git-receive-pack-request") => Ok(()),
        _ => Err(GatewayError::BadRequest("invalid Git receive-pack content type")),
    }
}

fn pack_stems(repo: &Path) -> Result<std::collections::BTreeSet<String>, GatewayError> {
    let directory = repo.join("objects").join("pack");
    let mut stems = std::collections::BTreeSet::new();
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(_) => return Ok(stems),
    };
    for entry in entries {
        let entry = entry.map_err(|_| GatewayError::Internal("temporary pack directory is unreadable"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(stem) = name.strip_suffix(".pack")
            && stem.starts_with("pack-")
        {
            stems.insert(stem.to_owned());
        }
    }
    Ok(stems)
}

fn collect_pairs(
    repo: &Path,
    before: &std::collections::BTreeSet<String>,
) -> Result<Vec<(PathBuf, PathBuf)>, GatewayError> {
    let directory = repo.join("objects").join("pack");
    let mut pairs = Vec::new();
    let entries =
        std::fs::read_dir(&directory).map_err(|_| GatewayError::Internal("temporary pack directory is unreadable"))?;
    let mut names = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .collect::<Vec<_>>();
    names.sort();
    for name in names {
        let Some(stem) = name.strip_suffix(".pack") else { continue };
        if !stem.starts_with("pack-") || before.contains(stem) {
            continue;
        }
        let pack = directory.join(&name);
        let idx = directory.join(format!("{stem}.idx"));
        if !idx.is_file() {
            return Err(GatewayError::Internal("native receive-pack produced a pack without an index"));
        }
        pairs.push((pack, idx));
    }
    Ok(pairs)
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

fn cancelled_results(request: &PushRequest, reason: &'static str) -> Vec<(String, Result<(), &'static str>)> {
    request.commands.iter().map(|command| (command.name.clone(), Err(reason))).collect()
}

fn terminal_response(
    request: &PushRequest,
    results: &[(String, Result<(), &'static str>)],
    operation: Uuid,
) -> Result<Response, GatewayError> {
    let body = protocol::report_status(request.wants_report(), results);
    response(StatusCode::OK, "application/x-git-receive-pack-result", body, operation)
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

/// Render the `report-status` of an already encoded durable terminal. With a key set, a committed
/// terminal additionally gets exactly one fresh writable lookup taken only after the whole body
/// exists, issuing a session from the opaque committed-write proof bound to its exact revision; the
/// lookup's own bounded connection is released before returning. Any such failure is the fixed
/// retryable [`COMMITTED_SESSION_UNAVAILABLE`], never a token-free `200`.
///
/// Everything one committed push response needs after the durable terminal exists; bundling it keeps
/// the async boundary readable without suppressing Clippy's argument-count lint.
struct CommittedResponse<'a> {
    state: &'a BlobGitState,
    identity: &'a crate::db::Identity,
    owner: &'a str,
    name: &'a str,
    authorized: &'a ServingRepository,
    terminal: &'a crate::ref_store::core::pack_commit::PackCommitTerminal,
    body: Vec<u8>,
    operation: Uuid,
    deadline: tokio::time::Instant,
}

async fn committed_response(request: CommittedResponse<'_>) -> Result<Response, GatewayError> {
    paired_write_raft_gate(request.state, request.authorized.gate.repository_id(), request.terminal.is_committed())
        .await?;
    let mut response =
        response(StatusCode::OK, "application/x-git-receive-pack-result", request.body, request.operation)?;
    let Some(tokens) = request.state.sessions() else { return Ok(response) };
    if !request.terminal.is_committed() {
        return Ok(response);
    }
    let issue = async {
        let final_lookup = lookup(
            request.state.pool(),
            request.identity,
            request.owner,
            request.name,
            true,
            request.state.store().backend_identity(),
            request.deadline,
        )
        .await
        .map_err(refused)?;
        let proof =
            CommittedWriteSessionProof::new(request.terminal, request.authorized, &final_lookup).map_err(refused)?;
        let issued = tokens.issue_from_committed_write(&proof).map_err(refused)?;
        Ok::<_, GatewayError>(issued)
    };
    let issued = tokio::time::timeout_at(request.deadline, issue).await.map_err(refused)??;
    issued.apply(&mut response);
    Ok(response)
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

fn response(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use uuid::Uuid;

    use crate::{
        blob_git_gateway::{
            protocol::{PushCommand, PushRequest},
            publish::{Pair, slot_one::SlotOneReceive},
        },
        db::{Identity, Repository},
        ref_store::{
            CommitMode, GitObjectFormat, IssuerLane, OperationState, RequestDigest,
            core::{
                contract::CoreGate,
                pack_commit::{PackCommitBaseline, PackMode},
            },
            pg::{
                public_attempt::{PublicAttempt, PublicAttemptEvidence, PublicAttemptRequest},
                public_terminal::PublicAttemptRetirement,
                slot_zero,
            },
            serving::ServingRepository,
        },
    };

    const LANE: &str = "blob-git-receive";

    fn serving() -> ServingRepository {
        let repository_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let gate = CoreGate::new(
            repository_id,
            tenant_id,
            GitObjectFormat::Sha1,
            Uuid::new_v4(),
            1,
            1,
            crate::ref_store::RefName::new("refs/heads/main").unwrap(),
            7,
        )
        .unwrap();
        ServingRepository {
            repository: Repository {
                id: repository_id,
                name: "receive-provenance".to_owned(),
                owner: "owner".to_owned(),
                state: "ready".to_owned(),
                clone_path: "/git/owner/receive-provenance.git".to_owned(),
                storage_backend: "pg_refstore".to_owned(),
                storage_generation: 1,
                object_format: "sha1".to_owned(),
            },
            gate,
            cluster_incarnation: Uuid::new_v4(),
        }
    }

    fn wire_request(atomic: bool) -> PushRequest {
        let mut capabilities = vec!["report-status".to_owned()];
        if atomic {
            capabilities.push("atomic".to_owned());
        }
        PushRequest {
            commands: vec![
                PushCommand { old: "1".repeat(40), new: "2".repeat(40), name: "refs/heads/main".to_owned() },
                PushCommand { old: "3".repeat(40), new: "4".repeat(40), name: "refs/heads/side".to_owned() },
            ],
            capabilities,
        }
    }

    fn mode_for(request: &PushRequest) -> CommitMode {
        if request.wants_atomic() { CommitMode::Atomic } else { CommitMode::AcceptedSubset }
    }

    fn staged_pair(name: &str, pack_digit: char, idx_digit: char) -> Pair {
        Pair {
            pack: PathBuf::from(format!("/staged/{name}.pack")),
            idx: PathBuf::from(format!("/staged/{name}.idx")),
            pack_id: Uuid::new_v4(),
            pack_sha: pack_digit.to_string().repeat(64),
            pack_len: 101,
            idx_sha: idx_digit.to_string().repeat(64),
            idx_len: 37,
        }
    }

    fn staged_pairs() -> Vec<Pair> {
        vec![staged_pair("first", 'a', 'b'), staged_pair("second", 'c', 'd')]
    }

    fn verified_receive<'a>(
        actor: &'a Identity,
        serving: &ServingRepository,
        operation: Uuid,
        request: PushRequest,
        mode: CommitMode,
        digest: RequestDigest,
        pairs: Vec<Pair>,
    ) -> VerifiedReceive<'a> {
        ReceiveInput {
            actor,
            operation,
            repository_id: serving.gate.repository_id(),
            object_format: serving.gate.object_format(),
            request,
            mode,
            digest,
        }
        .complete(pairs)
    }

    fn baseline(serving: &ServingRepository) -> PackCommitBaseline {
        PackCommitBaseline::new(serving.gate.version(), PackMode::MetadataOnly, Vec::new(), Vec::new()).unwrap()
    }

    fn public_request(
        serving: &ServingRepository,
        actor: &Identity,
        public_id: Uuid,
        digest: RequestDigest,
        mode: CommitMode,
    ) -> PublicAttemptRequest {
        PublicAttemptRequest {
            repository_id: serving.gate.repository_id(),
            admission_owner_id: serving.gate.tenant_id(),
            issuer_id: actor.id,
            public_id,
            wire_digest: digest,
            request_mode: mode,
            backend_identity: "a".repeat(64),
            object_format: serving.gate.object_format(),
            history_incarnation: serving.gate.history_incarnation(),
            authority_epoch: serving.gate.authority_epoch(),
            group_epoch: serving.gate.group_epoch(),
            restore_incarnation: serving.cluster_incarnation,
        }
    }

    fn rejected_evidence(
        public: &PublicAttemptRequest,
        private_id: Uuid,
        event_id: Uuid,
        base_revision: i64,
        event_revision: i64,
    ) -> PublicAttemptEvidence {
        let mut current = PublicAttempt {
            slot: 0,
            private_id,
            plan_digest: RequestDigest::of("receive-provenance-plan", &[b"plan"]),
            proof_digest: RequestDigest::of("receive-provenance-proof", &[b"placeholder"]),
            base_revision,
            lane: IssuerLane::new(LANE).unwrap(),
            sequence: 4,
            state: OperationState::Rejected,
            event_id: Some(event_id),
            event_revision: Some(event_revision),
        };
        current.proof_digest = slot_zero::recompute_slot_zero_proof(public, &current).unwrap();
        PublicAttemptEvidence { public_id: public.public_id, current, retired: Vec::new() }
    }

    fn retirement(event_id: Uuid, event_revision: i64) -> PublicAttemptRetirement {
        PublicAttemptRetirement { event_id, event_revision }
    }

    #[test]
    fn completed_receive_preserves_exact_commands_capability_mode_digest_and_pair_order() {
        let serving = serving();
        let actor = Identity {
            id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            parent_token_id: None,
            username: "actor".to_owned(),
            read_only: false,
            token_digest: vec![0; 32],
        };
        let request = wire_request(true);
        let mode = mode_for(&request);
        let digest = RequestDigest::of("receive-provenance-wire", &[b"body"]);
        let operation = Uuid::new_v4();
        let pairs = staged_pairs();
        let expected_pairs = pairs
            .iter()
            .map(|pair| {
                (
                    pair.pack.clone(),
                    pair.idx.clone(),
                    pair.pack_sha.clone(),
                    pair.pack_len,
                    pair.idx_sha.clone(),
                    pair.idx_len,
                )
            })
            .collect::<Vec<_>>();
        let verified = verified_receive(&actor, &serving, operation, request.clone(), mode, digest, pairs);

        assert!(std::ptr::eq(verified.actor(), &actor));
        assert_eq!(verified.operation_id(), operation);
        assert_eq!(verified.repository_id(), serving.gate.repository_id());
        assert_eq!(verified.object_format(), serving.gate.object_format());
        assert_eq!(verified.request(), &request);
        assert_eq!(verified.mode(), CommitMode::Atomic);
        assert_eq!(verified.digest(), digest);
        assert_eq!(verified.pairs().len(), expected_pairs.len());
        for (observed, (pack, idx, pack_sha, pack_len, idx_sha, idx_len)) in
            verified.pairs().iter().zip(&expected_pairs)
        {
            assert_eq!(observed.pack, *pack);
            assert_eq!(observed.idx, *idx);
            assert_eq!(observed.pack_sha, *pack_sha);
            assert_eq!(observed.pack_len, *pack_len);
            assert_eq!(observed.idx_sha, *idx_sha);
            assert_eq!(observed.idx_len, *idx_len);
        }
    }

    #[test]
    fn handoff_uses_only_completed_receive_and_exact_retirement() {
        let serving = serving();
        let actor = Identity {
            id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            parent_token_id: None,
            username: "actor".to_owned(),
            read_only: false,
            token_digest: vec![0; 32],
        };
        let request = wire_request(false);
        let mode = mode_for(&request);
        let digest = RequestDigest::of("receive-provenance-handoff", &[b"body"]);
        let operation = Uuid::new_v4();
        let pairs = staged_pairs();
        let verified = verified_receive(&actor, &serving, operation, request.clone(), mode, digest, pairs);
        let baseline = baseline(&serving);
        let public = public_request(&serving, &actor, operation, digest, mode);
        let private_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let evidence = rejected_evidence(&public, private_id, event_id, 6, 7);
        let retirement = retirement(event_id, 7);

        let handoff = SlotOneReceive::from_verified_rejection(
            &serving,
            &verified,
            &baseline,
            "a".repeat(64),
            &evidence,
            &retirement,
        )
        .unwrap();

        assert_eq!(handoff.public().public_id, operation);
        assert_eq!(handoff.public().wire_digest, digest);
        assert_eq!(handoff.public().request_mode, mode);
        assert_eq!(handoff.public().admission_owner_id, serving.gate.tenant_id());
        assert!(std::ptr::eq(handoff.actor(), verified.actor()));
        assert!(std::ptr::eq(handoff.request(), verified.request()));
        assert_eq!(handoff.pairs().as_ptr(), verified.pairs().as_ptr());
        assert_eq!(handoff.request(), &request);
        assert_eq!(handoff.retirement(), &retirement);
        assert!(!format!("{handoff:?}").contains(&private_id.to_string()));
        assert!(!format!("{handoff:?}").contains(&event_id.to_string()));
        assert!(!format!("{handoff:?}").contains(&"a".repeat(64)));
    }

    #[test]
    fn only_the_exact_current_slot_zero_retirement_is_accepted() {
        let serving = serving();
        let actor = Identity {
            id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            parent_token_id: None,
            username: "actor".to_owned(),
            read_only: false,
            token_digest: vec![0; 32],
        };
        let request = wire_request(false);
        let mode = mode_for(&request);
        let digest = RequestDigest::of("receive-provenance-invalid", &[b"body"]);
        let operation = Uuid::new_v4();
        let pairs = staged_pairs();
        let verified = verified_receive(&actor, &serving, operation, request, mode, digest, pairs);
        let baseline = baseline(&serving);
        let public = public_request(&serving, &actor, operation, digest, mode);
        let private_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let valid = rejected_evidence(&public, private_id, event_id, 6, 7);
        let valid_retirement = retirement(event_id, 7);

        let cases = [
            {
                let mut evidence = valid.clone();
                evidence.current.slot = 1;
                ("slot one is current", evidence, valid_retirement.clone())
            },
            {
                let mut evidence = valid.clone();
                evidence.current.state = OperationState::Pending;
                ("not rejected", evidence, valid_retirement.clone())
            },
            {
                let mut evidence = valid.clone();
                evidence.retired.push(valid.current.clone());
                ("already retired", evidence, valid_retirement.clone())
            },
            {
                let mut evidence = valid.clone();
                evidence.current.event_id = Some(Uuid::new_v4());
                ("different event", evidence, valid_retirement.clone())
            },
            {
                let mut evidence = valid.clone();
                evidence.current.proof_digest = RequestDigest::of("receive-provenance-wrong-proof", &[b"body"]);
                ("different proof", evidence, valid_retirement.clone())
            },
            {
                let mut evidence = valid.clone();
                evidence.public_id = Uuid::new_v4();
                ("different public id", evidence, valid_retirement.clone())
            },
            ("different revision", valid.clone(), retirement(event_id, 8)),
        ];

        for (label, evidence, retirement) in cases {
            let error = SlotOneReceive::from_verified_rejection(
                &serving,
                &verified,
                &baseline,
                "a".repeat(64),
                &evidence,
                &retirement,
            )
            .unwrap_err();
            assert!(matches!(error, GatewayError::Internal(_)), "{label}: {error:?}");
            assert!(!error.message().contains(&private_id.to_string()), "{label}");
            assert!(!format!("{error:?}").contains(&private_id.to_string()), "{label}");
            assert!(!format!("{error:?}").contains(&event_id.to_string()), "{label}");
        }
    }

    #[test]
    fn handoff_refuses_receive_provenance_from_another_repository() {
        let original = serving();
        let other = serving();
        let actor = Identity {
            id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            parent_token_id: None,
            username: "actor".to_owned(),
            read_only: false,
            token_digest: vec![0; 32],
        };
        let request = wire_request(false);
        let mode = mode_for(&request);
        let digest = RequestDigest::of("receive-provenance-foreign", &[b"body"]);
        let operation = Uuid::new_v4();
        let verified = verified_receive(&actor, &original, operation, request, mode, digest, staged_pairs());
        let other_baseline = baseline(&other);
        let public = public_request(&other, &actor, operation, digest, mode);
        let event_id = Uuid::new_v4();
        let evidence = rejected_evidence(&public, Uuid::new_v4(), event_id, 6, 7);
        let retirement = retirement(event_id, 7);

        let error = SlotOneReceive::from_verified_rejection(
            &other,
            &verified,
            &other_baseline,
            "a".repeat(64),
            &evidence,
            &retirement,
        )
        .unwrap_err();
        assert!(matches!(error, GatewayError::Internal(_)), "{error:?}");
        assert!(!format!("{error:?}").contains(&operation.to_string()));
    }

    #[test]
    fn receive_value_is_completed_only_by_the_producer() {
        let source = include_str!("receive.rs");
        let production = source.split("#[cfg(test)]").next().expect("production source");
        assert!(production.contains("struct ReceiveInput<'a> {"));
        assert!(!production.contains("pub(super) struct ReceiveInput<'a>"));
        assert!(production.contains("fn complete(self, pairs: Vec<Pair>) -> VerifiedReceive<'a>"));
        assert!(!production.contains("pub(super) fn complete("));
        assert_eq!(production.matches("ReceiveInput {").count(), 1);
        assert_eq!(production.matches(".complete(pairs)").count(), 1);
        let fields = production
            .split("pub(super) struct VerifiedReceive<'a> {")
            .nth(1)
            .expect("verified receive")
            .split('}')
            .next()
            .expect("verified receive fields");
        for field in
            ["actor:", "operation:", "repository_id:", "object_format:", "request:", "mode:", "digest:", "pairs:"]
        {
            assert!(fields.contains(field));
            assert!(!fields.contains(&format!("pub {field}")));
        }
    }
}

/// Test-only digest derivation for the same exact producer body a fixture will
/// later hand to [`verified_receive_from_test_wire`]. The operation id is
/// supplied by the caller because the durable public identity is chosen before
/// admission; nothing here invents a request or a mode.
#[cfg(test)]
pub(super) async fn producer_request_digest(
    repository_id: Uuid,
    operation: Uuid,
    format: GitObjectFormat,
    body: &Path,
    deadline: tokio::time::Instant,
) -> Result<RequestDigest, GatewayError> {
    let prefix = native::read_prefix(body, protocol::MAX_COMMAND_BYTES).await?;
    let request = protocol::parse_push(&prefix, format)?;
    let mode = if request.wants_atomic() { CommitMode::Atomic } else { CommitMode::AcceptedSubset };
    operation::request_digest(repository_id, operation, format, &request, mode, body, deadline).await
}

/// Test-only completion of one [`VerifiedReceive`] from the exact producer body
/// and already-staged pairs. It uses the production parser and digest assembly,
/// and only [`ReceiveInput::complete`] constructs the value, so it cannot accept
/// independent commands, mode, digest or pair metadata as the handoff input.
#[cfg(test)]
pub(super) async fn verified_receive_from_test_wire<'a>(
    actor: &'a Identity,
    operation: Uuid,
    serving: &ServingRepository,
    body: &Path,
    pairs: Vec<Pair>,
    deadline: tokio::time::Instant,
) -> Result<VerifiedReceive<'a>, GatewayError> {
    let format = serving.gate.object_format();
    let prefix = native::read_prefix(body, protocol::MAX_COMMAND_BYTES).await?;
    let request = protocol::parse_push(&prefix, format)?;
    let mode = if request.wants_atomic() { CommitMode::Atomic } else { CommitMode::AcceptedSubset };
    let digest =
        operation::request_digest(serving.gate.repository_id(), operation, format, &request, mode, body, deadline)
            .await?;
    Ok(ReceiveInput {
        actor,
        operation,
        repository_id: serving.gate.repository_id(),
        object_format: format,
        request,
        mode,
        digest,
    }
    .complete(pairs))
}
