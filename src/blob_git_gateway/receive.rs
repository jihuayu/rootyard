//! Smart-HTTP `git-receive-pack`: immutable operation probe, quarantine, real native ingestion, then the durable PostgreSQL commit.
//!
//! Ordering is deliberate: spool the bounded body and parse the prefix; compute the producer digest and query the
//! migration-138 operation registry **before** any native child or A3/A4 write (a durable terminal replays from its
//! persisted receipt, a pending operation is an unknown `503`, only an unknown one proceeds); build the sealed view,
//! run native `receive-pack`, stage pairs; then `prepare -> select -> verify -> commit`, rendering `report-status` only from the terminal.
#[cfg(test)]
use std::path::Path;
use std::sync::Arc;

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
    serving::{ServingRepository, lookup},
    session::{authenticate, authorize_write, operation_id, validate_git_protocol},
    snapshot,
    state::BlobGitState,
};
use crate::{
    db::Identity,
    namespace_service::push_causal_stream::{
        GatewayIncomingProofArgs, GatewayPairSummary, UploadReclaimState, classify_gateway_reclaim_error,
        prove_gateway_incoming_pack_closure, record_gateway_staging_inflight, settle_aborted_gateway_reclaim,
        spool_receive_stream_shared_deadline, sweep_gateway_reclaim_ledger, verify_gateway_authority_closure,
    },
    ref_store::{CommitMode, GitObjectFormat, RequestDigest},
};

mod pack_files;
mod response;

use pack_files::{collect_pairs, pack_stems};

use response::{ReceiveDisposition, cancelled_response, paired_write_raft_gate};

struct ReceiveContext<'a> {
    state: &'a BlobGitState,
    serving: &'a ServingRepository,
    owner: &'a str,
    name: &'a str,
    deadline: tokio::time::Instant,
}

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
    let context = ReceiveContext { state: &state, serving: &serving, owner: &owner, name, deadline };
    // Probe before native Git or staged writes. Only a fresh operation can
    // sweep old staging. A proven retirement can resume without that sweep.
    let pending_retirement = match context.probe(&receive).await? {
        ReceiveDisposition::Fresh => {
            let _ = sweep_gateway_reclaim_ledger(state.pool(), state.scratch_root(), backend_hex, deadline).await;
            None
        }
        ReceiveDisposition::Respond(response) => return Ok(response),
        ReceiveDisposition::Retire(evidence, retirement) => Some((evidence, retirement)),
    };

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
        // Raw native rejection is authoritative only before admission. An
        // existing wrapper must follow its exact durable outcome.
        match context.probe(&receive).await? {
            ReceiveDisposition::Fresh if pending_retirement.is_none() => {}
            ReceiveDisposition::Respond(response) => return Ok(response),
            ReceiveDisposition::Fresh | ReceiveDisposition::Retire(..) => return Err(GatewayError::OutcomeUnknown),
        }
        // Unknown when probed, so only an all-`ng`/unpack-failure report passes through.
        if protocol::native_report_is_rejection(&captured.stdout) {
            return response::git_response(
                StatusCode::OK,
                "application/x-git-receive-pack-result",
                captured.stdout,
                operation,
            );
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
                ReceiveContext { serving: &refreshed, ..context }
                    .render_terminal(
                        &identity,
                        receive.request(),
                        operation,
                        &retired.terminal,
                        Some(retired.private_id),
                        true,
                    )
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
            context.render_terminal(&identity, receive.request(), operation, &terminal, private_id, true).await
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
            cancelled_response(receive.request(), reason, operation)
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

#[cfg(test)]
mod tests;

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
