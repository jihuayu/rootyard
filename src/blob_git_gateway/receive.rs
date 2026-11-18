//! Smart-HTTP `git-receive-pack`: immutable operation probe, quarantine, real
//! native ingestion, then the durable PostgreSQL commit.
//!
//! Ordering is deliberate:
//!
//! 1. spool the bounded (decoded) wire body and parse the command prefix;
//! 2. compute the producer request digest and query the migration-138 operation
//!    registry **before** any native child or A3/A4 write: a durable terminal is
//!    replayed from its persisted receipt, a pending operation is an unknown
//!    outcome (`503`), and only an unknown operation proceeds;
//! 3. build the sealed local view, run native `receive-pack` and stage pairs;
//! 4. `prepare -> select -> verify -> commit`; a `report-status` is generated
//!    only from the durable terminal, never from a caller boolean, a local Git
//!    view or a broad error class.
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
    native,
    operation::{self, Claim},
    protocol::{self, PushRequest},
    publish::{self, Pair, PushOutcome},
    repo_session::CommittedWriteSessionProof,
    serving::{ServingRepository, lookup},
    session::{authenticate, authorize_write, operation_id, validate_git_protocol},
    snapshot,
    state::BlobGitState,
};
use crate::{
    namespace_service::push_causal_stream::{
        DurableGatewayReceiptArgs, GatewayIncomingProofArgs, GatewayPairSummary, UploadReclaimState,
        classify_gateway_reclaim_error, materialize_durable_gateway_receipt, prove_gateway_incoming_pack_closure,
        record_gateway_staging_inflight, settle_aborted_gateway_reclaim, spool_receive_stream_shared_deadline,
        sweep_gateway_reclaim_ledger, verify_gateway_authority_closure,
    },
    ref_store::{CommitMode, CommitRejectCode, RefCommitResult},
};

const MAX_NEW_PACKS: usize = 8;

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

    // Worst-case inbound reservation before a single body byte is read. For a
    // gzip/x-gzip body this is also the decoded ceiling the native spooler
    // enforces; the lease is held until this handler returns.
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
    let request = protocol::parse_push(&streamed_prefix, format)?;
    let mode = if request.wants_atomic() { CommitMode::Atomic } else { CommitMode::AcceptedSubset };
    let digest =
        operation::request_digest(repository_id, operation, format, &request, mode, &request_path, deadline).await?;

    let backend_hex = state.store().backend_identity().as_hex();
    let receipt_args = |settle_reclaim: bool| DurableGatewayReceiptArgs {
        pool: state.pool(),
        store: state.store(),
        git_binary: state.git_binary(),
        scratch_root: settle_reclaim.then(|| state.scratch_root()),
        sandbox_root: Some(state.scratch_root()),
        repository_id,
        operation_id: operation,
        deadline,
    };

    match operation::probe(&state, &serving, &identity, operation, &request, digest, deadline).await? {
        Claim::Pending => return Err(GatewayError::OutcomeUnknown),
        Claim::Cancelled(reason) => {
            return terminal_response(&request, &cancelled_results(&request, reason), operation);
        }
        Claim::Replay(terminal) => {
            materialize_durable_gateway_receipt(receipt_args(false)).await?;
            let results = report_results(&request, &terminal)?;
            let body = protocol::report_status(request.wants_report(), &results);
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
        Claim::Fresh => {}
    }
    // Reclaim sweeping is a fresh-admission side effect only: a pending, cancelled or replayed
    // claim must never mutate the local reclaim ledger or delete a remote staging object.
    let _ = sweep_gateway_reclaim_ledger(state.pool(), state.scratch_root(), backend_hex, deadline).await;

    // Real sealed read view; verify authority snapshot closure before building
    // the native Git view so base packs never skip closure verification.
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
    let target_oids: Vec<String> = request.commands.iter().filter(|c| !c.is_delete()).map(|c| c.new.clone()).collect();
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
    record_gateway_staging_inflight(
        state.scratch_root(),
        operation,
        &closure_ctx.snapshot,
        backend_hex,
        &pair_summaries,
    )?;

    let published =
        publish::push(&state, &serving, &identity, operation, digest, &request, &pairs, mode, deadline).await;
    match published {
        // Only the persisted (fresh or replayed) core terminal is rendered as a
        // Git report-status. Mixed/accepted-subset terminals are replayed
        // exactly as recorded.
        Ok(PushOutcome::Terminal(terminal)) => {
            materialize_durable_gateway_receipt(receipt_args(true)).await?;
            let results = report_results(&request, &terminal)?;
            let body = protocol::report_status(request.wants_report(), &results);
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
        Ok(PushOutcome::Cancelled(reason)) => {
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
            terminal_response(&request, &cancelled_results(&request, reason), operation)
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

/// Render the `report-status` of a durable terminal that is already fully
/// encoded into `body` (no session/DB work happens here, so a replayed or
/// freshly committed terminal that is *not* committed stays token-free).
///
/// With a key set configured, a committed terminal additionally gets exactly
/// one fresh writable lookup taken only now, after the whole body exists, and
/// a session signed from the opaque committed-write proof bound to the
/// terminal's exact revision. The lookup's own bounded connection is released
/// before this returns, so nothing database- or access-related outlives the
/// response. Any final lookup/proof/issue failure is the fixed retryable
/// [`COMMITTED_SESSION_UNAVAILABLE`]; a token-free `200` is never returned when
/// a key set is configured. Without a key set no extra lookup happens.
/// Everything one committed push response needs after the durable terminal
/// exists. Bundling it keeps the async boundary readable without suppressing
/// Clippy's argument-count lint.
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
