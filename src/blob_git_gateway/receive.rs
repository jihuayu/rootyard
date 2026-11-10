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
    serving::lookup,
    session::{authenticate, authorize_write, operation_id, validate_git_protocol},
    snapshot,
    state::BlobGitState,
};
use crate::ref_store::{CommitMode, CommitRejectCode, RefCommitResult};

const MAX_NEW_PACKS: usize = 8;

pub(super) async fn receive_pack(
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
    let received = native::spool_body_with_encoding(
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
    let request = protocol::parse_push(&prefix, format)?;
    let mode = if request.wants_atomic() { CommitMode::Atomic } else { CommitMode::AcceptedSubset };
    let digest =
        operation::request_digest(repository_id, operation, format, &request, mode, &request_path, deadline).await?;

    // Immutable operation identity before native fresh writes. A terminal is
    // replayed from the durable receipt; a pending operation stays unknown.
    match operation::probe(&state, &serving, &identity, operation, &request, digest, deadline).await? {
        Claim::Pending => return Err(GatewayError::OutcomeUnknown),
        Claim::Cancelled(reason) => {
            let results = cancelled_results(&request, reason);
            return terminal_response(&request, &results, operation);
        }
        Claim::Replay(terminal) => {
            let results = report_results(&request, &terminal)?;
            return terminal_response(&request, &results, operation);
        }
        Claim::Fresh => {}
    }

    // Real sealed read view; the native process sees the exact refs/bytes of the
    // pack-aware snapshot, never a legacy working copy.
    let refs = snapshot::load_ref_view(&state, &serving, deadline).await?;
    let view = snapshot::build_view(&state, &refs, deadline).await?;
    let before = pack_stems(view.repo())?;

    let mut command = view.command(state.git_binary());
    command.arg("receive-pack").arg("--stateless-rpc").arg(view.repo());
    let captured = native::run_capture(command, Some(request_path.as_path()), 4 * 1024 * 1024, deadline).await?;
    if !captured.success {
        // The operation was unknown when probed, so nothing was published: a
        // complete native refusal proves no authoritative ref change. Only an
        // all-`ng`/unpack-failure report is passed through; a local report that
        // claims an applied ref is never turned into durable success.
        if protocol::native_report_is_rejection(&captured.stdout) {
            return response(StatusCode::OK, "application/x-git-receive-pack-result", captured.stdout, operation);
        }
        return Err(GatewayError::BadRequest("push was refused by native Git validation"));
    }

    // A ref-only update (or a push whose objects already exist) legitimately
    // stages no new pack: the sealed verifier then proves the target objects
    // from the current registered memberships. A missing object fails there.
    let new_pairs = collect_pairs(view.repo(), &before)?;
    if new_pairs.len() > MAX_NEW_PACKS {
        return Err(GatewayError::TooLarge);
    }
    let mut pairs = Vec::with_capacity(new_pairs.len());
    for (pack, idx) in new_pairs {
        pairs.push(Pair::stage(pack, idx, operation).await?);
    }

    let published =
        publish::push(&state, &serving, &identity, operation, digest, &request, &pairs, mode, deadline).await;
    match published {
        // Only the persisted (fresh or replayed) core terminal is rendered as a
        // Git report-status. Mixed/accepted-subset terminals are replayed
        // exactly as recorded.
        Ok(PushOutcome::Terminal(terminal)) => {
            let results = report_results(&request, &terminal)?;
            terminal_response(&request, &results, operation)
        }
        Ok(PushOutcome::Cancelled(reason)) => {
            let results = cancelled_results(&request, reason);
            terminal_response(&request, &results, operation)
        }
        // Contention, an unverified adapter and an unknown COMMIT stay HTTP
        // errors with the operation header; they never become `ng`/`ok`.
        Err(error) => Err(error),
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
