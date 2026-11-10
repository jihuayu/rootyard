//! Bounded repository browsing from the same sealed Blob snapshot as Smart HTTP.
//!
//! No local repository is authoritative. Each request captures the current refs,
//! materializes their protected pack closure and discards its computed view.
//!
//! Every JSON read (this module and [`super::history`]) ends in [`finalize`]:
//! the body is fully encoded and size-checked first, then the live
//! authorization is re-run once and its cluster authority incarnation must
//! equal the capture's own anchor — unconditionally, with or without a key set.
//! Only after that fence — from the sealed [`MaterializedServingRead`] retained
//! with the view by [`snapshot::build_sealed_view`] — is a session token
//! issued, and only if the proof's realm matches that same fresh lookup. A
//! checked empty capture has no proof, so it never issues, but its anchor is
//! still fenced; a failed fence drops the encoded body with its slot/byte
//! leases and returns the generic retryable refusal.
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::Response,
};
use base64::Engine;
use bytes::Bytes;
use serde::Serialize;
use tokio::time::Instant;

use super::{
    error::GatewayError,
    native,
    read_session,
    repo_session::{IssuedSession, SessionRealm},
    serving::lookup,
    session::{ReadAuthorization, authenticate, authority_error, read_authorization},
    snapshot::{self, ComputedView},
    state::{BlobGitState, ByteLease},
};
use crate::{
    browse::models::{
        self, BlobByOidQuery, BlobQuery, BlobResponse, TreeByOidQuery, TreeEntry, TreeQuery, TreeResponse,
    },
    ref_store::{
        GitObjectFormat,
        core::pack_snapshot::MaterializedServingRead,
    },
};

const MAX_CAPTURE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MEMORY_BYTES: u64 = 32 * 1024 * 1024;

pub(super) async fn tree(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<TreeQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    read_tree(state, owner, name, query, headers).await
}

pub(super) async fn tree_by_oid(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name, oid)): Path<(String, String, String)>,
    Query(query): Query<TreeByOidQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    read_tree(
        state,
        owner,
        name,
        TreeQuery { oid: Some(oid), path: query.path, after: query.after, limit: query.limit },
        headers,
    )
    .await
}

pub(super) async fn blob(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<BlobQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    read_blob(state, owner, name, query, headers).await
}

pub(super) async fn blob_by_oid(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name, oid)): Path<(String, String, String)>,
    Query(query): Query<BlobByOidQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    read_blob(state, owner, name, BlobQuery { oid: Some(oid), path: query.path }, headers).await
}

/// One authorized, captured and materialized read view shared by every browse
/// and history handler.
///
/// The pipeline is fixed and mirrored from [`read_tree`]: authenticate the
/// current token, take the gateway slot and byte lease (released with the
/// response body), resolve the repository through the shared serving
/// authority, capture the RefStore ref view under the authorized cluster
/// incarnation, keep that capture's own incarnation anchor, score any session
/// lower bound against that captured revision, build its sealed computed view,
/// then require the captured realm to still match. [`finalize`] runs the second
/// authorization and the universal incarnation fence after the response is
/// encoded, right before a session may be issued.
pub(super) struct BrowseSession {
    pub state: Arc<BlobGitState>,
    pub view: ComputedView,
    pub slot: tokio::sync::OwnedSemaphorePermit,
    pub lease: ByteLease,
    pub deadline: tokio::time::Instant,
    /// Captured-output ceiling for this request: the same reserved memory
    /// budget, split so retained native output, the decoded/serialized copies
    /// and the encoded response body all fit inside it together.
    budget: u64,
    authorization: ReadAuthorization,
    /// The repository session key set this request was admitted under, if any.
    /// `None` means the gateway never claims a session for this response.
    tokens: Option<super::repo_session::SessionTokens>,
    /// The actual capture's cluster authority incarnation
    /// ([`snapshot::capture_incarnation`]), read before the ref view was
    /// released. [`finalize`] requires the fresh lookup and any issued proof to
    /// carry exactly this anchor, with or without a key set.
    capture_incarnation: Option<uuid::Uuid>,
    /// Captured non-zero refs (`refs/*` names and stored object ids).
    pub refs: Vec<(String, String)>,
    pub head_ref: String,
    pub head_oid: Option<String>,
    pub format: GitObjectFormat,
    pub repository_id: uuid::Uuid,
    pub storage_generation: i64,
}

impl BrowseSession {
    pub(super) async fn open(
        state: Arc<BlobGitState>,
        headers: HeaderMap,
        owner: String,
        name: String,
    ) -> Result<Self, GatewayError> {
        let actor = authenticate(&state, &headers).await?;
        let deadline = state.deadline();
        let slot = state.slot().await?;
        let memory = memory_budget(&state);
        let lease = state.reserve_bytes(memory)?;
        let serving = lookup(state.pool(), &actor, &owner, &name, false, state.store().backend_identity(), deadline)
            .await
            .map_err(authority_error)?;
        // Only after authorization: capture, then score any session lower
        // bound against the captured revision before any materialization.
        let authorization = read_authorization(state.clone(), &actor, &serving);
        read_session::admit(state.sessions(), &headers, &serving)?;
        let refs = read_session::capture(&state, &headers, &serving, deadline).await?;
        // The capture's own anchor, kept for the final fence: materialization
        // fails close whenever it is absent, and a checked empty capture has no
        // proof to read it from later.
        let capture_incarnation = snapshot::capture_incarnation(&refs);
        let view = snapshot::build_sealed_view(&state, &refs, deadline).await?;
        authorization.revalidate(deadline).await?;
        let tokens = state.sessions().cloned();
        Ok(Self {
            refs: refs.refs.clone(),
            head_ref: refs.head_ref.clone(),
            head_oid: refs.head_oid.clone(),
            format: refs.format,
            repository_id: serving.gate.repository_id(),
            storage_generation: serving.repository.storage_generation,
            authorization,
            tokens,
            capture_incarnation,
            state,
            view,
            slot,
            lease,
            deadline,
            budget: memory / 12,
        })
    }

    /// Per-request captured-output ceiling (never zero: the reservation above
    /// already requires a valid `max_inflight_bytes`, and the gateway's fixed
    /// bounds keep `memory >= 64 KiB`).
    pub(super) fn budget(&self) -> u64 {
        self.budget
    }

    pub(super) fn format_name(&self) -> &'static str {
        self.format.as_str()
    }

    /// The sealed read this request's view was verified over, if the capture
    /// had anything to prove.
    pub(super) fn materialized_read(&self) -> Option<&MaterializedServingRead> {
        self.view.read()
    }
}

/// The session decision for an already-encoded and already-fenced response.
/// Only a retained sealed read bound to the fenced capture anchor can produce
/// [`Self::Issue`]; without a key set the response never claims a session, and
/// without a proof (a checked empty read) no token is minted and no session
/// header is sent.
enum SessionClaim<'a> {
    Disabled,
    NoProof,
    /// The proof whose realm must still match the fresh authorized lookup.
    Issue(&'a MaterializedServingRead),
}

/// Quietly resolved peeled object (`rev-parse --verify --quiet <expr>`), where
/// exit 1 is the only "no such name" verdict and every other failure is a
/// broken native read.
pub(super) async fn peel(session: &BrowseSession, expression: &str) -> Result<String, GatewayError> {
    resolve(&session.state, &session.view, expression, session.deadline).await
}

/// The captured object must be a `kind` object before it is read.
pub(super) async fn require_kind(session: &BrowseSession, oid: &str, kind: &str) -> Result<(), GatewayError> {
    require_type(&session.state, &session.view, oid, kind, session.deadline).await
}

/// A full object id is admitted only when it belongs to the captured ref
/// closure of the verified computed view (same rule as blob-by-oid).
pub(super) async fn require_reachable(session: &BrowseSession, oid: &str) -> Result<(), GatewayError> {
    reachable(&session.state, &session.view, oid, memory_budget(&session.state), session.deadline).await
}

async fn read_tree(
    state: Arc<BlobGitState>,
    owner: String,
    name: String,
    query: TreeQuery,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let path = models::normalize_rel_path(query.path.as_deref()).map_err(bad_input)?;
    let limit = models::validate_limit(query.limit).map_err(bad_input)?;
    let after = validate_tree_after(query.after.as_deref())?.map(str::to_owned);
    let spec = query.oid.as_deref().unwrap_or("HEAD").to_owned();
    validate_spec(&spec)?;
    let session = BrowseSession::open(state, headers, owner, name).await?;
    let spec = captured_revision(&session.refs, &spec)?;
    let deadline = session.deadline;
    let memory = memory_budget(&session.state);
    let root_oid = root_oid(&session.state, &session.view, &spec, memory, deadline).await?;
    let expression = if path.is_empty() { format!("{root_oid}^{{tree}}") } else { format!("{root_oid}:{path}") };
    let tree_oid = resolve(&session.state, &session.view, &expression, deadline).await?;
    require_type(&session.state, &session.view, &tree_oid, "tree", deadline).await?;
    let raw = run(
        &session.state,
        &session.view,
        &["ls-tree", "-z", "-l", &tree_oid],
        (memory / 8).min(MAX_CAPTURE_BYTES),
        deadline,
    )
    .await?;
    let mut entries = parse_tree(&raw, &path, after.as_deref(), limit)?;
    let more = entries.len() > limit;
    entries.truncate(limit);
    let next_after = if more { entries.last().map(|entry| entry.name.clone()) } else { None };
    let result = TreeResponse { oid: root_oid, tree_oid, path, items: entries, next_after };
    // This includes empty trees, just as the Blob handler includes empty files:
    // the session ends in the same final fence and issuance path either way.
    finalize(session, &result).await
}

async fn read_blob(
    state: Arc<BlobGitState>,
    owner: String,
    name: String,
    query: BlobQuery,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let path = models::normalize_rel_path(query.path.as_deref()).map_err(bad_input)?;
    let spec = query.oid.as_deref().unwrap_or("HEAD").to_owned();
    validate_spec(&spec)?;
    if path.is_empty() && !models::valid_non_zero_oid(&spec) {
        return Err(GatewayError::BadRequest("a file path or full blob object identifier is required"));
    }
    let session = BrowseSession::open(state, headers, owner, name).await?;
    let spec = captured_revision(&session.refs, &spec)?;
    let deadline = session.deadline;
    let memory = memory_budget(&session.state);
    let oid = if path.is_empty() {
        reachable(&session.state, &session.view, &spec, memory, deadline).await?;
        resolve(&session.state, &session.view, &spec, deadline).await?
    } else {
        let root = root_oid(&session.state, &session.view, &spec, memory, deadline).await?;
        resolve(&session.state, &session.view, &format!("{root}:{path}"), deadline).await?
    };
    require_type(&session.state, &session.view, &oid, "blob", deadline).await?;
    let raw_size = run(&session.state, &session.view, &["cat-file", "-s", &oid], 64, deadline).await?;
    let size = std::str::from_utf8(&raw_size)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .ok_or(GatewayError::Internal("native blob size is invalid"))?;
    // Twelve times the payload covers base64, optional text and worst-case
    // JSON escaping together with their live input/output buffers.
    let max_blob = MAX_CAPTURE_BYTES
        .min(memory / 12)
        .min(session.state.limits().max_response_bytes / 8)
        .min(session.budget() / 12);
    if size > max_blob {
        return Err(GatewayError::TooLarge);
    }
    let raw = run(&session.state, &session.view, &["cat-file", "blob", &oid], max_blob, deadline).await?;
    if raw.len() as u64 != size {
        return Err(GatewayError::Internal("native blob length differs from its object size"));
    }
    let is_binary = raw.contains(&0) || std::str::from_utf8(&raw).is_err();
    let content = if is_binary { None } else { std::str::from_utf8(&raw).ok().map(str::to_owned) };
    let content_base64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    let result = BlobResponse { oid, size, is_binary, content, content_base64 };
    finalize(session, &result).await
}

fn bad_input(_: crate::Error) -> GatewayError {
    GatewayError::BadRequest("invalid repository browse parameters")
}

fn validate_spec(spec: &str) -> Result<(), GatewayError> {
    if models::valid_revision_spec(spec) {
        Ok(())
    } else {
        Err(GatewayError::BadRequest("invalid repository revision"))
    }
}

fn validate_tree_after(after: Option<&str>) -> Result<Option<&str>, GatewayError> {
    if let Some(name) = after
        && (name.is_empty() || name.len() > 4096 || name.contains(['/', '\0']) || matches!(name, "." | ".."))
    {
        return Err(GatewayError::BadRequest("invalid tree continuation name"));
    }
    // Git tree names can contain tabs and newlines. An API-generated cursor
    // must accept the same UTF-8 names on the next request (URL-encoded).
    Ok(after)
}

fn memory_budget(state: &BlobGitState) -> u64 {
    MAX_MEMORY_BYTES.min(state.limits().max_inflight_bytes)
}

fn captured_revision(refs: &snapshot::RefView, spec: &str) -> Result<String, GatewayError> {
    if models::valid_non_zero_oid(spec) || spec == "HEAD" {
        return Ok(spec.to_owned());
    }
    // A short revision denotes a captured branch/tag, never Git's object-id
    // abbreviation or another native revision fallback.
    let mut found = refs.refs.iter().filter(|(name, _)| {
        name == spec || name.strip_prefix("refs/heads/") == Some(spec) || name.strip_prefix("refs/tags/") == Some(spec)
    });
    let Some((name, _)) = found.next() else {
        return Err(GatewayError::NotFound);
    };
    if found.next().is_some() {
        return Err(GatewayError::BadRequest("repository revision is ambiguous; use its full ref name"));
    }
    Ok(name.clone())
}

async fn run(
    state: &BlobGitState,
    view: &ComputedView,
    args: &[&str],
    ceiling: u64,
    deadline: Instant,
) -> Result<Vec<u8>, GatewayError> {
    let mut command = view.command(state.git_binary());
    command.args(args);
    let output = native::run_capture(command, None, ceiling, deadline).await?;
    if !output.success {
        return Err(GatewayError::Internal("native repository browse was refused"));
    }
    Ok(output.stdout)
}

async fn resolve(
    state: &BlobGitState,
    view: &ComputedView,
    expression: &str,
    deadline: Instant,
) -> Result<String, GatewayError> {
    let mut command = view.command(state.git_binary());
    command.args(["rev-parse", "--verify", "--quiet", "--end-of-options", expression]);
    let output = native::run_capture(command, None, 128, deadline).await?;
    if !output.success {
        return Err(GatewayError::NotFound);
    }
    let oid = std::str::from_utf8(&output.stdout)
        .ok()
        .map(str::trim)
        .filter(|oid| models::valid_non_zero_oid(oid))
        .ok_or(GatewayError::Internal("native repository object identifier is invalid"))?;
    Ok(oid.to_owned())
}

async fn require_type(
    state: &BlobGitState,
    view: &ComputedView,
    oid: &str,
    expected: &str,
    deadline: Instant,
) -> Result<(), GatewayError> {
    let kind = run(state, view, &["cat-file", "-t", oid], 64, deadline).await?;
    if kind.strip_suffix(b"\n") == Some(expected.as_bytes()) { Ok(()) } else { Err(GatewayError::NotFound) }
}

async fn root_oid(
    state: &BlobGitState,
    view: &ComputedView,
    spec: &str,
    memory: u64,
    deadline: Instant,
) -> Result<String, GatewayError> {
    if models::valid_non_zero_oid(spec) {
        reachable(state, view, spec, memory, deadline).await?;
    }
    // Peel annotated tags, including tags of tags, before resolving a path.
    let oid = resolve(state, view, &format!("{spec}^{{}}"), deadline).await?;
    let kind = run(state, view, &["cat-file", "-t", &oid], 64, deadline).await?;
    if kind != b"commit\n" && kind != b"tree\n" {
        return Err(GatewayError::NotFound);
    }
    Ok(oid)
}

async fn reachable(
    state: &BlobGitState,
    view: &ComputedView,
    oid: &str,
    memory: u64,
    deadline: Instant,
) -> Result<(), GatewayError> {
    // Registered packs may also contain unreferenced objects. Knowing a full
    // object id never authorizes browsing those bytes. Only this captured ref
    // closure admits direct object-id reads, including reachable history.
    let raw = run(state, view, &["rev-list", "--objects", "--all", "--no-object-names"], memory / 2, deadline).await?;
    if raw.split(|byte| *byte == b'\n').any(|line| line == oid.as_bytes()) {
        Ok(())
    } else {
        Err(GatewayError::NotFound)
    }
}

fn parse_tree(raw: &[u8], path: &str, after: Option<&str>, limit: usize) -> Result<Vec<TreeEntry>, GatewayError> {
    // Keep at most one page plus its continuation entry. A long parent path
    // must not be copied once for every entry in a large native listing.
    let mut selected = std::collections::BTreeMap::new();
    for record in raw.split(|byte| *byte == 0).filter(|record| !record.is_empty()) {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(GatewayError::Internal("native tree entry is invalid"))?;
        let metadata =
            std::str::from_utf8(&record[..tab]).map_err(|_| GatewayError::Internal("native tree entry is invalid"))?;
        let name = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| GatewayError::Unsupported("tree contains a filename that is not UTF-8"))?;
        let parts: Vec<_> = metadata.split_ascii_whitespace().collect();
        if parts.len() != 4 || name.is_empty() || name.contains('/') || !models::valid_non_zero_oid(parts[2]) {
            return Err(GatewayError::Internal("native tree entry is invalid"));
        }
        if name.len() > 4096 {
            return Err(GatewayError::Unsupported("tree contains a filename beyond the browse name limit"));
        }
        let size = if parts[3] == "-" {
            None
        } else {
            Some(parts[3].parse().map_err(|_| GatewayError::Internal("native tree size is invalid"))?)
        };
        if after.is_some_and(|cursor| name <= cursor)
            || (selected.len() > limit && selected.last_key_value().is_some_and(|(last, _)| *last <= name))
        {
            continue;
        }
        selected.insert(name, (parts[0], parts[1], parts[2], size));
        if selected.len() > limit + 1 {
            selected.pop_last();
        }
    }
    Ok(selected
        .into_iter()
        .map(|(name, (mode, kind, oid, size))| TreeEntry {
            name: name.to_owned(),
            path: if path.is_empty() { name.to_owned() } else { format!("{path}/{name}") },
            mode: mode.to_owned(),
            kind: kind.to_owned(),
            oid: oid.to_owned(),
            size,
        })
        .collect())
}

/// The one JSON read reply path, shared by browse and history.
///
/// Order is fixed and non-negotiable:
///
/// 1. encode the complete body under this request's captured-output ceiling and
///    the response-size limit; a failure issues no token and drops the leases;
/// 2. one final live authorization lookup (after the body was encoded, so no
///    PostgreSQL client is held across Blob/native IO or encoding);
/// 3. the universal restore/incarnation fence
///    ([`read_session::verify_capture_anchor`]), unconditional and before any
///    token decision: the authorized lookup's current
///    `cluster_authority.incarnation` must equal the capture's own anchor, and a
///    retained sealed proof must carry that same anchor. A missing, nil or
///    rotated anchor drops the encoded body with its slot/byte leases and is the
///    generic retryable [`read_session::AUTHORITY_CHANGED`]; no incarnation is
///    ever included. This holds with or without a key set and for a checked
///    empty read that has no proof.
/// 4. only then decide the session: a token is signed from the proof (current
///    key, trusted clock) whose full realm matches this same fresh lookup, and
///    attached with [`IssuedSession::apply`]; a token-disabled gateway or a
///    checked empty read leaves the response token-free.
pub(super) async fn finalize<T: Serialize>(
    session: BrowseSession,
    value: &T,
) -> Result<Response, GatewayError> {
    let state = &session.state;
    let limit = session.budget().min(state.limits().max_response_bytes);
    let bytes = encode_response(value, limit)?;
    let serving = session.authorization.revalidate_serving(session.deadline).await?;
    read_session::verify_capture_anchor(session.capture_incarnation, session.materialized_read(), &serving)?;
    let issued = match session_claim(&session, &serving)? {
        SessionClaim::Disabled | SessionClaim::NoProof => None,
        SessionClaim::Issue(read) => Some(issue(&session, read, &serving)?),
    };
    // The slot and byte leases are unique bounded permits: they move into the
    // response stream state and are never cloned.
    Ok(body_response(bytes, session.slot, session.lease, issued.as_ref()))
}

/// The session decision for an encoded response, made only after the universal
/// fence above passed. Without a key set the response never claims a session.
/// A checked empty capture has no proof, so it omits the session header; its
/// anchor was still fenced just above. A proof outside its own anchor is a fence
/// failure, never a silent token-free answer.
fn session_claim(session: &BrowseSession) -> Result<SessionClaim<'_>, GatewayError> {
    if session.tokens.is_none() {
        return Ok(SessionClaim::Disabled);
    }
    let Some(read) = session.materialized_read() else {
        return Ok(SessionClaim::NoProof);
    };
    if session.capture_incarnation != Some(read.proof().cluster_incarnation()) {
        return Err(GatewayError::Unavailable(read_session::AUTHORITY_CHANGED));
    }
    Ok(SessionClaim::Issue(read))
}

/// Sign the proof's session with the current key and the trusted clock
/// (inside the issuer; no IO), only when the proof's full realm — including the
/// already-fenced incarnation — equals this same fresh authorized lookup. The
/// issuer re-derives every field from the proof itself, so the signed token
/// cannot differ from what this fence authorized. A proof that cannot form a
/// valid session is a fence failure, never a token-free answer.
fn issue(
    session: &BrowseSession,
    read: &MaterializedServingRead,
    serving: &super::serving::ServingRepository,
) -> Result<IssuedSession, GatewayError> {
    let tokens = session.tokens.as_ref().ok_or(GatewayError::Internal("repository session key set is absent"))?;
    let sealed_realm = SessionRealm::from_proof(read.proof().scope(), read.proof().cluster_incarnation())
        .map_err(|_| GatewayError::Unavailable(read_session::AUTHORITY_CHANGED))?;
    if !sealed_realm.matches_serving(serving) {
        return Err(GatewayError::Unavailable(read_session::AUTHORITY_CHANGED));
    }
    tokens
        .issue_from_materialized_read(read)
        .map_err(|_| GatewayError::Internal("repository session could not be issued"))
}

fn body_response(
    bytes: Vec<u8>,
    slot: tokio::sync::OwnedSemaphorePermit,
    lease: ByteLease,
    issued: Option<&IssuedSession>,
) -> Response {
    // Keep the bounded response's capacity charged until its body is consumed
    // or discarded, even after the request future has returned: the moved
    // leases live in the stream state.
    let stream =
        futures_util::stream::unfold((Some(Bytes::from(bytes)), slot, lease), |(bytes, slot, lease)| async move {
            bytes.map(|bytes| (Ok::<_, std::convert::Infallible>(bytes), (None, slot, lease)))
        });
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    response.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    // The served revision travels only with a token bound to the same proof,
    // so a token-disabled or proof-less response never claims a revision.
    if let Some(issued) = issued {
        issued.apply(&mut response);
    }
    response
}

/// Bound the encoded representation while serializing: JSON escaping can
/// expand a valid message or path, so a check after `to_vec` is too late. A
/// response that does not fit is refused before any token exists.
pub(super) fn encode_response(value: &impl Serialize, limit: u64) -> Result<Vec<u8>, GatewayError> {
    struct Buffer {
        bytes: Vec<u8>,
        limit: usize,
        exceeded: bool,
    }
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                self.exceeded = true;
                return Err(std::io::Error::other("repository response exceeds its byte budget"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let limit = usize::try_from(limit).map_err(|_| GatewayError::TooLarge)?;
    let mut buffer = Buffer { bytes: Vec::with_capacity(limit.min(8192)), limit, exceeded: false };
    if serde_json::to_writer(&mut buffer, value).is_err() {
        return Err(if buffer.exceeded {
            GatewayError::TooLarge
        } else {
            GatewayError::Internal("repository response could not be encoded")
        });
    }
    debug_assert!(buffer.bytes.len() as u64 <= limit);
    Ok(buffer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_budget_applies_after_json_escaping() {
        let control = "\0".repeat(16);
        assert!(control.len() < 32);
        assert_eq!(encode_response(&control, 32).unwrap_err(), GatewayError::TooLarge);
        let unicode = "中文";
        let encoded = serde_json::to_vec(unicode).unwrap();
        assert_eq!(encode_response(&unicode, encoded.len() as u64).unwrap(), encoded);
        assert_eq!(encode_response(&unicode, encoded.len() as u64 - 1).unwrap_err(), GatewayError::TooLarge);
    }

    #[test]
    fn tree_decoder_preserves_spaces_tabs_and_empty_blob_size() {
        let oid = "a".repeat(40);
        let raw =
            format!("100644 blob {oid}       0\tempty file\0") + &format!("100644 blob {oid}       3\twith\ttab\0");
        let entries = parse_tree(raw.as_bytes(), "nested", None, 100).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "nested/empty file");
        assert_eq!(entries[0].size, Some(0));
        assert_eq!(entries[1].name, "with\ttab");
    }

    #[test]
    fn tree_decoder_handles_sha256_tree_and_gitlink() {
        let oid = "b".repeat(64);
        let raw =
            format!("160000 commit {oid}       -\tz-submodule\0") + &format!("040000 tree {oid}       -\ta-dir\0");
        let entries = parse_tree(raw.as_bytes(), "", None, 100).unwrap();
        assert_eq!(entries[0].name, "a-dir");
        assert_eq!(entries[0].kind, "tree");
        assert_eq!(entries[1].kind, "commit");
        assert_eq!(entries[0].size, None);
    }

    #[test]
    fn tree_page_sorts_before_truncating_and_keeps_one_continuation() {
        let oid = "a".repeat(40);
        let raw: String =
            ["z", "d", "b", "a", "c"].iter().map(|name| format!("100644 blob {oid}       1\t{name}\0")).collect();
        let entries = parse_tree(raw.as_bytes(), "nested", Some("a"), 2).unwrap();
        assert_eq!(entries.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>(), ["b", "c", "d"]);
        assert_eq!(entries[0].path, "nested/b");
    }

    #[test]
    fn tree_continuation_roundtrips_a_tabbed_filename() {
        let oid = "a".repeat(40);
        let raw: String =
            ["a\tfile", "b\nfile", "c"].iter().map(|name| format!("100644 blob {oid}       1\t{name}\0")).collect();
        let page = parse_tree(raw.as_bytes(), "", None, 1).unwrap();
        let cursor = page[0].name.as_str();
        let after = validate_tree_after(Some(cursor)).unwrap();
        let next = parse_tree(raw.as_bytes(), "", after, 1).unwrap();
        assert_eq!(next[0].name, "b\nfile");
        let after = validate_tree_after(Some(&next[0].name)).unwrap();
        assert_eq!(parse_tree(raw.as_bytes(), "", after, 1).unwrap()[0].name, "c");
    }
}
