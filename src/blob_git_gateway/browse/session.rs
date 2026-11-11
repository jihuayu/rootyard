//! Authorized browse session and the one JSON read reply path (#174).
//!
//! Extraction keeps `browse.rs` inside the submodule line bound without changing
//! the public gateway surface: `BrowseSession`, `finalize` and the bounded JSON
//! encoder are re-exported by the parent module.
use std::sync::Arc;

use axum::{
    body::Body,
    http::{HeaderMap, header},
    response::Response,
};
use bytes::Bytes;
use serde::Serialize;

use super::super::{
    error::GatewayError,
    read_session,
    repo_session::{IssuedSession, SessionRealm},
    serving::lookup,
    session::{ReadAuthorization, authenticate, authority_error, read_authorization},
    snapshot::{self, ComputedView},
    state::{BlobGitState, ByteLease},
};
use super::memory_budget;
use crate::ref_store::{GitObjectFormat, core::pack_snapshot::MaterializedServingRead};

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
pub(crate) struct BrowseSession {
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
    tokens: Option<super::super::repo_session::SessionTokens>,
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
    pub(crate) async fn open(
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
    pub(crate) fn budget(&self) -> u64 {
        self.budget
    }

    pub(crate) fn format_name(&self) -> &'static str {
        self.format.as_str()
    }

    /// The sealed read this request's view was verified over, if the capture
    /// had anything to prove.
    pub(crate) fn materialized_read(&self) -> Option<&MaterializedServingRead> {
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
pub(crate) async fn finalize<T: Serialize>(session: BrowseSession, value: &T) -> Result<Response, GatewayError> {
    let state = &session.state;
    let limit = session.budget().min(state.limits().max_response_bytes);
    let bytes = encode_response(value, limit)?;
    let serving = session.authorization.revalidate_serving(session.deadline).await?;
    read_session::verify_capture_anchor(session.capture_incarnation, session.materialized_read(), &serving)?;
    let issued = match session_claim(&session)? {
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
    serving: &super::super::serving::ServingRepository,
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
pub(crate) fn encode_response(value: &impl Serialize, limit: u64) -> Result<Vec<u8>, GatewayError> {
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
    debug_assert!(buffer.bytes.len() <= limit);
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
}
