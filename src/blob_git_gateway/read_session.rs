//! Incoming repository session lower-bound enforcement for JSON read routes
//! (#174).
//!
//! This is the only gateway place a presented `x-rootyard-session` header is
//! scored. Every caller invokes it only after the request's current actor was
//! authenticated and the repository was authorized by the live serving lookup
//! ([`ServingRepository`]), which it must be handed. Nothing here is cached:
//! every request reads its own gate, binding, capture and cluster authority
//! incarnation.
//!
//! Ordering of one read request:
//!
//! 1. authenticate the actor and authorize the repository (`lookup`);
//! 2. inspect the header (duplicate/non-text refused; without a key set, only
//!    the presence of any occurrence is inspected, and it is a `501`);
//! 3. capture the ref view; its cluster authority incarnation must be the
//!    authorized lookup's own value or the refusal is a generic `503`. This
//!    anchor check is unconditional: it applies whether or not a key set is
//!    configured and whether or not the request presented a header, because it
//!    gates materialization, not the token verdict;
//! 4. only after that anchor check, and before any Blob/native materialization,
//!    score a presented header against the authorized realm (with the capture's
//!    incarnation) and the revision the capture actually locked through the
//!    single `SessionTokens::verify`/`compare` boundary. Without a key set there
//!    is nothing to verify and step 4 is skipped.
//!
//! Every refusal after capture releases the transient capture through the
//! bounded `snapshot::release_view` path before it is returned. A refusal never
//! invites dropping the bound: `Behind` stays a `503` with the same guidance,
//! a foreign/restored realm is a `409`, and a malformed header a `400`. This
//! checkpoint does not issue tokens.
use axum::http::HeaderMap;
use uuid::Uuid;

use super::{
    error::GatewayError,
    repo_session::{Presented, SESSION_HEADER, SessionRealm, SessionTokens, presented},
    serving::ServingRepository,
    snapshot::{self, RefView},
    state::BlobGitState,
};

/// Keyring absent: the gateway cannot judge any lower bound.
pub(super) const SESSIONS_DISABLED: &str = "repository session tokens are not configured on this gateway";

/// The single generic, retryable refusal for a restore rotation observed
/// between the lookup/token verdict and the capture. It names no incarnation.
pub(super) const AUTHORITY_CHANGED: &str =
    "repository authority changed after the read view was authorized; retry the same request";

/// Inspect the presented header after the authorized lookup and before any
/// capture or materialization. With a key set, duplicates/non-text values are
/// refused (the frame is scored later, against the captured revision); without
/// one, only the *presence* of any occurrence is inspected and any presented
/// header is the explicit `501`. The authorized `serving` argument is the
/// ordering guard: no header error can be produced before the lookup succeeded.
pub(super) fn admit(
    tokens: Option<&SessionTokens>,
    headers: &HeaderMap,
    serving: &ServingRepository,
) -> Result<(), GatewayError> {
    let Some(_) = tokens else {
        if headers.get_all(SESSION_HEADER).iter().next().is_some() {
            return Err(GatewayError::NotImplemented(SESSIONS_DISABLED));
        }
        return Ok(());
    };
    presented(headers).map_err(|error| error.for_repo())?;
    live_realm(serving, serving.cluster_incarnation).map(|_| ())
}

/// Capture the ref view and require it to belong to the cluster authority
/// incarnation the authorization was made under, then score the header against
/// the *captured* revision (never the lookup's). Any refusal releases the
/// capture through [`snapshot::release_view`] and never materializes.
pub(super) async fn capture(
    state: &BlobGitState,
    headers: &HeaderMap,
    serving: &ServingRepository,
    deadline: tokio::time::Instant,
) -> Result<RefView, GatewayError> {
    let view = snapshot::load_ref_view(state, serving, deadline).await?;
    if let Err(error) =
        answer(snapshot::capture_incarnation(&view), state.sessions(), headers, serving, view.gate_revision())
    {
        snapshot::release_view(state, &view, deadline).await;
        return Err(error);
    }
    Ok(view)
}

/// The pure verdict for one loaded capture. The capture's own cluster anchor is
/// checked first and unconditionally: a missing, nil or rotated anchor refuses
/// with [`AUTHORITY_CHANGED`] before the key set or the header is considered, so
/// a token-disabled or token-free read can never materialize a view captured in
/// another incarnation. Only after that anchor matches is a presented header
/// scored (when a key set exists) against the authorized realm bound to the
/// *captured* incarnation and the revision the capture actually locked.
fn answer(
    captured_incarnation: Option<Uuid>,
    tokens: Option<&SessionTokens>,
    headers: &HeaderMap,
    serving: &ServingRepository,
    captured_revision: i64,
) -> Result<(), GatewayError> {
    let captured = captured_incarnation
        .filter(|captured| !captured.is_nil() && *captured == serving.cluster_incarnation)
        .ok_or(GatewayError::Unavailable(AUTHORITY_CHANGED))?;
    let Some(tokens) = tokens else { return Ok(()) };
    let realm = live_realm(serving, captured)?;
    let header = presented(headers).map_err(|error| error.for_repo())?;
    tokens.verify(&header, &realm, captured_revision).map(|_| ()).map_err(|error| error.for_repo())
}

/// The full realm of an authorized serving lookup bound to the incarnation the
/// capture actually locked. Every field is re-checked by [`SessionRealm::new`],
/// so a nil/non-canonical live value is never compared.
fn live_realm(serving: &ServingRepository, captured: Uuid) -> Result<SessionRealm, GatewayError> {
    let gate = &serving.gate;
    SessionRealm::new(
        gate.tenant_id(),
        gate.repository_id(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
        captured,
    )
    .map_err(|error| error.for_repo())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_git_gateway::repo_session::{BEHIND_MESSAGE, SessionTokenCodec, TEST_MAX_TOKEN_LEN};
    use crate::ref_store::{GitObjectFormat, RefName};
    use axum::http::{HeaderName, HeaderValue};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    fn tokens() -> SessionTokens {
        let codec = SessionTokenCodec::new([(0u8, Zeroizing::new([9u8; 32]))], 0, &backend(), 120).expect("codec");
        SessionTokens::new(codec)
    }

    fn backend() -> crate::blob_store::BlobBackendIdentity {
        crate::blob_store::test_support::blob_backend_identity("read-session-tests")
    }

    /// `n` is the last uuid byte, so `Uuid::nil()` stays nil.
    fn id(n: u8) -> Uuid {
        let mut bytes = [0u8; 16];
        bytes[15] = n;
        Uuid::from_bytes(bytes)
    }

    /// A real core gate at `revision`; the fixture never touches PostgreSQL.
    fn serving(revision: i64, cluster: Uuid) -> ServingRepository {
        let gate = crate::ref_store::CoreGate::new(
            id(11),
            id(12),
            GitObjectFormat::Sha1,
            id(13),
            1,
            1,
            RefName::new("refs/heads/main").expect("ref"),
            revision,
        )
        .expect("gate");
        ServingRepository {
            repository: crate::db::Repository {
                id: id(11),
                name: "demo".into(),
                owner: "alice".into(),
                state: "ready".into(),
                clone_path: "/git/alice/demo.git".into(),
                storage_backend: "pg_refstore".into(),
                storage_generation: 1,
                object_format: "sha1".into(),
            },
            gate,
            cluster_incarnation: cluster,
        }
    }

    fn header(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_str(token).expect("header value"));
        headers
    }

    fn malformed() -> GatewayError {
        GatewayError::BadRequest("invalid repository session token")
    }

    #[test]
    fn absent_header_is_unchanged_with_and_without_a_keyring() {
        let live = serving(3, id(4));
        assert_eq!(answer(Some(id(4)), None, &HeaderMap::new(), &live, 3), Ok(()));
        assert_eq!(answer(Some(id(4)), Some(&tokens()), &HeaderMap::new(), &live, 3), Ok(()));
        assert_eq!(admit(None, &HeaderMap::new(), &live), Ok(()));
        assert_eq!(admit(Some(&tokens()), &HeaderMap::new(), &live), Ok(()));
    }

    #[test]
    fn a_disabled_gateway_answers_any_presented_header_with_501() {
        let live = serving(3, id(4));
        let disabled = Err(GatewayError::NotImplemented(SESSIONS_DISABLED));
        for value in ["rs1.anything.anything", "", "\u{e9}", "rs1.", &"x".repeat(TEST_MAX_TOKEN_LEN + 1)] {
            assert_eq!(admit(None, &header(value), &live), disabled, "{value:?}");
        }
        let mut duplicate = header("rs1.a.b");
        duplicate.append(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_static("rs1.a.b"));
        assert_eq!(admit(None, &duplicate, &live), disabled);
    }

    #[test]
    fn malformed_and_duplicate_headers_are_bad_requests() {
        for value in ["", "rs1.", "rs2.abc.def", &"x".repeat(TEST_MAX_TOKEN_LEN + 1)] {
            assert_eq!(presented(&header(value)).map_err(|error| error.for_repo()), Err(malformed()));
        }
        let mut duplicate = header("rs1.a.b");
        duplicate.append(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_static("rs1.a.b"));
        assert_eq!(presented(&duplicate).map_err(|error| error.for_repo()), Err(malformed()));
        // A nil capture/lookup incarnation is never compared.
        assert_eq!(live_realm(&serving(3, Uuid::nil()), id(4)), Err(malformed()));
    }

    #[test]
    fn the_bound_is_scored_against_the_captured_revision() {
        let tokens = tokens();
        let live = serving(9, id(4));
        let issued = tokens.issue_for_test(&live_realm(&live, id(4)).expect("realm"), 10).expect("issue");
        let presented = header(&issued.token());
        // The lookup saw gate 9 while the capture locked the committed 10.
        assert_eq!(answer(Some(id(4)), Some(&tokens), &presented, &live, 10), Ok(()));
        // The same bound-10 token against a capture at 9 is the existing Behind.
        assert_eq!(
            answer(Some(id(4)), Some(&tokens), &presented, &live, 9),
            Err(GatewayError::Unavailable(BEHIND_MESSAGE))
        );
        // No header remains token-free with a key set.
        assert_eq!(answer(Some(id(4)), Some(&tokens), &HeaderMap::new(), &live, 10), Ok(()));
    }

    #[test]
    fn the_capture_must_keep_the_authorized_cluster_incarnation() {
        let live = serving(5, id(4));
        // A restore rotation after issuance: the token's realm is the capture's,
        // not the rotated lookup's.
        let issued = tokens().issue_for_test(&live_realm(&live, id(4)).expect("realm"), 5).expect("issue");
        let foreign = live_realm(&live, id(8)).expect("realm");
        assert_eq!(
            tokens().verify(&Presented::Token(issued.token()), &foreign, 5).map_err(|error| error.for_repo()),
            Err(GatewayError::Conflict(
                "repository session belongs to another repository, history or authority generation; re-read the authoritative store and obtain a fresh session there"
            ))
        );
        assert_eq!(GatewayError::Unavailable(AUTHORITY_CHANGED).status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The capture anchor is checked before the key set and before the header:
    /// a missing, nil or rotated anchor is refused with the generic retryable
    /// `AUTHORITY_CHANGED`, whether session tokens are disabled or enabled and
    /// whether or not a header was presented.
    #[test]
    fn the_capture_anchor_is_checked_before_the_key_set_or_the_header() {
        let live = serving(5, id(4));
        let rotated = GatewayError::Unavailable(AUTHORITY_CHANGED);
        let tokens = tokens();
        for captured in [None, Some(id(8)), Some(Uuid::nil())] {
            // Tokens disabled and no header: the anchor still gates materialization.
            assert_eq!(answer(captured, None, &HeaderMap::new(), &live, 5), Err(rotated.clone()), "{captured:?}");
            // Tokens enabled and no header: the same refusal, not a token verdict.
            assert_eq!(
                answer(captured, Some(&tokens), &HeaderMap::new(), &live, 5),
                Err(rotated.clone()),
                "{captured:?}"
            );
        }
        // A matching anchor is admitted token-free, with or without a key set.
        assert_eq!(answer(Some(id(4)), None, &HeaderMap::new(), &live, 5), Ok(()));
        assert_eq!(answer(Some(id(4)), Some(&tokens), &HeaderMap::new(), &live, 5), Ok(()));
    }

    /// A keyring-present realm rotation still fails after the anchor matched:
    /// the presented token belongs to another authority generation.
    #[test]
    fn a_keyring_present_realm_rotation_is_refused() {
        let rotated = serving(5, id(4));
        let foreign = live_realm(&serving(5, id(8)), id(8)).expect("realm");
        let issued = tokens().issue_for_test(&foreign, 5).expect("issue");
        assert_eq!(
            answer(Some(id(4)), Some(&tokens()), &header(&issued.token()), &rotated, 5),
            Err(GatewayError::Conflict(
                "repository session belongs to another repository, history or authority generation; re-read the authoritative store and obtain a fresh session there"
            ))
        );
    }

    /// The header is scored only after the anchor matched, against the captured
    /// revision and never the lookup's; a malformed frame is a `400`.
    #[test]
    fn an_unrotated_capture_is_scored_after_its_anchor() {
        let tokens = tokens();
        let live = serving(9, id(4));
        let issued = tokens.issue_for_test(&live_realm(&live, id(4)).expect("realm"), 5).expect("issue");
        let presented = header(&issued.token());
        assert_eq!(answer(Some(id(4)), Some(&tokens), &presented, &live, 5), Ok(()));
        assert_eq!(
            answer(Some(id(8)), Some(&tokens), &presented, &live, 5),
            Err(GatewayError::Unavailable(AUTHORITY_CHANGED))
        );
        assert_eq!(
            answer(Some(id(4)), Some(&tokens), &header("rs1.anything.anything"), &live, 5),
            Err(malformed())
        );
    }
}
