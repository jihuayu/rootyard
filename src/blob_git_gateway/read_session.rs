//! Incoming repository session lower-bound enforcement for JSON read routes
//! (#174).
//!
//! This is the only gateway place a presented `x-rootyard-session` header is
//! scored. Every caller invokes it only after the request's current actor was
//! authenticated and the repository was authorized by the live serving lookup
//! ([`ServingRepository`]), which it must be handed. Nothing here is cached:
//! every request reads its own gate, binding and cluster authority
//! incarnation.
//!
//! Ordering of one read request:
//!
//! 1. authenticate the actor and authorize the repository ([`lookup`]);
//! 2. parse the header (duplicate/non-text refused; no frame validity check);
//! 3. build the full live [`SessionRealm`] from the authorized gate and this
//!    lookup's cluster incarnation, then score with the gate revision through
//!    the single `SessionTokens::verify`/`compare` boundary;
//! 4. capture the ref view and require the capture's own cluster incarnation to
//!    be the lookup's before any materialization ([`capture`]).
//!
//! A refusal never invites dropping the bound: `Behind` stays a `503` with the
//! same guidance, a foreign/restored realm is a `409`, and a malformed header a
//! `400`. Without a configured key set a token-free request is unchanged, while
//! a presented header is an explicit `501` — still only after authorization.
//! This checkpoint does not issue tokens.
use axum::http::HeaderMap;
use uuid::Uuid;

use super::{
    error::GatewayError,
    repo_session::{Presented, SessionRealm, SessionTokens, presented},
    serving::ServingRepository,
    snapshot::{self, RefView},
    state::BlobGitState,
};

/// Keyring absent: the gateway cannot judge any lower bound.
pub(super) const SESSIONS_DISABLED: &str = "repository session tokens are not configured on this gateway";

/// What one token-free or verified request may let through to the capture.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ReadSession {
    /// No session key set is configured and the request presented no header.
    pub(super) keyring_absent: bool,
}

/// Parse and score the presented header against the live realm and gate
/// revision of this very lookup. The authorized `serving` argument is the
/// ordering guard: no header error can be produced before the lookup succeeded.
pub(super) fn admit(
    tokens: Option<&SessionTokens>,
    headers: &HeaderMap,
    serving: &ServingRepository,
) -> Result<ReadSession, GatewayError> {
    let Some(tokens) = tokens else {
        return match presented(headers) {
            Ok(Presented::None) => Ok(ReadSession { keyring_absent: true }),
            Ok(Presented::Token(_)) => Err(GatewayError::NotImplemented(SESSIONS_DISABLED)),
            Err(error) => Err(error.for_repo()),
        };
    };
    let presented = presented(headers).map_err(|error| error.for_repo())?;
    let live = live_realm(serving)?;
    match tokens.verify(&presented, &live, serving.gate.revision()) {
        Ok(Some(_satisfied)) | Ok(None) => Ok(ReadSession { keyring_absent: false }),
        Err(error) => Err(error.for_repo()),
    }
}

/// The single generic, retryable refusal for a restore rotation observed
/// between the lookup/token verdict and the capture. It names no incarnation.
pub(super) const AUTHORITY_CHANGED: &str =
    "repository authority changed after the read view was authorized; retry the same request";

/// Capture the ref view and require it to belong to the cluster authority
/// incarnation the authorization/token verdict was made under.
///
/// A mismatched capture is released through the existing bounded cleanup path
/// ([`snapshot::release_view`]) and never materialized.
pub(super) async fn capture(
    state: &BlobGitState,
    serving: &ServingRepository,
    deadline: tokio::time::Instant,
) -> Result<RefView, GatewayError> {
    let view = snapshot::load_ref_view(state, serving, deadline).await?;
    if snapshot::capture_incarnation(&view) != serving.cluster_incarnation {
        snapshot::release_view(state, &view, deadline).await;
        return Err(GatewayError::Unavailable(AUTHORITY_CHANGED));
    }
    Ok(view)
}

/// The full realm of an authorized serving lookup, including this lookup's
/// cluster authority incarnation. Every field is re-checked by
/// [`SessionRealm::new`], so a nil/non-canonical live value is never compared.
fn live_realm(serving: &ServingRepository) -> Result<SessionRealm, GatewayError> {
    let gate = &serving.gate;
    SessionRealm::new(
        gate.tenant_id(),
        gate.repository_id(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
        serving.cluster_incarnation,
    )
    .map_err(|error| error.for_repo())
}

/// Compare a capture's anchor with the lookup the token verdict used.
pub(super) fn same_incarnation(lookup: Uuid, captured: Uuid) -> bool {
    lookup == captured
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_git_gateway::repo_session::{BEHIND_MESSAGE, SESSION_HEADER, SessionTokenCodec};
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
        assert!(!admit(Some(&tokens()), &HeaderMap::new(), &live).expect("authorized").keyring_absent);
        let no_keyring = admit(None, &HeaderMap::new(), &live).expect("a token-free request is unchanged");
        assert!(no_keyring.keyring_absent);
    }

    #[test]
    fn a_disabled_gateway_answers_only_a_presented_header_with_501() {
        let live = serving(3, id(4));
        assert_eq!(
            admit(None, &header("rs1.anything.anything"), &live),
            Err(GatewayError::NotImplemented(SESSIONS_DISABLED))
        );
    }

    #[test]
    fn malformed_and_duplicate_headers_are_bad_requests() {
        let live = serving(3, id(4));
        for value in ["", "rs1.", "rs2.abc.def", &"x".repeat(400)] {
            assert_eq!(admit(Some(&tokens()), &header(value), &live), Err(malformed()));
        }
        let mut duplicate = header("rs1.a.b");
        duplicate.append(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_static("rs1.a.b"));
        assert_eq!(admit(Some(&tokens()), &duplicate, &live), Err(malformed()));
        // The realm itself is re-validated by the same constructor the codec
        // uses: a nil live incarnation is never compared.
        let nil = serving(3, Uuid::nil());
        assert_eq!(live_realm(&nil), Err(malformed()));
        assert_eq!(admit(Some(&tokens()), &header("rs1.a.b"), &nil), Err(malformed()));
    }

    #[test]
    fn satisfied_behind_and_restored_realms_are_scored_by_the_shared_entry() {
        let cluster = id(4);
        let live = serving(5, cluster);
        let realm = live_realm(&live).expect("realm");
        let issued = tokens().issue_for_test(&realm, 5).expect("issue");
        let presented = header(issued.token());
        // Satisfied: the live gate is exactly the bound.
        assert!(admit(Some(&tokens()), &presented, &live).is_ok());
        // Behind: same realm, older live gate; the bound and its guidance stay.
        assert_eq!(
            admit(Some(&tokens()), &presented, &serving(4, cluster)),
            Err(GatewayError::Unavailable(BEHIND_MESSAGE))
        );
        // Restore rotation: only the cluster authority incarnation differs.
        assert_eq!(
            admit(Some(&tokens()), &presented, &serving(5, id(8))),
            Err(GatewayError::Conflict(
                "repository session belongs to another repository, history or authority generation; re-read the authoritative store and obtain a fresh session there"
            ))
        );
    }

    #[test]
    fn the_capture_must_keep_the_authorized_cluster_incarnation() {
        let live = serving(5, id(4));
        let captured = id(8);
        assert!(same_incarnation(live.cluster_incarnation, id(4)));
        assert!(!same_incarnation(live.cluster_incarnation, captured));
        assert_eq!(GatewayError::Unavailable(AUTHORITY_CHANGED).status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
}
