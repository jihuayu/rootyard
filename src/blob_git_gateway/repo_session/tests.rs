//! Unit tests for the repository session token core (#174).
//!
//! Only synthetic fixtures live here: fill-byte keys, uuid::from_bytes realms
//! and two real `cfg(test)` in-memory Blob identities. No user key material.
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    BEHIND_MESSAGE, MAX_LIFETIME_SECONDS, MIN_LIFETIME_SECONDS, REVISION_HEADER, SESSION_HEADER, SessionRealm,
    SessionTokenCodec, SessionTokenError, SessionTokens, TEST_MAX_TOKEN_LEN, VersionComparison,
    codec::{BODY_LEN, FORMAT_BYTE, PREFIX, Presented, TRAILER, now_seconds, presented},
    compare, presented_for_test,
};
use crate::{blob_store::BlobBackendIdentity, ref_store::GitObjectFormat};

/// Two genuinely distinct, real `cfg(test)` memory-store identities. The
/// codec stores only their digest, never a profile or credential.
fn backends() -> (BlobBackendIdentity, BlobBackendIdentity) {
    crate::blob_store::test_support::distinct_backend_identities()
}

/// One stable synthetic identity for the codecs that only need "some
/// backend". The MAC covers the backend digest, so issuing and verifying a
/// token must always use the same identity; a fresh randomized in-memory
/// identity per call would differ on every call.
fn backend() -> BlobBackendIdentity {
    crate::blob_store::test_support::blob_backend_identity("repo-session-tests")
}

fn codec_with(keys: &[(u8, [u8; 32])], current: u8, backend: &BlobBackendIdentity) -> SessionTokenCodec {
    SessionTokenCodec::new(keys.iter().copied().map(|(id, bytes)| (id, zeroizing(bytes))), current, backend, 120)
        .expect("codec")
}

/// Same construction as the keyring loader: key material enters the codec as
/// a `Zeroizing` owner, never as a bare array it has to remember to wipe.
fn zeroizing(bytes: [u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(bytes)
}

fn codec(keys: &[(u8, [u8; 32])], current: u8) -> SessionTokenCodec {
    codec_with(keys, current, &backend())
}

fn header(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_str(token).expect("header value"));
    headers
}

fn key(fill: u8) -> [u8; 32] {
    [fill; 32]
}

fn realm(seed: u8) -> SessionRealm {
    SessionRealm::new(
        Uuid::from_bytes([seed; 16]),
        Uuid::from_bytes([seed.wrapping_add(10); 16]),
        GitObjectFormat::Sha1,
        Uuid::from_bytes([seed.wrapping_add(20); 16]),
        1,
        1,
        Uuid::from_bytes([seed.wrapping_add(30); 16]),
    )
    .expect("realm")
}

#[test]
fn round_trip_binds_the_full_realm_at_the_served_gate_revision() {
    let codec = codec(&[(3, key(7))], 3);
    let live = realm(1);
    let issued = codec.issue(&live, 9, 1_000).expect("issue");
    assert!(issued.token().len() <= TEST_MAX_TOKEN_LEN, "token must stay inside its fixed ceiling");
    let comparison = codec.verify(issued.token(), 1_010, &live, 9).expect("verify");
    assert_eq!(comparison, VersionComparison::Satisfied { bound: 9 });
    let session = codec.authenticate_for_test(issued.token(), 1_010).expect("mac");
    assert_eq!(session.realm(), &live);
    assert_eq!(session.bound(), 9);
}

#[test]
fn a_bound_is_scored_against_gate_revisions_only() {
    let codec = codec(&[(0, key(1))], 0);
    let live = realm(2);
    let issued = codec.issue(&live, 10, 1_000).expect("issue");
    let session = codec.authenticate_for_test(issued.token(), 1_001).expect("mac");
    // The scoring helper takes the live revision explicitly: a bound of 10
    // with a live gate of 9 is Behind, never Satisfied. This used to be a
    // revision-blind comparison that always said Satisfied.
    assert_eq!(compare(&session, &live, 9), Ok(VersionComparison::Behind { live_revision: 9 }));
    assert_eq!(compare(&session, &live, 10), Ok(VersionComparison::Satisfied { bound: 10 }));
    assert_eq!(compare(&session, &live, 12), Ok(VersionComparison::Satisfied { bound: 10 }));
    // The gateway verify path delegates to the same scoring.
    assert_eq!(codec.verify(issued.token(), 1_001, &live, 9), Ok(VersionComparison::Behind { live_revision: 9 }));
    assert_eq!(codec.verify(issued.token(), 1_001, &live, 10), Ok(VersionComparison::Satisfied { bound: 10 }));
    assert_eq!(codec.verify(issued.token(), 1_001, &live, 12), Ok(VersionComparison::Satisfied { bound: 10 }));
    assert_eq!(SessionTokenError::Behind.for_repo().status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn behind_is_reported_at_the_same_revision_and_never_scores_a_foreign_realm() {
    let codec = codec(&[(0, key(1))], 0);
    let live = realm(3);
    let issued = codec.issue(&live, 10, 1_000).expect("issue");
    let session = codec.authenticate_for_test(issued.token(), 1_001).expect("mac");
    // The refusal carries exactly the live revision it was given; it is not a
    // storage generation or any other counter.
    for live_revision in [1, 9, 0, -5] {
        assert_eq!(compare(&session, &live, live_revision), Ok(VersionComparison::Behind { live_revision }));
    }
    // Behind is only reachable for the identical realm.
    let other = SessionRealm { repository_id: Uuid::from_bytes([77; 16]), ..live };
    assert_eq!(compare(&session, &other, 1), Err(SessionTokenError::Realm));
}

#[test]
fn every_realm_field_mismatch_is_refused_never_compared() {
    let codec = codec(&[(0, key(1))], 0);
    let live = realm(4);
    let issued = codec.issue(&live, 5, 1_000).expect("issue");
    let variants = [
        SessionRealm { tenant_id: Uuid::from_bytes([99; 16]), ..live },
        SessionRealm { repository_id: Uuid::from_bytes([99; 16]), ..live },
        SessionRealm { history_incarnation: Uuid::from_bytes([99; 16]), ..live },
        SessionRealm { authority_epoch: 2, ..live },
        SessionRealm { group_epoch: 2, ..live },
        SessionRealm { object_format: GitObjectFormat::Sha256, ..live },
        // A restore rotates only the cluster authority incarnation.
        SessionRealm { cluster_incarnation: Uuid::from_bytes([98; 16]), ..live },
    ];
    for variant in variants {
        // A different realm is refused at every live gate revision: a
        // revision from another realm never scores as older or newer.
        for revision in [1, 5, 50] {
            assert_eq!(
                codec.verify(issued.token(), 1_001, &variant, revision),
                Err(SessionTokenError::Realm),
                "{variant:?} @ {revision}"
            );
        }
    }
}

#[test]
fn expiry_is_judged_inside_the_signed_frame() {
    let codec = codec(&[(0, key(1))], 0);
    let live = realm(5);
    let issued = codec.issue(&live, 2, 100_000).expect("issue");
    assert!(codec.authenticate_for_test(issued.token(), 100_119).is_ok());
    assert_eq!(codec.authenticate_for_test(issued.token(), 100_120), Err(SessionTokenError::Expired));
    assert_eq!(
        codec.authenticate_for_test(issued.token(), 99_999),
        Err(SessionTokenError::Expired),
        "clock before issue"
    );

    // A correctly signed frame cannot extend the bound beyond the ceiling.
    let mut frame = [0u8; BODY_LEN];
    frame[0] = FORMAT_BYTE;
    frame[2] = 0;
    frame[3..7].copy_from_slice(&(MAX_LIFETIME_SECONDS + 1).to_be_bytes());
    frame[7..15].copy_from_slice(&2i64.to_be_bytes());
    frame[15..31].copy_from_slice(live.tenant_id.as_bytes());
    frame[31..47].copy_from_slice(live.repository_id.as_bytes());
    frame[47] = 1;
    frame[49..65].copy_from_slice(live.history_incarnation.as_bytes());
    frame[65..73].copy_from_slice(&1i64.to_be_bytes());
    frame[73..81].copy_from_slice(&1i64.to_be_bytes());
    frame[81..97].copy_from_slice(live.cluster_incarnation.as_bytes());
    frame[97..101].copy_from_slice(&100_000u32.to_be_bytes());
    frame[101..111].copy_from_slice(TRAILER);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key(1));
    let tag = hmac::sign(&key, &codec.message(0, &frame));
    let overlong = format!("{PREFIX}{}.{}", URL_SAFE_NO_PAD.encode(frame), URL_SAFE_NO_PAD.encode(tag.as_ref()));
    assert_eq!(codec.authenticate_for_test(&overlong, 100_001), Err(SessionTokenError::Invalid));
}

#[test]
fn rotated_deleted_and_forged_tokens_fail_closed() {
    let backend = backend();
    let codec = codec_with(&[(0, key(1))], 0, &backend);
    let live = realm(6);
    let issued = codec.issue(&live, 2, 1_000).expect("issue");
    // Rotation: a key set without the signer refuses its tokens.
    let rotated = codec_with(&[(1, key(2))], 1, &backend);
    assert_eq!(rotated.authenticate_for_test(issued.token(), 1_001), Err(SessionTokenError::Invalid));
    // Overlap: old key configured but not current verifies until retired.
    let transition = codec_with(&[(0, key(1)), (1, key(2))], 1, &backend);
    assert!(transition.authenticate_for_test(issued.token(), 1_001).is_ok());
    // New tokens are signed by the current key id.
    let body = URL_SAFE_NO_PAD
        .decode(transition.issue(&live, 2, 1_001).expect("issue").token().split('.').nth(1).expect("body"))
        .expect("b64");
    assert_eq!(body[2], 1, "new tokens use the current key");
    // The key id byte redirects which secret verifies; it cannot forge.
    let mut bytes = issued.token().as_bytes().to_vec();
    let id_offset = PREFIX.len() + 2;
    bytes[id_offset] = b'B';
    let forged = std::str::from_utf8(&bytes).expect("ascii");
    assert_eq!(codec.authenticate_for_test(forged, 1_001), Err(SessionTokenError::Invalid));
    assert_eq!(transition.authenticate_for_test(forged, 1_001), Err(SessionTokenError::Invalid));

    // Corruption anywhere in frame or MAC is refused.
    for index in [0, 4, 10, 40, 80, 120, bytes.len() - 5, bytes.len() - 1] {
        let mut corrupt = issued.token().as_bytes().to_vec();
        corrupt[index] = if corrupt[index] == b'A' { b'B' } else { b'A' };
        let text = std::str::from_utf8(&corrupt).expect("ascii");
        if text != issued.token() {
            assert_eq!(codec.authenticate_for_test(text, 1_001), Err(SessionTokenError::Invalid), "byte {index}");
        }
    }
}

#[test]
fn malformed_and_oversized_tokens_are_invalid_without_specifics() {
    let codec = codec(&[(0, key(1))], 0);
    let live = realm(7);
    let good = codec.issue(&live, 1, 1_000).expect("issue");
    let cases = [
        String::new(),
        "rs1.".to_owned(),
        "rs2.abc.def".to_owned(),
        "x".repeat(TEST_MAX_TOKEN_LEN + 1),
        format!("{}=", good.token()),
        good.token().replace('.', ""),
        format!("{}é", &good.token()[..TEST_MAX_TOKEN_LEN - 1]),
        good.token()[..good.token().len() - 1].to_owned(),
    ];
    for case in cases {
        assert_eq!(codec.authenticate_for_test(&case, 1_001), Err(SessionTokenError::Invalid), "{case:?}");
    }
}

#[test]
fn a_codec_is_bound_to_the_backend_its_gateway_opened() {
    let keys = [(0u8, key(1))];
    let (first, second) = backends();
    let left = codec_with(&keys, 0, &first);
    let right = codec_with(&keys, 0, &second);
    let live = realm(8);
    let issued = left.issue(&live, 1, 1_000).expect("issue");
    assert!(left.verify(issued.token(), 1_001, &live, 1).is_ok());
    assert_eq!(right.authenticate_for_test(issued.token(), 1_001), Err(SessionTokenError::Invalid));
}

#[test]
fn key_and_lifetime_configuration_is_validated() {
    let (target, _) = backends();
    let live = realm(9);
    let cases = [
        (SessionTokenCodec::new([(0u8, zeroizing(key(1)))], 1, &target, 120), "current key must exist"),
        (SessionTokenCodec::new([(0u8, zeroizing(key(1))), (0, zeroizing(key(2)))], 0, &target, 120), "duplicate ids"),
        (SessionTokenCodec::new([(0u8, zeroizing(key(1)))], 0, &target, MAX_LIFETIME_SECONDS + 1), "too long"),
        (SessionTokenCodec::new([(0u8, zeroizing(key(1)))], 0, &target, MIN_LIFETIME_SECONDS - 1), "too short"),
    ];
    for (result, reason) in cases {
        assert!(result.is_err(), "{reason}");
    }
    let codec = SessionTokenCodec::new([(0u8, zeroizing(key(1)))], 0, &target, 120).expect("codec");
    assert!(codec.issue(&live, 0, 1_000).is_err(), "revision below one is refused");
    assert_eq!(codec.verify("anything", 1_000, &live, 1), Err(SessionTokenError::Invalid));
    let nil_tenant = SessionRealm::new(
        Uuid::nil(),
        live.repository_id,
        GitObjectFormat::Sha1,
        live.history_incarnation,
        1,
        1,
        live.cluster_incarnation,
    );
    assert_eq!(nil_tenant, Err(SessionTokenError::Invalid));
    let nil_cluster = SessionRealm::new(
        live.tenant_id,
        live.repository_id,
        GitObjectFormat::Sha1,
        live.history_incarnation,
        1,
        1,
        Uuid::nil(),
    );
    assert_eq!(nil_cluster, Err(SessionTokenError::Invalid));
    let zero_epoch = SessionRealm::new(
        live.tenant_id,
        live.repository_id,
        GitObjectFormat::Sha1,
        live.history_incarnation,
        0,
        1,
        live.cluster_incarnation,
    );
    assert_eq!(zero_epoch, Err(SessionTokenError::Invalid));
}

#[test]
fn only_the_header_carries_a_token() {
    let mut headers = HeaderMap::new();
    assert!(matches!(presented(&headers), Ok(Presented::None)));
    headers.insert(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_static("rs1.body.mac"));
    assert!(matches!(presented(&headers), Ok(Presented::Token("rs1.body.mac"))));
    headers.append(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_static("rs1.body.mac"));
    assert!(matches!(presented(&headers), Err(SessionTokenError::Invalid)));
    // A token value is never percent-decoded: the alphabet is literal.
    headers.clear();
    headers.insert(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_static("rs1.a%2Bb.c"));
    let codec = codec(&[(0, key(1))], 0);
    assert_eq!(codec.authenticate_for_test("rs1.a%2Bb.c", 1_000), Err(SessionTokenError::Invalid));
}

#[test]
fn errors_and_debug_output_never_render_token_material() {
    let live = realm(10);
    let issued = codec_with(&[(0, key(1))], 0, &backends().0).issue(&live, 1, 1_000).expect("issue");
    let text = format!("{issued:?} {:?}", SessionTokens::new(codec(&[(0, key(1))], 0)));
    let token = issued.token();
    assert!(!text.contains(token));
    assert!(!text.contains(&token[PREFIX.len()..PREFIX.len() + 8]));
    assert!(!text.contains(&hex::encode(key(1))));
    for error in [SessionTokenError::Invalid, SessionTokenError::Expired, SessionTokenError::Realm] {
        let message = error.for_repo().message();
        assert!(!message.contains(token), "{message}");
    }
    assert_eq!(error_status(SessionTokenError::Invalid).as_u16(), 400);
    assert_eq!(error_status(SessionTokenError::Expired).as_u16(), 503);
    assert_eq!(error_status(SessionTokenError::Realm).as_u16(), 409);
}

fn error_status(error: SessionTokenError) -> axum::http::StatusCode {
    use axum::response::IntoResponse;
    error.for_repo().into_response().status()
}

#[test]
fn refusals_never_suggest_dropping_the_bound() {
    // Behind/expired/realm must keep the client on the authoritative path at
    // the same lower bound; none may invite an unbounded read, a stale read,
    // or "starting over" (which would silently reset the client's bound).
    assert_eq!(SessionTokenError::Behind.for_repo().message(), BEHIND_MESSAGE, "the served text is the tested text");
    assert_eq!(
        BEHIND_MESSAGE,
        "repository session lower bound is not yet served by the authoritative store; wait for the authoritative store to reach that bound and retry against the same bound, keeping read-your-writes and monotonic reads (do not fall back to a stale, replica or cache read)"
    );
    let behind = BEHIND_MESSAGE.to_ascii_lowercase();
    assert!(behind.contains("same bound"), "{behind}");
    assert!(behind.contains("read-your-writes") && behind.contains("monotonic"), "{behind}");
    for error in [SessionTokenError::Expired, SessionTokenError::Realm, SessionTokenError::Behind] {
        let message = error.for_repo().message().to_ascii_lowercase();
        for banned in [
            "without a bound",
            "without a stale bound",
            "unbounded",
            "without waiting",
            "ignore",
            "start over",
            "starting over",
            "fresh authoritative read",
            "reset",
        ] {
            assert!(!message.contains(banned), "{error:?}: {message}");
        }
        assert!(message.contains("authoritative"), "{error:?}: {message}");
    }
}

#[test]
fn the_gateway_entry_and_compare_agree_without_global_state() {
    let tokens = SessionTokens::new(codec(&[(0, key(1))], 0));
    let live = realm(11);
    // Two independent requests issuing at the same served revision produce
    // the same bound: the gateway holds no cross-request write flag.
    assert_eq!(tokens.issue_for_test(&live, 3).expect("a").revision(), 3);
    let second = tokens.issue_for_test(&live, 3).expect("b");
    assert_eq!(second.revision(), 3);
    assert!(now_seconds() > 1_000_000_000);
    let headers = header(second.token());
    let token = presented_for_test(&headers).expect("presented");
    let comparison = tokens.verify(&token, &live, 3).expect("verify");
    assert_eq!(comparison, Some(VersionComparison::Satisfied { bound: 3 }));
    // The same entry point reports Behind for a lagging authoritative read.
    let behind = tokens.verify(&token, &live, 2).expect("verify");
    assert_eq!(behind, Some(VersionComparison::Behind { live_revision: 2 }));
    let absent = HeaderMap::new();
    let none = presented_for_test(&absent).expect("presented");
    assert_eq!(tokens.verify(&none, &live, 2).expect("none"), None);
    let mut response = axum::response::Response::new(axum::body::Body::empty());
    second.apply(&mut response);
    assert!(response.headers().contains_key(REVISION_HEADER));
    // The non-secret descriptor says exactly the revision and lifetime the
    // token was really issued with, and never carries the token itself.
    let descriptor = second.descriptor();
    assert_eq!(descriptor.revision, 3);
    assert_eq!(descriptor.lifetime_seconds, tokens.lifetime_seconds());
    assert_eq!(descriptor.repository_id, live.repository_id);
    let json = serde_json::to_string(&descriptor).expect("descriptor json");
    assert!(!json.contains(second.token()), "{json}");
}

/// Synthetic committed-write proof fixtures: no PostgreSQL, no IO. Real core
/// gates and repository rows are assembled in memory from fixed ids.
mod committed_write {
    use super::{
        CommittedWriteSessionProof, SessionRealm, SessionTokenError, SessionTokens, VersionComparison, codec, header,
        key, presented_for_test,
    };
    use crate::{
        db::Repository,
        ref_store::{
            CommitRejectCode, CoreGate, GitObjectFormat, RefCommitResult, RefName, ServingRepository,
            core::pack_commit::{PackCommitTerminal, PackMode},
        },
    };
    use uuid::Uuid;

    fn id(n: u8) -> Uuid {
        let mut bytes = [0u8; 16];
        bytes[15] = n;
        Uuid::from_bytes(bytes)
    }

    /// `revision` is the live gate; ids and cluster incarnation are fixed per
    /// `realm` selector, and the row/gate repository id may be overridden.
    fn serving(realm: u8, revision: i64, cluster: u8, gate_repository: u8, row_repository: u8) -> ServingRepository {
        let gate = CoreGate::new(
            id(gate_repository),
            id(11 + realm),
            GitObjectFormat::Sha1,
            id(13 + realm),
            1 + i64::from(realm),
            1 + i64::from(realm),
            RefName::new("refs/heads/main").expect("ref"),
            revision,
        )
        .expect("gate");
        ServingRepository {
            repository: Repository {
                id: id(row_repository),
                name: "demo".into(),
                owner: "alice".into(),
                state: "ready".into(),
                clone_path: "/git/alice/demo.git".into(),
                storage_backend: "pg_refstore".into(),
                storage_generation: 1,
                object_format: "sha1".into(),
            },
            gate,
            cluster_incarnation: id(cluster),
        }
    }

    fn committed(repository: u8, revision: i64) -> PackCommitTerminal {
        PackCommitTerminal::committed(
            id(repository),
            revision,
            "refs/heads/main".into(),
            PackMode::MetadataOnly,
            vec![RefCommitResult::Applied {
                name: "refs/heads/main".into(),
                old_oid: None,
                new_oid: Some("a".repeat(40)),
            }],
            Vec::new(),
        )
    }

    fn rejected(repository: u8, revision: i64) -> PackCommitTerminal {
        PackCommitTerminal::rejected(
            id(repository),
            revision,
            Some("refs/heads/main".into()),
            PackMode::MetadataOnly,
            vec![RefCommitResult::NotApplied {
                name: "refs/heads/main".into(),
                reason: CommitRejectCode::OldOidMismatch,
            }],
            crate::ref_store::core::pack_commit::PackCommitRejection::new(
                crate::ref_store::core::pack_commit::PackCommitRejectCode::ClosureMismatch,
                "closure",
            ),
        )
    }

    fn admit(
        terminal: &PackCommitTerminal,
        first: &ServingRepository,
        last: &ServingRepository,
    ) -> Result<CommittedWriteSessionProof, SessionTokenError> {
        CommittedWriteSessionProof::new(terminal, first, last)
    }

    /// The exact durable terminal revision is signed and survives the exact/later
    /// live-revision cases unchanged.
    #[test]
    fn committed_terminals_are_admitted_at_their_exact_revision() {
        let tokens = SessionTokens::new(codec(&[(0, key(3))], 0));
        let first = serving(0, 4, 40, 20, 20);
        let terminal = committed(20, 5);
        // The final lookup must be exactly at the terminal's gate revision: a
        // final gate behind it cannot admit the terminal, even though the
        // initial (authorizing) lookup at revision 4 is fine.
        assert_eq!(admit(&terminal, &first, &first).err(), Some(SessionTokenError::Invalid));
        let exact = serving(0, 5, 40, 20, 20);
        let proof = admit(&terminal, &first, &exact).expect("exact");
        assert_eq!(proof.revision, 5);
        let issued = tokens.issue_from_committed_write(&proof).expect("issue");
        assert_eq!(issued.revision(), 5);
        let live = SessionRealm::of_serving(&exact).expect("realm");
        let presented = header(issued.token());
        let presented: Presented<'_> = presented_for_test(&presented).expect("presented");
        assert_eq!(tokens.verify(&presented, &live, 5), Ok(Some(VersionComparison::Satisfied { bound: 5 })));

        // A concurrent higher revision in the same realm is acceptable, but the
        // bound stays the durable terminal revision, never the live one.
        let later = serving(0, 9, 40, 20, 20);
        let proof = admit(&terminal, &first, &later).expect("later");
        assert_eq!(proof.revision, 5);
        let issued = tokens.issue_from_committed_write(&proof).expect("issue");
        assert_eq!(issued.revision(), 5);
        let presented = header(issued.token());
        let presented: Presented<'_> = presented_for_test(&presented).expect("presented");
        let live = SessionRealm::of_serving(&later).expect("realm");
        assert_eq!(tokens.verify(&presented, &live, 9), Ok(Some(VersionComparison::Satisfied { bound: 5 })));
    }

    #[test]
    fn noncommitted_terminals_are_never_admitted() {
        let first = serving(0, 4, 40, 20, 20);
        let terminal = rejected(20, 5);
        assert!(!terminal.is_committed());
        assert_eq!(admit(&terminal, &first, &first).err(), Some(SessionTokenError::Invalid));
    }

    #[test]
    fn the_terminal_repository_must_match_both_lookups() {
        let first = serving(0, 4, 40, 20, 20);
        let terminal = committed(20, 5);
        // Terminal names another repository than either lookup.
        assert_eq!(admit(&committed(21, 5), &first, &first).err(), Some(SessionTokenError::Realm));
        // A first lookup whose row names another repository.
        assert_eq!(admit(&terminal, &serving(0, 4, 40, 20, 22), &first).err(), Some(SessionTokenError::Realm));
        // A first lookup whose gate names another repository.
        assert_eq!(admit(&terminal, &serving(0, 4, 40, 22, 20), &first).err(), Some(SessionTokenError::Realm));
        // A final lookup whose row names another repository.
        assert_eq!(admit(&terminal, &first, &serving(0, 4, 40, 20, 22)).err(), Some(SessionTokenError::Realm));
        // A final lookup whose gate names another repository.
        assert_eq!(admit(&terminal, &first, &serving(0, 4, 40, 22, 20)).err(), Some(SessionTokenError::Realm));
    }

    #[test]
    fn any_realm_divergence_between_the_two_lookups_is_refused() {
        let first = serving(0, 4, 40, 20, 20);
        let terminal = committed(20, 5);
        // A restore between authorization and the final lookup rotates the
        // cluster authority incarnation even though the RefStore realm is the
        // same; the old terminal must not be relabeled into the new incarnation.
        assert_eq!(admit(&terminal, &first, &serving(0, 9, 41, 20, 20)).err(), Some(SessionTokenError::Realm));
        // Tenant/history/epochs divergence: same ids, another realm selector.
        assert_eq!(admit(&terminal, &first, &serving(1, 9, 40, 20, 20)).err(), Some(SessionTokenError::Realm));
        // A nil cluster incarnation never forms a realm.
        assert_eq!(admit(&terminal, &first, &serving(0, 9, 0, 20, 20)).err(), Some(SessionTokenError::Invalid));
    }

    #[test]
    fn revision_bounds_are_enforced() {
        let first = serving(0, 4, 40, 20, 20);
        let last = serving(0, 9, 40, 20, 20);
        assert_eq!(admit(&committed(20, 0), &first, &last).err(), Some(SessionTokenError::Invalid));
        assert_eq!(admit(&committed(20, -1), &first, &last).err(), Some(SessionTokenError::Invalid));
        // Ahead of the final authoritative gate: never sign a future bound.
        assert_eq!(admit(&committed(20, 10), &first, &last).err(), Some(SessionTokenError::Invalid));
        assert_eq!(admit(&committed(20, 9), &first, &last).expect("bound").revision, 9);
    }
}
