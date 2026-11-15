use super::*;
use crate::blob_git_gateway::repo_session::{
    SessionTokenCodec, SessionTokenError, TEST_MAX_TOKEN_LEN, presented_for_test,
};
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

fn serving(revision: i64, cluster: Uuid) -> ServingRepository {
    serving_with_epochs(revision, cluster, 1, 1)
}

fn serving_with_epochs(revision: i64, cluster: Uuid, authority_epoch: i64, group_epoch: i64) -> ServingRepository {
    let gate = crate::ref_store::CoreGate::new(
        id(11),
        id(12),
        GitObjectFormat::Sha1,
        id(13),
        authority_epoch,
        group_epoch,
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
    let tokens = tokens();
    let live = serving(3, id(4));
    for value in ["", "rs1.", "rs2.abc.def", &"x".repeat(TEST_MAX_TOKEN_LEN + 1)] {
        assert!(presented(&header(value)).is_ok(), "{value:?}");
        assert_eq!(answer(Some(id(4)), Some(&tokens), &header(value), &live, 3), Err(malformed()), "{value:?}");
    }
    let mut duplicate = header("rs1.a.b");
    duplicate.append(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_static("rs1.a.b"));
    assert_eq!(presented(&duplicate).err(), Some(SessionTokenError::Invalid));
    assert_eq!(presented_for_test(&duplicate).err(), Some(SessionTokenError::Invalid));
    assert_eq!(answer(Some(id(4)), Some(&tokens), &duplicate, &live, 3), Err(malformed()));
    assert_eq!(live_realm(&serving(3, id(4)), Uuid::nil()), Err(malformed()));
}

#[test]
fn the_bound_is_scored_against_the_captured_revision() {
    let tokens = tokens();
    let live = serving(9, id(4));
    let issued = tokens.issue_for_test(&live_realm(&live, id(4)).expect("realm"), 10).expect("issue");
    let presented = header(issued.token());
    assert_eq!(answer(Some(id(4)), Some(&tokens), &presented, &live, 10), Ok(()));
    assert_eq!(
        answer(Some(id(4)), Some(&tokens), &presented, &live, 9),
        Err(GatewayError::Unavailable(BEHIND_MESSAGE))
    );
    let foreign = live_realm(&serving(5, id(8)), id(8)).expect("realm");
    assert_eq!(
        tokens.verify(&presented_for_test(&presented).expect("presented"), &foreign, 5).map_err(|e| e.for_repo()),
        Err(SessionTokenError::Realm.for_repo())
    );
    let wrong_gateway = SessionTokenCodec::new([(0u8, Zeroizing::new([9u8; 32]))], 0, &backend(), 120).expect("codec");
    let foreign_codec =
        SessionTokenCodec::new([(0u8, Zeroizing::new([7u8; 32]))], 0, &backend(), 120).expect("foreign");
    let wrong_sig =
        SessionTokens::new(foreign_codec).issue_for_test(&live_realm(&live, id(4)).expect("realm"), 5).expect("issue");
    assert_eq!(
        SessionTokens::new(wrong_gateway)
            .verify(&presented_for_test(&header(wrong_sig.token())).expect("presented"), &foreign, 5)
            .map_err(|e| e.for_repo()),
        Err(SessionTokenError::Realm.for_repo())
    );
    assert_eq!(GatewayError::Unavailable(AUTHORITY_CHANGED).status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn simulated_lagging_view_refuses_until_revision_advances_then_admits() {
    let tokens = tokens();
    let cluster = id(4);
    let authoritative = serving(12, cluster);
    let realm = live_realm(&authoritative, cluster).expect("realm");
    let issued = tokens.issue_for_test(&realm, 12).expect("issue bound 12");
    let presented = header(issued.token());

    // Simulate polling a lagging compute/cache view through a bounded budget:
    // stale observations (< 12) MUST refuse explicitly (`Behind` / `503`),
    // never silently downgrade to a stale 200. Once the observed revision
    // reaches or surpasses 12, the exact same presented token succeeds.
    let observe_lagging_then_catch_up = |revisions: &[i64]| {
        let mut last = Err(GatewayError::Unavailable(BEHIND_MESSAGE));
        for &rev in revisions {
            let snapshot = serving(rev, cluster);
            last = answer(Some(cluster), Some(&tokens), &presented, &snapshot, rev);
            if last.is_ok() {
                return last;
            }
            assert_eq!(last, Err(GatewayError::Unavailable(BEHIND_MESSAGE)));
        }
        last
    };

    assert_eq!(
        observe_lagging_then_catch_up(&[10, 11]),
        Err(GatewayError::Unavailable(BEHIND_MESSAGE)),
        "exhausting bounded retries while still lagging must remain explicit 503 Behind"
    );
    assert_eq!(
        observe_lagging_then_catch_up(&[10, 11, 12]),
        Ok(()),
        "same presented bound succeeds immediately once revision reaches bound"
    );
    assert_eq!(
        observe_lagging_then_catch_up(&[11, 13]),
        Ok(()),
        "same presented bound succeeds when view advances past bound"
    );
}

#[test]
fn the_capture_anchor_is_checked_before_the_key_set_or_the_header() {
    let live = serving(5, id(4));
    let rotated = GatewayError::Unavailable(AUTHORITY_CHANGED);
    let tokens = tokens();
    for captured in [None, Some(id(8)), Some(Uuid::nil())] {
        assert_eq!(answer(captured, None, &HeaderMap::new(), &live, 5), Err(rotated), "{captured:?}");
        assert_eq!(answer(captured, Some(&tokens), &HeaderMap::new(), &live, 5), Err(rotated), "{captured:?}");
    }
    assert_eq!(answer(Some(id(4)), None, &HeaderMap::new(), &live, 5), Ok(()));
    assert_eq!(answer(Some(id(4)), Some(&tokens), &HeaderMap::new(), &live, 5), Ok(()));
}

#[test]
fn a_keyring_present_realm_rotation_is_refused() {
    let rotated = serving(5, id(4));
    let foreign = live_realm(&serving(5, id(8)), id(8)).expect("realm");
    let issued = tokens().issue_for_test(&foreign, 5).expect("issue");
    assert_eq!(
        answer(Some(id(4)), Some(&tokens()), &header(issued.token()), &rotated, 5),
        Err(SessionTokenError::Realm.for_repo())
    );
}

#[test]
fn epochs_above_i32_max_stay_token_free_and_fail_closed_for_foreign_tokens() {
    let high = i64::from(i32::MAX) + 1;
    let live = serving_with_epochs(9, id(4), high, high);
    let tokens = tokens();
    let realm = live_realm(&live, id(4)).expect("high-epoch realm");
    assert_eq!(realm.authority_epoch, high);
    assert_eq!(answer(Some(id(4)), Some(&tokens), &HeaderMap::new(), &live, 9), Ok(()));
    assert_eq!(admit(Some(&tokens), &HeaderMap::new(), &live), Ok(()));
    let issued = tokens.issue_for_test(&realm, 9).expect("high-epoch issue");
    assert_eq!(answer(Some(id(4)), Some(&tokens), &header(issued.token()), &live, 9), Ok(()));
    assert_eq!(
        answer(Some(id(4)), Some(&tokens), &header(issued.token()), &live, 8),
        Err(GatewayError::Unavailable(BEHIND_MESSAGE))
    );
    let foreign = serving_with_epochs(9, id(4), high + 1, high);
    assert_eq!(
        answer(Some(id(4)), Some(&tokens), &header(issued.token()), &foreign, 9),
        Err(SessionTokenError::Realm.for_repo())
    );
}

#[test]
fn the_final_fence_refuses_missing_nil_and_rotated_anchors_without_a_proof() {
    let live = serving(5, id(4));
    let rotated = GatewayError::Unavailable(AUTHORITY_CHANGED);
    for anchor in [None, Some(id(8)), Some(Uuid::nil())] {
        assert_eq!(verify_capture_anchor(anchor, None, &live), Err(rotated), "{anchor:?}");
    }
    assert_eq!(verify_capture_anchor(Some(id(4)), None, &live), Ok(id(4)));
}

#[test]
fn an_unrotated_capture_is_scored_after_its_anchor() {
    let tokens = tokens();
    let live = serving(9, id(4));
    let issued = tokens.issue_for_test(&live_realm(&live, id(4)).expect("realm"), 5).expect("issue");
    let presented = header(issued.token());
    assert_eq!(answer(Some(id(4)), Some(&tokens), &presented, &live, 5), Ok(()));
    assert_eq!(
        answer(Some(id(8)), Some(&tokens), &presented, &live, 5),
        Err(GatewayError::Unavailable(AUTHORITY_CHANGED))
    );
    assert_eq!(answer(Some(id(4)), Some(&tokens), &header("rs1.anything.anything"), &live, 5), Err(malformed()));
}
