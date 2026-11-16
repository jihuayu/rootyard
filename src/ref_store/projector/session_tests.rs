//! Unit tests for Raft Ref-CAS session lower bounds, ReadIndex fences,
//! realm separation, and strict deserialization contracts (#175).

use super::dependency::{ProjectionDependencyError, ProjectionDependencyTarget};
use super::session_fence::{
    AuthoritySourceKind, CallerAccessState, MAX_LIFETIME_SECONDS, MIN_LIFETIME_SECONDS, RAFT_SESSION_HEADER,
    RaftProbeOutcome, RaftReadProof, RaftSessionCodec, RaftSessionLowerBound, RaftSessionRealm, SessionFenceError,
    assert_authoritative_source, await_raft_read_or_redirect, current_unix_seconds, evaluate_raft_read,
};
use super::types::ProjectionRealm;
use crate::ref_store::GitObjectFormat;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

fn realm_fixture(group_id: i64) -> RaftSessionRealm {
    RaftSessionRealm {
        group_id,
        group_epoch: 1,
        history_incarnation: Uuid::from_u128(0x1001),
        authority_id: Uuid::from_u128(0x2002),
        authority_epoch: 1,
        cluster_incarnation: Uuid::from_u128(0x3003),
        tenant_id: Uuid::from_u128(0x4004),
        repository_id: Uuid::from_u128(0x5005),
        object_format: GitObjectFormat::Sha256,
    }
}

fn codec_fixture() -> RaftSessionCodec {
    RaftSessionCodec::new([(1u8, Zeroizing::new([0x11u8; 32])), (2u8, Zeroizing::new([0x22u8; 32]))], 2, 120)
        .expect("valid test codec")
}

fn proof_fixture(realm: RaftSessionRealm, idx: u64, ver: i64) -> RaftReadProof {
    RaftReadProof {
        source: AuthoritySourceKind::RaftReadIndexQuorum,
        realm,
        leader_id: Some(1),
        committed_log_index: idx,
        last_applied_log_index: idx,
        repo_ref_version: ver,
        state_digest_hex: "aa".repeat(32),
        pin_closure_intact: true,
    }
}

#[test]
fn token_roundtrip_key_rotation_forgery_and_clock_skew() {
    let realm = realm_fixture(7);
    let codec = codec_fixture();
    let now = 1_700_000_000;
    let tok = codec.mint_token(&realm, 42, 9, now).expect("mint token");
    assert!(tok.starts_with("rrs1."));

    let parsed = codec.verify_token(&tok, &realm, now).expect("verify at iat");
    assert_eq!(parsed.raft_log_index, 42);
    assert_eq!(parsed.repo_ref_version, 9);
    assert_eq!(parsed.realm, realm);

    // Zero future-iat skew and half-open upper expiry boundary.
    assert_eq!(codec.verify_token(&tok, &realm, now - 1), Err(SessionFenceError::Expired));
    assert!(codec.verify_token(&tok, &realm, now + 119).is_ok());
    assert_eq!(codec.verify_token(&tok, &realm, now + 120), Err(SessionFenceError::Expired));

    // Tampered token byte fails closed as ForgedOrInvalidToken (401).
    let mut tampered = tok.clone().into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered_str = String::from_utf8(tampered).unwrap();
    let forged = codec.verify_token(&tampered_str, &realm, now).unwrap_err();
    assert_eq!(forged, SessionFenceError::ForgedOrInvalidToken);
    assert_eq!(forged.status_code(), StatusCode::UNAUTHORIZED);

    // Retired key fails closed as ForgedOrInvalidToken (401).
    let retired = RaftSessionCodec::new([(1u8, Zeroizing::new([0x11u8; 32]))], 1, 120).expect("codec without key 2");
    assert_eq!(retired.verify_token(&tok, &realm, now), Err(SessionFenceError::ForgedOrInvalidToken));
}

#[test]
fn realm_isolation_forbids_cross_group_or_rotated_history_comparisons() {
    let r1 = realm_fixture(1);
    let codec = codec_fixture();
    let now = 1_700_000_000;
    let tok = codec.mint_token(&r1, 5, 2, now).expect("mint token");

    let mut diff_group = r1.clone();
    diff_group.group_id = 2;
    assert_eq!(codec.verify_token(&tok, &diff_group, now), Err(SessionFenceError::RealmMismatch));

    let mut diff_history = r1.clone();
    diff_history.history_incarnation = Uuid::from_u128(0x9999);
    assert_eq!(codec.verify_token(&tok, &diff_history, now), Err(SessionFenceError::RealmMismatch));

    let mut diff_authority = r1.clone();
    diff_authority.authority_id = Uuid::from_u128(0x8888);
    assert_eq!(codec.verify_token(&tok, &diff_authority, now), Err(SessionFenceError::RealmMismatch));

    let mut diff_cluster = r1.clone();
    diff_cluster.cluster_incarnation = Uuid::from_u128(0x7777);
    assert_eq!(codec.verify_token(&tok, &diff_cluster, now), Err(SessionFenceError::RealmMismatch));

    let bound = codec.verify_token(&tok, &r1, now).unwrap();
    // Even with much higher log_index & repo_ref_version in another group/history, comparison MUST fail.
    assert_eq!(bound.satisfies(9_999, 9_999, 9_999, &diff_group), Err(SessionFenceError::RealmMismatch));
    assert_eq!(bound.satisfies(9_999, 9_999, 9_999, &diff_history), Err(SessionFenceError::RealmMismatch));
    assert_eq!(SessionFenceError::RealmMismatch.status_code(), StatusCode::CONFLICT);
}

#[test]
fn permission_revocation_forbids_before_proof_and_non_raft_sources_are_rejected() {
    let realm = realm_fixture(3);
    let codec = codec_fixture();
    let proof = proof_fixture(realm.clone(), 10, 4);
    let now = 1_700_000_000;

    // Permission revocation checked before proof/version leak.
    let err = evaluate_raft_read(
        CallerAccessState { authenticated: true, has_read_permission: false },
        &codec,
        &proof,
        None,
        now,
    )
    .unwrap_err();
    assert_eq!(err, SessionFenceError::PermissionDenied);
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);

    let unauth = evaluate_raft_read(
        CallerAccessState { authenticated: false, has_read_permission: false },
        &codec,
        &proof,
        None,
        now,
    )
    .unwrap_err();
    assert_eq!(unauth, SessionFenceError::Unauthenticated);
    assert_eq!(unauth.status_code(), StatusCode::UNAUTHORIZED);

    // PG projection, Redis cache, and unverified local replica are NEVER allowed to authorize reads.
    for bad in [
        AuthoritySourceKind::PgRefsProjection,
        AuthoritySourceKind::RedisCache,
        AuthoritySourceKind::UnverifiedLocalReplica,
    ] {
        assert!(matches!(assert_authoritative_source(bad), Err(SessionFenceError::AuthorityViolation(_))));
        let mut non_auth = proof.clone();
        non_auth.source = bad;
        let res = evaluate_raft_read(
            CallerAccessState { authenticated: true, has_read_permission: true },
            &codec,
            &non_auth,
            None,
            now,
        );
        assert!(matches!(res, Err(SessionFenceError::AuthorityViolation(_))));
    }

    // Broken pin/pack closure fails closed even on RaftReadIndexQuorum.
    let mut bad_closure = proof.clone();
    bad_closure.pin_closure_intact = false;
    assert!(matches!(
        evaluate_raft_read(
            CallerAccessState { authenticated: true, has_read_permission: true },
            &codec,
            &bad_closure,
            None,
            now,
        ),
        Err(SessionFenceError::AuthorityViolation(_))
    ));
}

#[tokio::test]
async fn await_redirect_follows_leader_and_rejects_behind_or_lost_quorum() {
    let realm = realm_fixture(11);
    let codec = codec_fixture();
    let access = CallerAccessState { authenticated: true, has_read_permission: true };
    let now = current_unix_seconds();
    let bound = codec.mint_token(&realm, 15, 5, now).unwrap();

    // Follower forwards -> leader still lagged at 14 once -> catches up to 16 on retry.
    let calls = AtomicUsize::new(0);
    let admitted = await_raft_read_or_redirect(
        access,
        &codec,
        Some(&bound),
        Duration::from_millis(500),
        Duration::from_millis(10),
        3,
        |leader| {
            let realm = realm.clone();
            let c = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                match c {
                    0 => Ok(RaftProbeOutcome::ForwardToLeader(2)),
                    1 => {
                        assert_eq!(leader, Some(2));
                        Ok(RaftProbeOutcome::Ready(proof_fixture(realm, 14, 4)))
                    }
                    _ => Ok(RaftProbeOutcome::Ready(proof_fixture(realm, 16, 6))),
                }
            }
        },
    )
    .await
    .expect("converged on leader >= bound");
    assert_eq!(admitted.committed_log_index, 16);
    assert_eq!(admitted.repo_ref_version, 6);
    assert_ne!(admitted.session_token, bound);

    // Exhausted quorum loss returns 503 QuorumUnavailable.
    let lost = await_raft_read_or_redirect(
        access,
        &codec,
        Some(&bound),
        Duration::from_millis(40),
        Duration::from_millis(10),
        2,
        |_| async { Ok(RaftProbeOutcome::QuorumUnavailable("no quorum".into())) },
    )
    .await
    .unwrap_err();
    assert_eq!(lost.status_code(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn headers_and_serde_deny_unknown_fields_enforced() {
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static(RAFT_SESSION_HEADER), HeaderValue::from_static("rrs1.abc.def"));
    assert_eq!(RaftSessionCodec::extract_header(&headers).unwrap(), Some("rrs1.abc.def"));
    headers.append(HeaderName::from_static(RAFT_SESSION_HEADER), HeaderValue::from_static("rrs1.abc.def"));
    assert!(matches!(RaftSessionCodec::extract_header(&headers), Err(SessionFenceError::MalformedToken(_))));

    assert!(RaftSessionCodec::new([(1, Zeroizing::new([1; 32]))], 1, MIN_LIFETIME_SECONDS - 1).is_err());
    assert!(RaftSessionCodec::new([(1, Zeroizing::new([1; 32]))], 1, MAX_LIFETIME_SECONDS + 1).is_err());

    let realm = realm_fixture(1);
    let mut val = serde_json::to_value(&realm).unwrap();
    val.as_object_mut().unwrap().insert("unknown_extra".into(), serde_json::json!(1));
    assert!(serde_json::from_value::<RaftSessionRealm>(val).is_err());

    let lb = RaftSessionLowerBound {
        realm: realm.clone(),
        raft_log_index: 1,
        repo_ref_version: 1,
        key_id: 2,
        issued_unix: 100,
        lifetime_seconds: 60,
    };
    let mut lb_val = serde_json::to_value(&lb).unwrap();
    lb_val.as_object_mut().unwrap().insert("projection_cursor".into(), serde_json::json!(99));
    assert!(serde_json::from_value::<RaftSessionLowerBound>(lb_val).is_err());

    let dep = ProjectionDependencyTarget {
        realm: ProjectionRealm::new(Uuid::from_u128(1), 1, 1).unwrap(),
        min_log_index: 1,
        min_event_seq: 1,
        required_op_event_id: Some("ab".repeat(32)),
        required_repository_id: None,
        min_repo_revision: None,
    };
    assert!(dep.validate().is_ok());
    let mut dep_val = serde_json::to_value(&dep).unwrap();
    dep_val.as_object_mut().unwrap().insert("extra_field".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<ProjectionDependencyTarget>(dep_val).is_err());

    let bad_dep = ProjectionDependencyTarget {
        realm: ProjectionRealm::new(Uuid::from_u128(1), 1, 1).unwrap(),
        min_log_index: 0,
        min_event_seq: 1,
        required_op_event_id: None,
        required_repository_id: None,
        min_repo_revision: None,
    };
    assert!(matches!(bad_dep.validate(), Err(ProjectionDependencyError::InvalidInput(_))));
}
