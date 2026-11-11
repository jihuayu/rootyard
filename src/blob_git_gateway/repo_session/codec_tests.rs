//! Signed-frame tests for authority kind, group id, clock and transcript.
use super::*;

#[test]
fn authority_kind_and_group_id_are_signed_and_mismatch_is_realm() {
    let codec = codec(&[(0, key(1))], 0);
    let pg = realm(20);
    let issued = codec.issue(&pg, 5, 1_000).expect("pg issue");
    for foreign in [SessionRealm { authority: AuthorityKind::RaftRefStore, ..pg }, SessionRealm { group_id: 7, ..pg }] {
        assert_eq!(codec.verify(issued.token(), 1_001, &foreign, 5), Err(SessionTokenError::Realm));
    }
    let raft = SessionRealm { authority: AuthorityKind::RaftRefStore, group_id: 4, ..pg };
    let raft_token = codec.issue(&raft, 5, 1_000).expect("raft issue");
    assert_eq!(codec.verify(raft_token.token(), 1_001, &pg, 5), Err(SessionTokenError::Realm));
    // The signed frame really carries the authority kind and group id.
    let session = codec.authenticate_for_test(raft_token.token(), 1_001).expect("raft mac");
    assert_eq!(session.realm().authority, AuthorityKind::RaftRefStore);
    assert_eq!(session.realm().group_id, 4);
    assert_eq!(session.realm().authority, AuthorityKind::RaftRefStore);
}

/// A correctly MACed frame with an unknown one-byte authority discriminator is
/// malformed, never silently treated as the PostgreSQL authority.
#[test]
fn unknown_authority_kind_wire_byte_is_malformed() {
    let codec = codec(&[(0, key(1))], 0);
    let live = realm(21);
    let mut frame = [0u8; BODY_LEN];
    frame[0] = FORMAT_BYTE;
    frame[1] = 9;
    frame[2] = 0;
    frame[3..7].copy_from_slice(&120u32.to_be_bytes());
    frame[7..15].copy_from_slice(&2i64.to_be_bytes());
    frame[15..31].copy_from_slice(live.tenant_id.as_bytes());
    frame[31..47].copy_from_slice(live.repository_id.as_bytes());
    frame[47] = 1;
    frame[49..65].copy_from_slice(live.history_incarnation.as_bytes());
    frame[65..73].copy_from_slice(&1i64.to_be_bytes());
    frame[73..81].copy_from_slice(&1i64.to_be_bytes());
    frame[81..97].copy_from_slice(live.cluster_incarnation.as_bytes());
    frame[97..105].copy_from_slice(&0u64.to_be_bytes());
    frame[105..109].copy_from_slice(&100_000u32.to_be_bytes());
    frame[109..119].copy_from_slice(TRAILER);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key(1));
    let tag = hmac::sign(&key, &codec.message(0, &frame));
    let token = format!("{PREFIX}{}.{}", URL_SAFE_NO_PAD.encode(frame), URL_SAFE_NO_PAD.encode(tag.as_ref()));
    assert_eq!(codec.authenticate_for_test(&token, 100_001), Err(SessionTokenError::Malformed));
}

/// The strict clock rule is explicit: one second before `iat` is expired, the
/// exact `iat` second is accepted, and the half-open upper bound is exact.
#[test]
fn future_iat_has_zero_skew_and_the_expiry_boundary_is_exact() {
    let codec = codec(&[(0, key(1))], 0);
    let live = realm(22);
    let issued = codec.issue(&live, 2, 100_000).expect("issue");
    assert_eq!(codec.authenticate_for_test(issued.token(), 99_999), Err(SessionTokenError::Expired));
    assert!(codec.authenticate_for_test(issued.token(), 100_000).is_ok());
    assert!(codec.authenticate_for_test(issued.token(), 100_119).is_ok());
    assert_eq!(codec.authenticate_for_test(issued.token(), 100_120), Err(SessionTokenError::Expired));
}

/// Shifting one byte across the adjacent tenant/repository frame fields changes
/// the MAC input even though the body length and every delimiter stay equal.
#[test]
fn shifting_a_byte_between_adjacent_transcript_fields_fails_the_mac() {
    let codec = codec(&[(0, key(1))], 0);
    let live = realm(23);
    let issued = codec.issue(&live, 2, 1_000).expect("issue");
    let mut parts = issued.token().split('.');
    assert_eq!(parts.next(), Some("rs1"));
    let body = parts.next().expect("body");
    let mac = parts.next().expect("mac");
    let mut frame = URL_SAFE_NO_PAD.decode(body).expect("body b64");
    frame[30] = frame[30].wrapping_sub(1);
    frame[31] = frame[31].wrapping_add(1);
    let shifted = format!("{PREFIX}{}.{}", URL_SAFE_NO_PAD.encode(&frame), mac);
    assert_eq!(codec.authenticate_for_test(&shifted, 1_001), Err(SessionTokenError::Invalid));
}
