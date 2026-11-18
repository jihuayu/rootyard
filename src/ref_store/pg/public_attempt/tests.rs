use super::{
    PublicAttemptLookup, PublicAttemptRequest, RawAttempt, RawRealm, RawSnapshot, RawWrapper, SELECT_SNAPSHOT, evaluate,
};
use crate::ref_store::{
    CommitMode, GitObjectFormat, OperationState, RefStoreError, RequestDigest,
    core::pack_commit::{PackCommitError, PackCommitRejectCode},
};
use serde_json::{Value, json};
use uuid::Uuid;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn digest(byte: u8) -> RequestDigest {
    RequestDigest::from_bytes([byte; 32])
}

fn repo() -> Uuid {
    id(1)
}

fn public() -> Uuid {
    id(2)
}

fn owner() -> Uuid {
    id(3)
}

fn issuer() -> Uuid {
    id(4)
}

fn history() -> Uuid {
    id(5)
}

fn restore() -> Uuid {
    id(6)
}

fn private0() -> Uuid {
    id(7)
}

fn private1() -> Uuid {
    id(8)
}

fn event0() -> Uuid {
    id(9)
}

fn event1() -> Uuid {
    id(10)
}

fn wire() -> RequestDigest {
    digest(0x11)
}

fn plan0() -> RequestDigest {
    digest(0x21)
}

fn proof0() -> RequestDigest {
    digest(0x22)
}

fn plan1() -> RequestDigest {
    digest(0x31)
}

fn proof1() -> RequestDigest {
    digest(0x32)
}

fn backend() -> String {
    "0123456789abcdef".repeat(4)
}

fn request() -> PublicAttemptRequest {
    PublicAttemptRequest {
        repository_id: repo(),
        admission_owner_id: owner(),
        issuer_id: issuer(),
        public_id: public(),
        wire_digest: wire(),
        request_mode: CommitMode::Atomic,
        backend_identity: backend(),
        object_format: GitObjectFormat::Sha1,
        history_incarnation: history(),
        authority_epoch: 1,
        group_epoch: 2,
        restore_incarnation: restore(),
    }
}

fn realm() -> RawRealm {
    RawRealm {
        repository_id: repo(),
        repository_owner_id: owner(),
        repository_name: "public-attempt".into(),
        repository_object_format: "sha1".into(),
        repository_state: "ready".into(),
        repository_storage_backend: "pg_refstore".into(),
        repository_transition_state: "stable".into(),
        repository_archived_at: None,
        repository_deleted_at: None,
        gate_tenant_id: Some(owner()),
        gate_object_format: Some("sha1".into()),
        gate_history_incarnation: Some(history()),
        gate_authority_epoch: Some(1),
        gate_group_epoch: Some(2),
        gate_revision: Some(2),
        serving_owner_id: Some(owner()),
        serving_name: Some("public-attempt".into()),
        serving_object_format: Some("sha1".into()),
        serving_history_incarnation: Some(history()),
        serving_authority_epoch: Some(1),
        serving_group_epoch: Some(2),
        serving_backend_identity: Some(backend()),
        serving_state: Some("ready".into()),
        protocol_tenant_id: Some(owner()),
        protocol_object_format: Some("sha1".into()),
        protocol_history_incarnation: Some(history()),
        protocol_authority_epoch: Some(1),
        protocol_group_epoch: Some(2),
        protocol_decision_required: Some(true),
        cluster_incarnation: Some(restore()),
    }
}

fn wrapper(current_slot: i16, state: &str) -> RawWrapper {
    RawWrapper {
        repository_id: repo(),
        public_id: public(),
        admission_owner_id: owner(),
        issuer_id: issuer(),
        wire_digest: wire().as_hex(),
        request_mode: "atomic".into(),
        backend_identity: backend(),
        object_format: "sha1".into(),
        history_incarnation: history(),
        authority_epoch: 1,
        group_epoch: 2,
        restore_incarnation: restore(),
        current_slot,
        state: state.into(),
        event_id: if matches!(state, "committed" | "rejected") { Some(event1()) } else { None },
        retired_event_id: if current_slot == 1 { Some(event0()) } else { None },
        cancelled_private_id: if state == "cancelled" {
            Some(if current_slot == 1 { private1() } else { private0() })
        } else {
            None
        },
    }
}

fn committed_payload(revision: i64) -> Value {
    json!({
        "kind": "committed",
        "repository_id": repo(),
        "revision": revision,
        "head_ref": "refs/heads/main",
        "mode": "atomic",
        "refs": [],
        "registrations": [],
        "rejection": null
    })
}

fn rejected_payload(revision: i64) -> Value {
    json!({
        "kind": "rejected",
        "repository_id": repo(),
        "revision": revision,
        "head_ref": null,
        "mode": "atomic",
        "refs": [],
        "registrations": [],
        "rejection": {"code": "revision_mismatch", "detail": "gate revision differs"}
    })
}

fn cancelled_terminal() -> Value {
    json!({"state": "cancelled", "reason": "cancel_requested"})
}

fn base_attempt(slot: i16, private_id: Uuid, plan: RequestDigest, proof: RequestDigest, sequence: i64) -> RawAttempt {
    RawAttempt {
        slot,
        private_id,
        plan_digest: plan.as_hex(),
        proof_digest: proof.as_hex(),
        base_revision: 1,
        serving_bound: true,
        operation_issuer_id: Some(issuer()),
        operation_lane: Some("lane".into()),
        operation_sequence: Some(sequence),
        operation_request_digest: Some(plan.as_hex()),
        operation_state: Some("pending".into()),
        operation_terminal_result: None,
        event_id: None,
        event_repository_id: None,
        event_revision: None,
        event_outcome: None,
        event_payload: None,
        tombstone_operation_id: None,
        tombstone_issuer_id: None,
        tombstone_lane: None,
        tombstone_sequence: None,
        tombstone_request_digest: None,
        lane_tombstone_operation_id: None,
    }
}

fn pending_attempt(
    slot: i16,
    private_id: Uuid,
    plan: RequestDigest,
    proof: RequestDigest,
    sequence: i64,
    base_revision: i64,
) -> RawAttempt {
    let mut attempt = base_attempt(slot, private_id, plan, proof, sequence);
    attempt.base_revision = base_revision;
    attempt
}

fn retired_attempt() -> RawAttempt {
    let mut attempt = base_attempt(0, private0(), plan0(), proof0(), 1);
    let payload = rejected_payload(2);
    attempt.operation_state = Some("rejected".into());
    attempt.operation_terminal_result = Some(payload.clone());
    attempt.event_id = Some(event0());
    attempt.event_repository_id = Some(repo());
    attempt.event_revision = Some(2);
    attempt.event_outcome = Some("rejected".into());
    attempt.event_payload = Some(payload);
    attempt
}

fn committed_attempt() -> RawAttempt {
    let mut attempt = base_attempt(0, private0(), plan0(), proof0(), 1);
    let payload = committed_payload(2);
    attempt.operation_state = Some("committed".into());
    attempt.operation_terminal_result = Some(payload.clone());
    attempt.event_id = Some(event1());
    attempt.event_repository_id = Some(repo());
    attempt.event_revision = Some(2);
    attempt.event_outcome = Some("committed".into());
    attempt.event_payload = Some(payload);
    attempt
}

fn cancelled_attempt() -> RawAttempt {
    let mut attempt = base_attempt(0, private0(), plan0(), proof0(), 1);
    attempt.operation_state = Some("cancelled".into());
    attempt.operation_terminal_result = Some(cancelled_terminal());
    attempt.tombstone_operation_id = Some(private0());
    attempt.tombstone_issuer_id = Some(issuer());
    attempt.tombstone_lane = Some("lane".into());
    attempt.tombstone_sequence = Some(1);
    attempt.tombstone_request_digest = Some(plan0().as_hex());
    attempt.lane_tombstone_operation_id = Some(private0());
    attempt
}

fn snapshot(wrapper: RawWrapper, attempts: Vec<RawAttempt>) -> RawSnapshot {
    RawSnapshot {
        wrapper: Some(wrapper),
        attempts,
        private_occupied: false,
        legacy_operation: false,
        legacy_cancellation: false,
        realm: Some(realm()),
    }
}

fn empty_snapshot() -> RawSnapshot {
    RawSnapshot {
        wrapper: None,
        attempts: Vec::new(),
        private_occupied: false,
        legacy_operation: false,
        legacy_cancellation: false,
        realm: Some(realm()),
    }
}

fn assert_ledger(result: Result<PublicAttemptLookup, PackCommitError>) {
    match result {
        Err(PackCommitError::Rejected(rejection)) => {
            assert_eq!(rejection.code, PackCommitRejectCode::LedgerIntegrity);
        }
        other => panic!("expected ledger integrity, got {other:?}"),
    }
}

fn assert_identity_conflict(result: Result<PublicAttemptLookup, PackCommitError>) {
    assert!(matches!(result, Err(PackCommitError::RefStore(RefStoreError::IdentityConflict))));
}

fn assert_digest_conflict(result: Result<PublicAttemptLookup, PackCommitError>) {
    assert!(matches!(result, Err(PackCommitError::RefStore(RefStoreError::DigestConflict))));
}

#[test]
fn pending_slot_zero_is_resolved_from_the_current_attempt() {
    let result = evaluate(
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]),
        &request(),
    )
    .expect("valid pending slot zero");
    match result {
        PublicAttemptLookup::Pending(evidence) => {
            assert_eq!(evidence.public_id, public());
            assert_eq!(evidence.current.slot, 0);
            assert_eq!(evidence.current.private_id, private0());
            assert_eq!(evidence.current.state, OperationState::Pending);
            assert_eq!(evidence.current.plan_digest, plan0());
            assert_eq!(evidence.current.proof_digest, proof0());
            assert!(evidence.current.event_id.is_none());
            assert!(evidence.retired.is_none());
        }
        other => panic!("expected pending slot zero, got {other:?}"),
    }
}

#[test]
fn pending_slot_one_returns_pending_and_never_the_retired_rejection() {
    let result = evaluate(
        snapshot(
            wrapper(1, "pending"),
            vec![retired_attempt(), pending_attempt(1, private1(), plan1(), proof1(), 2, 2)],
        ),
        &request(),
    )
    .expect("valid pending slot one");
    match result {
        PublicAttemptLookup::Pending(evidence) => {
            assert_eq!(evidence.current.slot, 1);
            assert_eq!(evidence.current.private_id, private1());
            let retired = evidence.retired.expect("slot-zero retirement evidence");
            assert_eq!(retired.slot, 0);
            assert_eq!(retired.private_id, private0());
            assert_eq!(retired.state, OperationState::Rejected);
            assert_eq!(retired.event_id, Some(event0()));
        }
        PublicAttemptLookup::Rejected(_) => panic!("retired slot zero must not be the public final result"),
        other => panic!("expected pending slot one, got {other:?}"),
    }
}

#[test]
fn slot_zero_rejection_with_a_pending_wrapper_fails_closed() {
    assert_ledger(evaluate(snapshot(wrapper(0, "pending"), vec![retired_attempt()]), &request()));
}

#[test]
fn committed_requires_the_exact_event_and_terminal_body() {
    let result =
        evaluate(snapshot(wrapper(0, "committed"), vec![committed_attempt()]), &request()).expect("valid committed");
    match result {
        PublicAttemptLookup::Committed(evidence) => {
            assert_eq!(evidence.current.state, OperationState::Committed);
            assert_eq!(evidence.current.event_id, Some(event1()));
            assert_eq!(evidence.current.event_revision, Some(2));
        }
        other => panic!("expected committed, got {other:?}"),
    }

    let mut wrong_payload = committed_attempt();
    wrong_payload.event_payload = Some(committed_payload(3));
    assert_ledger(evaluate(snapshot(wrapper(0, "committed"), vec![wrong_payload]), &request()));

    let mut wrong_outcome = committed_attempt();
    wrong_outcome.event_outcome = Some("rejected".into());
    assert_ledger(evaluate(snapshot(wrapper(0, "committed"), vec![wrong_outcome]), &request()));

    assert_ledger(evaluate(snapshot(wrapper(0, "committed"), vec![retired_attempt()]), &request()));
}

#[test]
fn cancelled_requires_the_current_private_id_and_exact_tombstone() {
    let result =
        evaluate(snapshot(wrapper(0, "cancelled"), vec![cancelled_attempt()]), &request()).expect("valid cancelled");
    match result {
        PublicAttemptLookup::Cancelled(evidence) => {
            assert_eq!(evidence.current.state, OperationState::Cancelled);
            assert_eq!(evidence.current.private_id, private0());
            assert!(evidence.current.event_id.is_none());
        }
        other => panic!("expected cancelled, got {other:?}"),
    }

    let mut wrong_current = wrapper(0, "cancelled");
    wrong_current.cancelled_private_id = Some(private1());
    assert_ledger(evaluate(snapshot(wrong_current, vec![cancelled_attempt()]), &request()));

    let mut wrong_tombstone = cancelled_attempt();
    wrong_tombstone.tombstone_request_digest = Some(plan1().as_hex());
    assert_ledger(evaluate(snapshot(wrapper(0, "cancelled"), vec![wrong_tombstone]), &request()));

    let mut wrong_lane_tombstone = cancelled_attempt();
    wrong_lane_tombstone.lane_tombstone_operation_id = Some(private1());
    assert_ledger(evaluate(snapshot(wrapper(0, "cancelled"), vec![wrong_lane_tombstone]), &request()));

    let mut wrong_terminal = cancelled_attempt();
    wrong_terminal.operation_terminal_result = Some(json!({"state": "cancelled", "reason": "other"}));
    assert_ledger(evaluate(snapshot(wrapper(0, "cancelled"), vec![wrong_terminal]), &request()));
}

#[test]
fn cancelled_slot_one_binds_only_the_current_attempt() {
    let mut current = wrapper(1, "cancelled");
    current.cancelled_private_id = Some(private1());
    let mut cancelled = base_attempt(1, private1(), plan1(), proof1(), 2);
    cancelled.base_revision = 2;
    cancelled.operation_state = Some("cancelled".into());
    cancelled.operation_terminal_result = Some(cancelled_terminal());
    cancelled.tombstone_operation_id = Some(private1());
    cancelled.tombstone_issuer_id = Some(issuer());
    cancelled.tombstone_lane = Some("lane".into());
    cancelled.tombstone_sequence = Some(2);
    cancelled.tombstone_request_digest = Some(plan1().as_hex());
    cancelled.lane_tombstone_operation_id = Some(private1());

    let result = evaluate(snapshot(current.clone(), vec![retired_attempt(), cancelled.clone()]), &request())
        .expect("valid cancelled slot one");
    match result {
        PublicAttemptLookup::Cancelled(evidence) => {
            assert_eq!(evidence.current.slot, 1);
            assert_eq!(evidence.current.private_id, private1());
            assert_eq!(evidence.retired.expect("retired evidence").private_id, private0());
        }
        other => panic!("expected cancelled slot one, got {other:?}"),
    }

    current.cancelled_private_id = Some(private0());
    assert_ledger(evaluate(snapshot(current, vec![retired_attempt(), cancelled]), &request()));
}

#[test]
fn retired_attempt_must_be_the_advanced_revision_mismatch_rejection() {
    let mut wrong_code = retired_attempt();
    let mut payload = rejected_payload(2);
    payload["rejection"]["code"] = json!("old_oid_mismatch");
    wrong_code.operation_terminal_result = Some(payload.clone());
    wrong_code.event_payload = Some(payload);
    assert_ledger(evaluate(
        snapshot(wrapper(1, "pending"), vec![wrong_code, pending_attempt(1, private1(), plan1(), proof1(), 2, 2)]),
        &request(),
    ));

    let mut wrong_revision = retired_attempt();
    wrong_revision.event_revision = Some(1);
    let mut payload = rejected_payload(1);
    payload["revision"] = json!(1);
    wrong_revision.operation_terminal_result = Some(payload.clone());
    wrong_revision.event_payload = Some(payload);
    assert_ledger(evaluate(
        snapshot(wrapper(1, "pending"), vec![wrong_revision, pending_attempt(1, private1(), plan1(), proof1(), 2, 2)]),
        &request(),
    ));

    let mut wrong_registrations = retired_attempt();
    let mut payload = rejected_payload(2);
    payload["registrations"] = json!([{"pack_id": id(30)}]);
    wrong_registrations.operation_terminal_result = Some(payload.clone());
    wrong_registrations.event_payload = Some(payload);
    assert_ledger(evaluate(
        snapshot(
            wrapper(1, "pending"),
            vec![wrong_registrations, pending_attempt(1, private1(), plan1(), proof1(), 2, 2)],
        ),
        &request(),
    ));
}

#[test]
fn stale_or_inconsistent_realm_is_refused() {
    let mut stale_restore =
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]);
    stale_restore.realm.as_mut().unwrap().cluster_incarnation = Some(id(99));
    assert_ledger(evaluate(stale_restore, &request()));

    let mut stale_backend =
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]);
    stale_backend.realm.as_mut().unwrap().serving_backend_identity = Some("f".repeat(64));
    assert_ledger(evaluate(stale_backend, &request()));

    let mut archived = snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]);
    archived.realm.as_mut().unwrap().repository_archived_at = Some("2026-11-19T00:00:00Z".into());
    assert_ledger(evaluate(archived, &request()));
}

#[test]
fn attempt_set_must_be_exactly_the_slots_required_by_the_current_slot() {
    assert_ledger(evaluate(snapshot(wrapper(0, "pending"), Vec::new()), &request()));

    let mut duplicate = pending_attempt(0, private0(), plan0(), proof0(), 1, 1);
    duplicate.proof_digest = proof1().as_hex();
    assert_ledger(evaluate(
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1), duplicate]),
        &request(),
    ));

    assert_ledger(evaluate(
        snapshot(wrapper(1, "pending"), vec![pending_attempt(1, private1(), plan1(), proof1(), 2, 2)]),
        &request(),
    ));

    assert_ledger(evaluate(
        snapshot(
            wrapper(0, "pending"),
            vec![retired_attempt(), pending_attempt(1, private1(), plan1(), proof1(), 2, 2)],
        ),
        &request(),
    ));

    assert_ledger(evaluate(
        snapshot(
            wrapper(1, "pending"),
            vec![retired_attempt(), pending_attempt(1, private0(), plan1(), proof1(), 2, 2)],
        ),
        &request(),
    ));
}

#[test]
fn private_and_legacy_markers_never_expose_legacy_data() {
    let mut private = empty_snapshot();
    private.private_occupied = true;
    private.legacy_operation = true;
    private.legacy_cancellation = true;
    assert!(matches!(evaluate(private, &request()).expect("private marker"), PublicAttemptLookup::PrivateIdentifier));

    let mut legacy = empty_snapshot();
    legacy.legacy_operation = true;
    assert!(matches!(evaluate(legacy, &request()).expect("legacy marker"), PublicAttemptLookup::LegacyPath));

    let mut legacy_cancellation = empty_snapshot();
    legacy_cancellation.legacy_cancellation = true;
    assert!(matches!(
        evaluate(legacy_cancellation, &request()).expect("legacy cancellation marker"),
        PublicAttemptLookup::LegacyPath
    ));

    assert!(matches!(evaluate(empty_snapshot(), &request()).expect("unknown marker"), PublicAttemptLookup::Unknown));
}

#[test]
fn public_identifier_cannot_alias_a_private_or_legacy_claim() {
    let mut private_alias =
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]);
    private_alias.private_occupied = true;
    assert_ledger(evaluate(private_alias, &request()));

    let mut legacy_alias =
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]);
    legacy_alias.legacy_operation = true;
    assert_ledger(evaluate(legacy_alias, &request()));

    let mut cancellation_alias =
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]);
    cancellation_alias.legacy_cancellation = true;
    assert_ledger(evaluate(cancellation_alias, &request()));
}

#[test]
fn wrapper_identity_mismatches_are_fixed_typed_errors() {
    let attempt = || vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)];

    let mut wrong_wire = request();
    wrong_wire.wire_digest = plan0();
    assert_digest_conflict(evaluate(snapshot(wrapper(0, "pending"), attempt()), &wrong_wire));

    let mut wrong_issuer = request();
    wrong_issuer.issuer_id = private1();
    assert_identity_conflict(evaluate(snapshot(wrapper(0, "pending"), attempt()), &wrong_issuer));

    let mut wrong_mode = request();
    wrong_mode.request_mode = CommitMode::AcceptedSubset;
    assert_identity_conflict(evaluate(snapshot(wrapper(0, "pending"), attempt()), &wrong_mode));
}

#[test]
fn request_shape_rejects_nil_non_hex_and_non_positive_epochs() {
    let mut nil_repo = request();
    nil_repo.repository_id = Uuid::nil();
    assert!(matches!(nil_repo.validate(), Err(PackCommitError::Invalid(_))));

    let mut nil_issuer = request();
    nil_issuer.issuer_id = Uuid::nil();
    assert!(matches!(nil_issuer.validate(), Err(PackCommitError::Invalid(_))));

    let mut non_hex = request();
    non_hex.backend_identity = "not-a-digest".into();
    assert!(matches!(non_hex.validate(), Err(PackCommitError::Invalid(_))));

    let mut zero_epoch = request();
    zero_epoch.authority_epoch = 0;
    assert!(matches!(zero_epoch.validate(), Err(PackCommitError::Invalid(_))));

    let mut negative_epoch = request();
    negative_epoch.group_epoch = -1;
    assert!(matches!(negative_epoch.validate(), Err(PackCommitError::Invalid(_))));

    assert!(request().validate().is_ok());
}

#[test]
fn attempt_binding_and_event_evidence_are_fail_closed() {
    let mut unbound = pending_attempt(0, private0(), plan0(), proof0(), 1, 1);
    unbound.serving_bound = false;
    assert_ledger(evaluate(snapshot(wrapper(0, "pending"), vec![unbound]), &request()));

    let mut pending_with_event = pending_attempt(0, private0(), plan0(), proof0(), 1, 1);
    pending_with_event.event_id = Some(event1());
    assert_ledger(evaluate(snapshot(wrapper(0, "pending"), vec![pending_with_event]), &request()));

    let mut partial_tombstone = pending_attempt(0, private0(), plan0(), proof0(), 1, 1);
    partial_tombstone.tombstone_operation_id = Some(private0());
    assert_ledger(evaluate(snapshot(wrapper(0, "pending"), vec![partial_tombstone]), &request()));
}

#[test]
fn stored_wrapper_and_attempt_evidence_is_fail_closed() {
    let mut bad_wire = wrapper(0, "pending");
    bad_wire.wire_digest = "not-a-wire-digest".into();
    assert_ledger(evaluate(
        snapshot(bad_wire, vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]),
        &request(),
    ));

    let mut bad_backend = wrapper(0, "pending");
    bad_backend.backend_identity = "not-a-backend".into();
    assert_ledger(evaluate(
        snapshot(bad_backend, vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]),
        &request(),
    ));

    let mut bad_state = wrapper(0, "pending");
    bad_state.state = "unknown".into();
    assert_ledger(evaluate(
        snapshot(bad_state, vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]),
        &request(),
    ));

    let mut bad_plan = pending_attempt(0, private0(), plan0(), proof0(), 1, 1);
    bad_plan.plan_digest = "not-a-plan".into();
    assert_ledger(evaluate(snapshot(wrapper(0, "pending"), vec![bad_plan]), &request()));

    let mut bad_operation_state = pending_attempt(0, private0(), plan0(), proof0(), 1, 1);
    bad_operation_state.operation_state = Some("unknown".into());
    assert_ledger(evaluate(snapshot(wrapper(0, "pending"), vec![bad_operation_state]), &request()));
}

#[test]
fn snapshot_sql_is_one_read_only_statement_with_the_required_evidence() {
    let sql = SELECT_SNAPSHOT.to_ascii_lowercase();
    for table in [
        "ref_store_public_operations",
        "ref_store_private_attempts",
        "ref_store_operations",
        "ref_store_core_events",
        "ref_store_cancellations",
        "ref_store_core_gates",
        "ref_store_serving_repositories",
        "ref_store_core_protocol_repos",
        "cluster_authority",
    ] {
        assert!(sql.contains(table), "snapshot SQL is missing {table}");
    }
    assert!(sql.contains("rootyard_ref_store_attempt_has_binding"));
    for forbidden in [" insert ", " update ", " delete ", " for update", " for share", "pg_advisory", ";"] {
        assert!(!sql.contains(forbidden), "snapshot SQL contains forbidden {forbidden:?}");
    }
}
