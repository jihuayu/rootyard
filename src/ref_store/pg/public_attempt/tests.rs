use super::{
    PublicAttemptLookup, PublicAttemptRequest, PublicOperationReadAuthorization, PublicOperationStatusLookup,
    PublicOperationStatusRequest, RawAttempt, RawSnapshot, RawWrapper, SELECT_SNAPSHOT, evaluate, evaluate_status,
    status_terminal::project_terminal,
};
use crate::ref_store::{
    CommitMode, CommitRejectCode, GitObjectFormat, OperationState, RefCommitResult, RefStoreError, RequestDigest,
    TerminalKind,
    core::pack_commit::{
        PackCommitError, PackCommitRejectCode, PackCommitTerminal, PackTerminalRegistration,
        receipt::PackTerminalRejection,
    },
};
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

fn status_request() -> PublicOperationStatusRequest {
    PublicOperationStatusRequest {
        repository_id: repo(),
        public_id: public(),
        authorization: PublicOperationReadAuthorization::LiveIssuer { issuer_id: issuer() },
    }
}

fn admin_status_request() -> PublicOperationStatusRequest {
    PublicOperationStatusRequest {
        repository_id: repo(),
        public_id: public(),
        authorization: PublicOperationReadAuthorization::RepositoryAdmin,
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
        terminal_present: false,
        terminal_cancelled_exact: false,
        event_id: None,
        event_revision: None,
        event_outcome_matches: false,
        event_body_matches: false,
        tombstone_present: false,
        tombstone_absent: true,
        tombstone_matches_lane: false,
        tombstone_exact_operation: false,
        revision_mismatch_rejection: false,
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
    attempt.operation_state = Some("rejected".into());
    attempt.terminal_present = true;
    attempt.event_id = Some(event0());
    attempt.event_revision = Some(2);
    attempt.event_outcome_matches = true;
    attempt.event_body_matches = true;
    attempt.revision_mismatch_rejection = true;
    attempt
}

fn committed_attempt() -> RawAttempt {
    let mut attempt = base_attempt(0, private0(), plan0(), proof0(), 1);
    attempt.operation_state = Some("committed".into());
    attempt.terminal_present = true;
    attempt.event_id = Some(event1());
    attempt.event_revision = Some(2);
    attempt.event_outcome_matches = true;
    attempt.event_body_matches = true;
    attempt
}

fn rejected_attempt() -> RawAttempt {
    let mut attempt = committed_attempt();
    attempt.operation_state = Some("rejected".into());
    attempt
}

fn cancelled_attempt() -> RawAttempt {
    let mut attempt = base_attempt(0, private0(), plan0(), proof0(), 1);
    attempt.operation_state = Some("cancelled".into());
    attempt.terminal_present = true;
    attempt.terminal_cancelled_exact = true;
    attempt.tombstone_present = true;
    attempt.tombstone_absent = false;
    attempt.tombstone_matches_lane = true;
    attempt.tombstone_exact_operation = true;
    attempt
}

fn snapshot(wrapper: RawWrapper, attempts: Vec<RawAttempt>) -> RawSnapshot {
    RawSnapshot {
        wrapper: Some(wrapper),
        attempts,
        private_occupied: false,
        legacy_operation: false,
        legacy_cancellation: false,
        realm_matches: true,
        status_terminal: None,
    }
}

fn empty_snapshot() -> RawSnapshot {
    RawSnapshot {
        wrapper: None,
        attempts: Vec::new(),
        private_occupied: false,
        legacy_operation: false,
        legacy_cancellation: false,
        realm_matches: true,
        status_terminal: None,
    }
}

fn pack_committed_terminal() -> PackCommitTerminal {
    PackCommitTerminal {
        kind: TerminalKind::Committed,
        repository_id: repo(),
        revision: 2,
        head_ref: Some("refs/heads/main".into()),
        mode: "pack_verified".into(),
        refs: vec![RefCommitResult::Applied {
            name: "refs/heads/main".into(),
            old_oid: Some("1".repeat(40)),
            new_oid: Some("2".repeat(40)),
        }],
        registrations: vec![PackTerminalRegistration {
            pack_id: id(11),
            registration_id: id(12),
            artifact_set_digest: "b".repeat(64),
        }],
        rejection: None,
    }
}

fn pack_rejected_terminal(code: PackCommitRejectCode, detail: &str) -> PackCommitTerminal {
    PackCommitTerminal {
        kind: TerminalKind::Rejected,
        repository_id: repo(),
        revision: 2,
        head_ref: Some("refs/heads/main".into()),
        mode: "pack_verified".into(),
        refs: vec![RefCommitResult::NotApplied {
            name: "refs/heads/main".into(),
            reason: CommitRejectCode::PolicyDenied,
        }],
        registrations: Vec::new(),
        rejection: Some(PackTerminalRejection { code: code.as_str().to_owned(), detail: detail.to_owned() }),
    }
}

fn terminal_value(terminal: &PackCommitTerminal) -> serde_json::Value {
    serde_json::to_value(terminal).expect("terminal serializes")
}

fn with_terminal(mut snapshot: RawSnapshot, terminal: serde_json::Value) -> RawSnapshot {
    snapshot.status_terminal = Some(terminal);
    snapshot
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

fn assert_status_ledger(result: Result<PublicOperationStatusLookup, PackCommitError>) {
    match result {
        Err(PackCommitError::Rejected(rejection)) => {
            assert_eq!(rejection.code, PackCommitRejectCode::LedgerIntegrity);
        }
        other => panic!("expected status ledger integrity, got {other:?}"),
    }
}

fn assert_projection_ledger(result: Result<Option<serde_json::Value>, PackCommitError>) {
    match result {
        Err(PackCommitError::Rejected(rejection)) => {
            assert_eq!(rejection.code, PackCommitRejectCode::LedgerIntegrity);
        }
        other => panic!("expected terminal projection ledger integrity, got {other:?}"),
    }
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

    let mut wrong_body = committed_attempt();
    wrong_body.event_body_matches = false;
    assert_ledger(evaluate(snapshot(wrapper(0, "committed"), vec![wrong_body]), &request()));

    let mut wrong_outcome = committed_attempt();
    wrong_outcome.event_outcome_matches = false;
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
    wrong_tombstone.tombstone_exact_operation = false;
    assert_ledger(evaluate(snapshot(wrapper(0, "cancelled"), vec![wrong_tombstone]), &request()));

    let mut wrong_lane_tombstone = cancelled_attempt();
    wrong_lane_tombstone.tombstone_matches_lane = false;
    assert_ledger(evaluate(snapshot(wrapper(0, "cancelled"), vec![wrong_lane_tombstone]), &request()));

    let mut wrong_terminal = cancelled_attempt();
    wrong_terminal.terminal_cancelled_exact = false;
    assert_ledger(evaluate(snapshot(wrapper(0, "cancelled"), vec![wrong_terminal]), &request()));

    let mut no_tombstone = cancelled_attempt();
    no_tombstone.tombstone_present = false;
    no_tombstone.tombstone_absent = true;
    no_tombstone.tombstone_matches_lane = false;
    no_tombstone.tombstone_exact_operation = false;
    assert_ledger(evaluate(snapshot(wrapper(0, "cancelled"), vec![no_tombstone]), &request()));
}

#[test]
fn cancelled_slot_one_binds_only_the_current_attempt() {
    let mut current = wrapper(1, "cancelled");
    current.cancelled_private_id = Some(private1());
    let mut cancelled = base_attempt(1, private1(), plan1(), proof1(), 2);
    cancelled.base_revision = 2;
    cancelled.operation_state = Some("cancelled".into());
    cancelled.terminal_present = true;
    cancelled.terminal_cancelled_exact = true;
    cancelled.tombstone_present = true;
    cancelled.tombstone_absent = false;
    cancelled.tombstone_matches_lane = true;
    cancelled.tombstone_exact_operation = true;

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
    let mut wrong_revision = retired_attempt();
    wrong_revision.event_revision = Some(1);
    assert_ledger(evaluate(
        snapshot(wrapper(1, "pending"), vec![wrong_revision, pending_attempt(1, private1(), plan1(), proof1(), 2, 2)]),
        &request(),
    ));

    let mut wrong_retirement = retired_attempt();
    wrong_retirement.revision_mismatch_rejection = false;
    assert_ledger(evaluate(
        snapshot(
            wrapper(1, "pending"),
            vec![wrong_retirement, pending_attempt(1, private1(), plan1(), proof1(), 2, 2)],
        ),
        &request(),
    ));

    let mut wrong_body = retired_attempt();
    wrong_body.event_body_matches = false;
    assert_ledger(evaluate(
        snapshot(wrapper(1, "pending"), vec![wrong_body, pending_attempt(1, private1(), plan1(), proof1(), 2, 2)]),
        &request(),
    ));

    let mut wrong_state = retired_attempt();
    wrong_state.operation_state = Some("committed".into());
    assert_ledger(evaluate(
        snapshot(wrapper(1, "pending"), vec![wrong_state, pending_attempt(1, private1(), plan1(), proof1(), 2, 2)]),
        &request(),
    ));
}

#[test]
fn stale_realm_is_refused() {
    let mut stale = snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]);
    stale.realm_matches = false;
    assert_ledger(evaluate(stale, &request()));
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
    partial_tombstone.tombstone_present = true;
    partial_tombstone.tombstone_absent = false;
    assert_ledger(evaluate(snapshot(wrapper(0, "pending"), vec![partial_tombstone]), &request()));

    let mut pending_terminal = pending_attempt(0, private0(), plan0(), proof0(), 1, 1);
    pending_terminal.terminal_present = true;
    assert_ledger(evaluate(snapshot(wrapper(0, "pending"), vec![pending_terminal]), &request()));
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
fn status_returns_only_the_current_public_state() {
    let pending = evaluate_status(
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]),
        &status_request(),
    )
    .expect("valid pending status");
    match pending {
        PublicOperationStatusLookup::Found(status) => {
            assert_eq!(status.public_id, public());
            assert_eq!(status.state, OperationState::Pending);
            assert!(status.terminal().is_none());
        }
        other => panic!("expected pending status, got {other:?}"),
    }

    let committed_terminal = pack_committed_terminal();
    let expected_committed = terminal_value(&committed_terminal);
    let committed = evaluate_status(
        with_terminal(snapshot(wrapper(0, "committed"), vec![committed_attempt()]), expected_committed.clone()),
        &status_request(),
    )
    .expect("valid committed status");
    match committed {
        PublicOperationStatusLookup::Found(status) => {
            assert_eq!(status.public_id, public());
            assert_eq!(status.state, OperationState::Committed);
            assert_eq!(status.terminal(), Some(&expected_committed));
        }
        other => panic!("expected committed status, got {other:?}"),
    }

    let rejected_terminal =
        pack_rejected_terminal(PackCommitRejectCode::RevisionMismatch, "admitted base was superseded");
    let expected_rejected = terminal_value(&rejected_terminal);
    let rejected = evaluate_status(
        with_terminal(snapshot(wrapper(0, "rejected"), vec![rejected_attempt()]), expected_rejected.clone()),
        &status_request(),
    )
    .expect("valid rejected status");
    match rejected {
        PublicOperationStatusLookup::Found(status) => {
            assert_eq!(status.state, OperationState::Rejected);
            assert_eq!(status.terminal(), Some(&expected_rejected));
        }
        other => panic!("expected rejected status, got {other:?}"),
    }

    let expected_cancelled = serde_json::json!({"state": "cancelled", "reason": "cancel_requested"});
    let cancelled = evaluate_status(
        with_terminal(snapshot(wrapper(0, "cancelled"), vec![cancelled_attempt()]), expected_cancelled.clone()),
        &status_request(),
    )
    .expect("valid cancelled status");
    match cancelled {
        PublicOperationStatusLookup::Found(status) => {
            assert_eq!(status.state, OperationState::Cancelled);
            assert_eq!(status.terminal(), Some(&expected_cancelled));
        }
        other => panic!("expected cancelled status, got {other:?}"),
    }
}

#[test]
fn status_requires_the_exact_live_issuer_or_a_caller_resolved_admin_policy() {
    let mut other_issuer = status_request();
    other_issuer.authorization = PublicOperationReadAuthorization::LiveIssuer { issuer_id: private1() };
    assert!(matches!(
        evaluate_status(
            snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]),
            &other_issuer,
        )
        .expect("data-free forbidden marker"),
        PublicOperationStatusLookup::Forbidden
    ));

    let admin = evaluate_status(
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]),
        &admin_status_request(),
    )
    .expect("caller-resolved admin policy");
    assert!(matches!(
        admin,
        PublicOperationStatusLookup::Found(status)
            if status.public_id == public() && status.state == OperationState::Pending
    ));
}

#[test]
fn status_markers_preserve_unknown_legacy_and_private_routes() {
    let mut private = empty_snapshot();
    private.private_occupied = true;
    private.legacy_operation = true;
    private.legacy_cancellation = true;
    assert!(matches!(
        evaluate_status(private, &status_request()).expect("private marker"),
        PublicOperationStatusLookup::PrivateIdentifier
    ));

    let mut legacy = empty_snapshot();
    legacy.legacy_operation = true;
    assert!(matches!(
        evaluate_status(legacy, &status_request()).expect("legacy marker"),
        PublicOperationStatusLookup::LegacyPath
    ));

    assert!(matches!(
        evaluate_status(empty_snapshot(), &status_request()).expect("unknown marker"),
        PublicOperationStatusLookup::Unknown
    ));

    let mut private_alias =
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]);
    private_alias.private_occupied = true;
    assert_status_ledger(evaluate_status(private_alias, &status_request()));
}

#[test]
fn status_reuses_terminal_event_attempt_and_realm_integrity() {
    let valid_terminal = terminal_value(&pack_committed_terminal());
    let mut wrong_body = committed_attempt();
    wrong_body.event_body_matches = false;
    assert_status_ledger(evaluate_status(
        with_terminal(snapshot(wrapper(0, "committed"), vec![wrong_body]), valid_terminal.clone()),
        &status_request(),
    ));

    let mut pending_with_terminal = pending_attempt(0, private0(), plan0(), proof0(), 1, 1);
    pending_with_terminal.operation_state = Some("committed".into());
    pending_with_terminal.terminal_present = true;
    pending_with_terminal.event_id = Some(event1());
    pending_with_terminal.event_revision = Some(2);
    pending_with_terminal.event_outcome_matches = true;
    pending_with_terminal.event_body_matches = true;
    assert_status_ledger(evaluate_status(
        with_terminal(snapshot(wrapper(0, "pending"), vec![pending_with_terminal]), valid_terminal),
        &status_request(),
    ));

    let mut stale = snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]);
    stale.realm_matches = false;
    assert_status_ledger(evaluate_status(stale, &status_request()));

    let mut unbound = pending_attempt(0, private0(), plan0(), proof0(), 1, 1);
    unbound.serving_bound = false;
    assert_status_ledger(evaluate_status(snapshot(wrapper(0, "pending"), vec![unbound]), &status_request()));
}

#[test]
fn status_checks_stored_immutable_digest_and_mode_without_a_push_request() {
    let attempt = || vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)];

    let mut bad_wire = wrapper(0, "pending");
    bad_wire.wire_digest = "not-a-wire-digest".into();
    assert_status_ledger(evaluate_status(snapshot(bad_wire, attempt()), &status_request()));

    let mut bad_mode = wrapper(0, "pending");
    bad_mode.request_mode = "unknown".into();
    assert_status_ledger(evaluate_status(snapshot(bad_mode, attempt()), &status_request()));

    let mut bad_backend = wrapper(0, "pending");
    bad_backend.backend_identity = "not-a-backend".into();
    assert_status_ledger(evaluate_status(snapshot(bad_backend, attempt()), &status_request()));

    let mut bad_state = wrapper(0, "pending");
    bad_state.state = "unknown".into();
    assert_status_ledger(evaluate_status(snapshot(bad_state, attempt()), &status_request()));
}

#[test]
fn status_request_shape_and_debug_are_bounded_and_redacted() {
    let mut nil_repo = status_request();
    nil_repo.repository_id = Uuid::nil();
    assert!(matches!(nil_repo.validate(), Err(PackCommitError::Invalid(_))));

    let mut nil_public = status_request();
    nil_public.public_id = Uuid::nil();
    assert!(matches!(nil_public.validate(), Err(PackCommitError::Invalid(_))));

    let mut nil_issuer = status_request();
    nil_issuer.authorization = PublicOperationReadAuthorization::LiveIssuer { issuer_id: Uuid::nil() };
    assert!(matches!(nil_issuer.validate(), Err(PackCommitError::Invalid(_))));
    assert!(admin_status_request().validate().is_ok());

    let found = evaluate_status(
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]),
        &status_request(),
    )
    .expect("valid pending status");
    let debug = format!("{found:?}");
    for secret in [
        public().to_string(),
        private0().to_string(),
        plan0().as_hex(),
        proof0().as_hex(),
        wire().as_hex(),
        event0().to_string(),
    ] {
        assert!(!debug.contains(secret.as_str()), "status Debug leaked {secret}");
    }
    assert!(debug.contains("Found"));
    assert!(debug.contains("Pending"));

    let request_debug = format!("{:?}", status_request());
    for secret in [repo().to_string(), public().to_string(), issuer().to_string()] {
        assert!(!request_debug.contains(secret.as_str()), "status request Debug leaked {secret}");
    }
    assert!(request_debug.contains("LiveIssuer"));
    assert_eq!(format!("{:?}", PublicOperationReadAuthorization::RepositoryAdmin), "RepositoryAdmin");
}

#[test]
fn status_terminal_projection_keeps_the_exact_typed_public_payload() {
    let terminal = pack_committed_terminal();
    let expected = terminal_value(&terminal);
    let projected =
        project_terminal(OperationState::Committed, repo(), GitObjectFormat::Sha1, Some(2), Some(&expected))
            .expect("valid committed projection")
            .expect("committed terminal is present");
    assert_eq!(projected, expected);
    let object = projected.as_object().expect("terminal object");
    assert_eq!(object.len(), 8);
    for field in ["kind", "repository_id", "revision", "head_ref", "mode", "refs", "registrations", "rejection"] {
        assert!(object.contains_key(field), "terminal is missing {field}");
    }
    let registration =
        object["registrations"].as_array().expect("registrations array")[0].as_object().expect("registration object");
    for field in ["pack_id", "registration_id", "artifact_set_digest"] {
        assert!(registration.contains_key(field), "registration is missing {field}");
    }
    assert_eq!(registration.len(), 3);

    let rejected = pack_rejected_terminal(PackCommitRejectCode::RevisionMismatch, "admitted base was superseded");
    let expected = terminal_value(&rejected);
    let projected = project_terminal(OperationState::Rejected, repo(), GitObjectFormat::Sha1, Some(2), Some(&expected))
        .expect("valid rejected projection")
        .expect("rejected terminal is present");
    assert_eq!(projected, expected);
}

#[test]
fn status_terminal_projection_fails_closed_on_untyped_or_mismatched_payloads() {
    let expected = terminal_value(&pack_committed_terminal());
    assert_projection_ledger(project_terminal(
        OperationState::Pending,
        repo(),
        GitObjectFormat::Sha1,
        None,
        Some(&expected),
    ));
    assert_projection_ledger(project_terminal(
        OperationState::Cancelled,
        repo(),
        GitObjectFormat::Sha1,
        None,
        Some(&serde_json::json!({"state": "cancelled", "reason": "cancel_before_register"})),
    ));

    let mut extra = expected.clone();
    extra.as_object_mut().expect("terminal object").insert("wire_digest".into(), serde_json::json!("leaked"));
    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&extra),
    ));

    let mut missing = expected.clone();
    missing.as_object_mut().expect("terminal object").remove("mode");
    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&missing),
    ));

    let mut wrong_repo = expected.clone();
    wrong_repo["repository_id"] = serde_json::json!(id(99));
    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&wrong_repo),
    ));

    let mut wrong_revision = expected.clone();
    wrong_revision["revision"] = serde_json::json!(3);
    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&wrong_revision),
    ));

    let mut wrong_kind = expected.clone();
    wrong_kind["kind"] = serde_json::json!("rejected");
    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&wrong_kind),
    ));

    let mut non_applied = expected.clone();
    non_applied["refs"] = serde_json::json!([{
        "outcome": "not_applied",
        "name": "refs/heads/main",
        "reason": "policy_denied"
    }]);
    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&non_applied),
    ));

    let mut bad_head = expected.clone();
    bad_head["head_ref"] = serde_json::json!("not-a-ref");
    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&bad_head),
    ));

    let mut bad_oid = expected.clone();
    bad_oid["refs"][0]["new_oid"] = serde_json::json!("0".repeat(40));
    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&bad_oid),
    ));

    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&serde_json::json!([1, 2])),
    ));
}

#[test]
fn status_terminal_projection_validates_rejection_paths_and_registrations() {
    for terminal in [
        pack_rejected_terminal(PackCommitRejectCode::RevisionMismatch, "admitted base was superseded"),
        pack_rejected_terminal(PackCommitRejectCode::NoRefApplied, "no ref accepted"),
        pack_rejected_terminal(PackCommitRejectCode::DecisionRejected, "policy_changed"),
    ] {
        let expected = terminal_value(&terminal);
        let projected =
            project_terminal(OperationState::Rejected, repo(), GitObjectFormat::Sha1, Some(2), Some(&expected))
                .expect("accepted rejection producer path")
                .expect("rejected terminal is present");
        assert_eq!(projected, expected);
    }

    let unknown_detail = pack_rejected_terminal(PackCommitRejectCode::DecisionRejected, "caller supplied text");
    let unknown_detail = terminal_value(&unknown_detail);
    assert_projection_ledger(project_terminal(
        OperationState::Rejected,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&unknown_detail),
    ));

    let mut with_registration = pack_rejected_terminal(PackCommitRejectCode::NoRefApplied, "no ref accepted");
    with_registration.registrations = pack_committed_terminal().registrations;
    let with_registration = terminal_value(&with_registration);
    assert_projection_ledger(project_terminal(
        OperationState::Rejected,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&with_registration),
    ));

    let mut bad_registration = pack_committed_terminal();
    bad_registration.registrations[0].artifact_set_digest = "not-a-digest".into();
    let bad_registration = terminal_value(&bad_registration);
    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&bad_registration),
    ));
}

#[test]
fn status_terminal_projection_uses_the_compact_64k_bound() {
    let mut dense = pack_committed_terminal();
    dense.refs = (0..80)
        .map(|index| RefCommitResult::Applied {
            name: format!("refs/heads/{index:02}-{}", "n".repeat(300)),
            old_oid: Some("1".repeat(40)),
            new_oid: Some("2".repeat(40)),
        })
        .collect();
    dense.registrations.clear();
    let dense = terminal_value(&dense);
    assert!(serde_json::to_vec(&dense).expect("compact terminal").len() < 64 * 1024);
    assert!(project_terminal(OperationState::Committed, repo(), GitObjectFormat::Sha1, Some(2), Some(&dense)).is_ok());

    let oversized = serde_json::json!({"body": "x".repeat(65 * 1024)});
    assert_projection_ledger(project_terminal(
        OperationState::Committed,
        repo(),
        GitObjectFormat::Sha1,
        Some(2),
        Some(&oversized),
    ));
}

#[test]
fn status_terminal_debug_redacts_the_private_view() {
    let terminal = pack_committed_terminal();
    let expected = terminal_value(&terminal);
    let found = evaluate_status(
        with_terminal(snapshot(wrapper(0, "committed"), vec![committed_attempt()]), expected),
        &status_request(),
    )
    .expect("valid committed status");
    let debug = format!("{found:?}");
    for secret in [
        "refs/heads/main".to_owned(),
        terminal.registrations[0].pack_id.to_string(),
        terminal.registrations[0].registration_id.to_string(),
        terminal.registrations[0].artifact_set_digest.clone(),
        public().to_string(),
        private0().to_string(),
        wire().as_hex(),
    ] {
        assert!(!debug.contains(secret.as_str()), "status Debug leaked {secret}");
    }
    assert!(debug.contains("Found"));
    assert!(debug.contains("Committed"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn debug_output_is_redacted() {
    let lookup = evaluate(
        snapshot(wrapper(0, "pending"), vec![pending_attempt(0, private0(), plan0(), proof0(), 1, 1)]),
        &request(),
    )
    .expect("valid pending lookup");
    let lookup_debug = format!("{lookup:?}");
    for secret in [
        public().to_string(),
        private0().to_string(),
        plan0().as_hex(),
        proof0().as_hex(),
        wire().as_hex(),
        event0().to_string(),
    ] {
        assert!(!lookup_debug.contains(secret.as_str()), "lookup Debug leaked {secret}");
    }
    assert!(lookup_debug.contains("Pending"));
    assert!(lookup_debug.contains("slot: 0"));

    let request_debug = format!("{:?}", request());
    for secret in [
        repo().to_string(),
        public().to_string(),
        owner().to_string(),
        issuer().to_string(),
        history().to_string(),
        restore().to_string(),
        wire().as_hex(),
        backend(),
    ] {
        assert!(!request_debug.contains(secret.as_str()), "request Debug leaked {secret}");
    }
    assert!(request_debug.contains("Atomic"));
}

#[test]
fn snapshot_sql_is_one_read_only_statement_with_finite_evidence() {
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
        "repositories",
    ] {
        assert!(sql.contains(table), "snapshot SQL is missing {table}");
    }
    assert!(sql.contains("rootyard_ref_store_attempt_has_binding"));
    for evidence in [
        "terminal_present",
        "terminal_cancelled_exact",
        "event_outcome_matches",
        "event_body_matches",
        "revision_mismatch_rejection",
        "tombstone_present",
        "tombstone_absent",
        "tombstone_matches_lane",
        "tombstone_exact_operation",
        "realm_matches",
    ] {
        assert!(sql.contains(evidence), "snapshot SQL is missing {evidence}");
    }
    for realm in ["r.archived_at", "s.backend_identity", "p.decision_required", "c.incarnation"] {
        assert!(sql.contains(realm), "snapshot SQL is missing realm evidence {realm}");
    }
    for payload in ["operation_terminal_result", "event_payload", "tombstone_request_digest"] {
        assert!(!sql.contains(payload), "snapshot SQL still projects payload column {payload}");
    }
    for forbidden in [" insert ", " update ", " delete ", " for update", " for share", "pg_advisory", ";"] {
        assert!(!sql.contains(forbidden), "snapshot SQL contains forbidden {forbidden:?}");
    }
}
