use super::{
    AttemptFacts, SLOT_ONE_PROOF_DOMAIN, SlotOneProofFacts, SlotOneRotationRequest, StoredAttempt,
    checked_prospective_revision, checked_prospective_sequence, slot_one_proof_digest, slot_one_proof_fields,
    split_attempts, validate_attempt, validate_replay, validate_request, validate_retired, validate_retirement_at_gate,
    validate_slot_one_replay_evidence,
};
use crate::ref_store::{
    CommitMode, GitObjectFormat, IssuerLane, OperationState, RequestDigest,
    core::pack_commit::{PackCommitError, PackCommitRejectCode},
    pg::{
        public_attempt::{PublicAttemptRequest, RawWrapper},
        public_terminal::PublicAttemptRetirement,
    },
};
use serde_json::json;
use uuid::Uuid;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
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

fn private_zero() -> Uuid {
    id(7)
}

fn private_one() -> Uuid {
    id(8)
}

fn event_zero() -> Uuid {
    id(9)
}

fn event_one() -> Uuid {
    id(10)
}

fn plan_zero() -> RequestDigest {
    RequestDigest::from_bytes([0x21; 32])
}

fn proof_zero() -> RequestDigest {
    RequestDigest::from_bytes([0x22; 32])
}

fn plan_one() -> RequestDigest {
    RequestDigest::from_bytes([0x31; 32])
}

fn lane() -> IssuerLane {
    IssuerLane::new("slot-one").expect("valid lane")
}

fn public_request() -> PublicAttemptRequest {
    PublicAttemptRequest {
        repository_id: repo(),
        admission_owner_id: owner(),
        issuer_id: issuer(),
        public_id: public(),
        wire_digest: RequestDigest::from_bytes([0x11; 32]),
        request_mode: CommitMode::Atomic,
        backend_identity: "a".repeat(64),
        object_format: GitObjectFormat::Sha1,
        history_incarnation: history(),
        authority_epoch: 1,
        group_epoch: 2,
        restore_incarnation: restore(),
    }
}

fn retirement() -> PublicAttemptRetirement {
    PublicAttemptRetirement { event_id: event_zero(), event_revision: 3 }
}

fn rotation_request() -> SlotOneRotationRequest {
    SlotOneRotationRequest { public: public_request(), retirement: retirement() }
}

fn stored_attempt(slot: i16) -> StoredAttempt {
    let retired = slot == 0;
    let plan = if retired { plan_zero() } else { plan_one() };
    let proof = if retired { proof_zero() } else { RequestDigest::from_bytes([0x32; 32]) };
    StoredAttempt {
        slot,
        private_id: if retired { private_zero() } else { private_one() },
        plan_digest: plan.as_hex(),
        proof_digest: proof.as_hex(),
        base_revision: if retired { 2 } else { 3 },
        serving_bound: true,
        operation_issuer_id: Some(issuer()),
        operation_lane: Some(lane().as_str().to_owned()),
        operation_sequence: Some(if retired { 1 } else { 2 }),
        operation_request_digest: Some(plan.as_hex()),
        operation_state: Some(if retired { "rejected" } else { "pending" }.to_owned()),
        terminal_present: retired,
        event_id: retired.then_some(event_zero()),
        event_revision: retired.then_some(3),
        event_outcome_matches: retired,
        event_body_matches: retired,
        tombstone_present: false,
        tombstone_absent: true,
        tombstone_matches_lane: false,
        tombstone_exact_operation: false,
        revision_mismatch_rejection: retired,
    }
}

fn retired_facts() -> AttemptFacts {
    validate_attempt(stored_attempt(0), &public_request()).expect("valid retired facts")
}

fn proof_facts<'a>(
    request: &'a PublicAttemptRequest,
    retired: &'a AttemptFacts,
    current: &'a AttemptFacts,
) -> SlotOneProofFacts<'a> {
    SlotOneProofFacts {
        public: request,
        lane: &retired.lane,
        retired_private_id: retired.private_id,
        retired_event_id: retirement().event_id,
        retired_event_revision: retirement().event_revision,
        retired_plan_digest: retired.plan_digest,
        private_id: current.private_id,
        sequence: current.sequence,
        base_revision: current.base_revision,
        plan_digest: current.plan_digest,
    }
}

fn pending_facts(retired: &AttemptFacts) -> AttemptFacts {
    let request = public_request();
    let mut current = validate_attempt(stored_attempt(1), &request).expect("valid pending facts");
    current.proof_digest = slot_one_proof_digest(&proof_facts(&request, retired, &current));
    current
}

fn wrapper_json() -> serde_json::Value {
    json!({
        "repository_id": repo(),
        "public_id": public(),
        "admission_owner_id": owner(),
        "issuer_id": issuer(),
        "wire_digest": public_request().wire_digest.as_hex(),
        "request_mode": "atomic",
        "backend_identity": "a".repeat(64),
        "object_format": "sha1",
        "history_incarnation": history(),
        "authority_epoch": 1,
        "group_epoch": 2,
        "restore_incarnation": restore(),
        "current_slot": 1,
        "state": "pending",
        "event_id": null,
        "retired_event_id": event_zero(),
        "cancelled_private_id": null,
    })
}

fn expect_ledger<T>(result: Result<T, PackCommitError>, detail: &str) {
    match result {
        Err(PackCommitError::Rejected(rejection)) => {
            assert_eq!(rejection.code, PackCommitRejectCode::LedgerIntegrity);
            assert_eq!(rejection.detail, detail);
        }
        Err(other) => panic!("expected ledger integrity {detail}, got {other:?}"),
        Ok(_) => panic!("expected ledger integrity {detail}, got success"),
    }
}

#[test]
fn request_requires_a_non_nil_positive_retired_event() {
    let mut request = rotation_request();
    request.retirement.event_id = Uuid::nil();
    assert!(matches!(validate_request(&request), Err(PackCommitError::Invalid(_))));

    let mut request = rotation_request();
    request.retirement.event_revision = 0;
    assert!(matches!(validate_request(&request), Err(PackCommitError::Invalid(_))));

    validate_request(&rotation_request()).expect("valid rotation request");
}

#[test]
fn retired_attempt_must_be_the_selected_advanced_revision_mismatch() {
    let retired = retired_facts();
    validate_retired(&retired, &retirement()).expect("exact selected retirement");

    let mut wrong_event = retirement();
    wrong_event.event_id = event_one();
    expect_ledger(
        validate_retired(&retired, &wrong_event),
        "retired public attempt event differs from the selected retirement",
    );

    let mut wrong_revision = retirement();
    wrong_revision.event_revision = 4;
    expect_ledger(
        validate_retired(&retired, &wrong_revision),
        "retired public attempt event differs from the selected retirement",
    );

    let mut no_advance = retired;
    no_advance.base_revision = 3;
    expect_ledger(
        validate_retired(&no_advance, &retirement()),
        "retired public attempt did not observe an advanced gate",
    );

    let mut not_mismatch = retired_facts();
    not_mismatch.revision_mismatch_rejection = false;
    expect_ledger(
        validate_retired(&not_mismatch, &retirement()),
        "retired public attempt is not the exact revision-mismatch rejection",
    );

    let mut committed = retired_facts();
    committed.state = OperationState::Committed;
    expect_ledger(validate_retired(&committed, &retirement()), "retired public attempt is not a slot-zero rejection");
}

#[test]
fn current_gate_must_match_the_retired_event_and_advance_its_base() {
    let retired = retired_facts();
    validate_retirement_at_gate(&retired, &retirement(), 3).expect("current advanced gate");
    expect_ledger(
        validate_retirement_at_gate(&retired, &retirement(), 2),
        "slot one current gate revision did not advance past the retired base",
    );
    expect_ledger(
        validate_retirement_at_gate(&retired, &retirement(), 4),
        "slot one current gate revision differs from the retired event",
    );
}

#[test]
fn slot_one_proof_has_a_distinct_domain_and_binds_the_retirement() {
    let retired = retired_facts();
    let current = pending_facts(&retired);
    let request = public_request();
    let facts = proof_facts(&request, &retired, &current);
    let proof = slot_one_proof_digest(&facts);
    let fields = slot_one_proof_fields(&facts);
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let zero_domain = RequestDigest::of("ref-store-slot-zero-proof-v1", &parts);
    assert_ne!(proof, zero_domain, "slot one proof must not share the slot-zero proof domain");
    assert_eq!(SLOT_ONE_PROOF_DOMAIN, "ref-store-slot-one-proof-v1");

    let mut other_event = proof_facts(&request, &retired, &current);
    other_event.retired_event_id = event_one();
    assert_ne!(slot_one_proof_digest(&other_event), proof);

    let mut other_private = proof_facts(&request, &retired, &current);
    other_private.private_id = id(99);
    assert_ne!(slot_one_proof_digest(&other_private), proof);
}

#[test]
fn replay_requires_pending_slot_one_and_a_fresh_identity_plan_and_proof() {
    let retired = retired_facts();
    let current = pending_facts(&retired);
    let request = public_request();
    let wrapper: RawWrapper = serde_json::from_value(wrapper_json()).expect("valid wrapper evidence");

    validate_replay(&wrapper, &request, &retirement(), &retired, &current).expect("exact pending replay");

    let mut same_private = current.clone();
    same_private.private_id = retired.private_id;
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &same_private),
        "slot one replay reuses retired identity, plan or proof",
    );

    let mut same_plan = current.clone();
    same_plan.plan_digest = retired.plan_digest;
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &same_plan),
        "slot one replay reuses retired identity, plan or proof",
    );

    let mut same_proof = current.clone();
    same_proof.proof_digest = retired.proof_digest;
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &same_proof),
        "slot one replay reuses retired identity, plan or proof",
    );

    let mut wrong_base = current.clone();
    wrong_base.base_revision = 4;
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &wrong_base),
        "slot one replay base revision differs from the retired event",
    );

    let mut wrong_lane = current.clone();
    wrong_lane.lane = IssuerLane::new("another-lane").expect("valid lane");
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &wrong_lane),
        "slot one replay switched issuer lanes",
    );

    let mut terminal = current.clone();
    terminal.state = OperationState::Rejected;
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &terminal),
        "slot one replay current attempt is not pending slot one",
    );
}

#[test]
fn replay_evidence_validator_rejects_retired_or_duplicate_attempts() {
    let retired = retired_facts();
    let current = pending_facts(&retired);
    validate_slot_one_replay_evidence(&retired, &current, &public_request(), &retirement())
        .expect("exact slot-one replay evidence");

    let mut duplicate = current.clone();
    duplicate.private_id = retired.private_id;
    expect_ledger(
        validate_slot_one_replay_evidence(&retired, &duplicate, &public_request(), &retirement()),
        "slot one replay reuses retired identity, plan or proof",
    );
}

#[test]
fn attempt_split_never_accepts_a_third_attempt_or_duplicate_slot() {
    let (old, new) = split_attempts(vec![stored_attempt(0), stored_attempt(1)]).expect("two slots");
    assert_eq!(old.slot, 0);
    assert_eq!(new.expect("slot one").slot, 1);

    let mut third = stored_attempt(1);
    third.slot = 2;
    expect_ledger(
        split_attempts(vec![stored_attempt(0), third]),
        "public operation has an attempt outside slot zero or one",
    );

    expect_ledger(
        split_attempts(vec![stored_attempt(0), stored_attempt(1), stored_attempt(1)]),
        "public operation has multiple attempts in slot one",
    );

    expect_ledger(split_attempts(vec![stored_attempt(1)]), "public operation retired slot-zero attempt is missing");
}

#[test]
fn prospective_sequence_and_revision_are_checked() {
    assert_eq!(checked_prospective_sequence(4, 5).expect("next sequence"), 5);
    assert_eq!(checked_prospective_sequence(4, 9).expect("advanced sequence"), 9);
    expect_ledger(checked_prospective_sequence(4, 4), "slot one sequence does not advance the retired attempt");
    expect_ledger(checked_prospective_sequence(i64::MAX, i64::MAX), "slot one retired sequence cannot advance");
    expect_ledger(checked_prospective_sequence(0, 1), "slot one sequence is not positive");

    assert_eq!(checked_prospective_revision(4).expect("next revision"), 5);
    expect_ledger(checked_prospective_revision(i64::MAX), "slot one gate revision cannot advance");
    expect_ledger(checked_prospective_revision(0), "slot one base revision is not positive");
}

#[test]
fn source_keeps_the_reviewed_lock_and_write_order() {
    let source = include_str!("../slot_one.rs");
    let markers = [
        "tx.query_one(LOCK_PUBLIC",
        "lock_cluster_incarnation(tx).await",
        "LockedSequence::preview(",
        "LockedScope::lock(",
        "read_gate_in_tx(",
        "insert_slot_one_attempt(",
        "advance_sequence(",
        "insert_operation(",
        "bind_existing_serving_pending_in_tx",
        "UPDATE_WRAPPER,",
        "verify_public_operation(tx, &request.public).await?",
    ];
    let positions = markers.map(|marker| source.find(marker).unwrap_or_else(|| panic!("missing marker {marker}")));
    let mut sorted = positions;
    sorted.sort_unstable();
    assert_eq!(positions, sorted);

    assert!(source.contains("tx.savepoint(SLOT_ONE_SAVEPOINT)"));
    assert!(source.contains("nested.commit().await"));
    assert!(source.contains("nested.rollback().await"));
    assert!(source.contains("ROLLBACK TO SAVEPOINT"));
    assert!(source.contains("RELEASE SAVEPOINT"));
    assert!(!source.contains("tx.commit("));
    assert!(!source.contains("tx.rollback("));
    assert!(!source.contains("pool.get()"));
}

mod native;
