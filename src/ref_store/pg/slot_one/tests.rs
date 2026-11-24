use super::{
    AttemptFacts, SLOT_ONE_PROOF_DOMAIN, SlotOneProofFacts, SlotOneRotationRequest, StoredAttempt,
    checked_prospective_revision, checked_prospective_sequence, recompute_slot_one_proof, recompute_slot_two_proof,
    slot_one_proof_digest, slot_one_proof_fields, validate_attempt, validate_history, validate_replay,
    validate_request, validate_retired, validate_retirement_at_gate, validate_slot_one_replay_evidence,
};
use crate::ref_store::{
    CommitMode, GitObjectFormat, IssuerLane, OperationState, RequestDigest,
    core::pack_commit::{PackCommitError, PackCommitRejectCode},
    pg::{
        public_attempt::{PublicAttempt, PublicAttemptRequest, RawWrapper},
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
        retired_event_id: None,
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

fn public_attempt(facts: &AttemptFacts) -> PublicAttempt {
    PublicAttempt {
        slot: facts.slot,
        private_id: facts.private_id,
        plan_digest: facts.plan_digest,
        proof_digest: facts.proof_digest,
        base_revision: facts.base_revision,
        lane: facts.lane.clone(),
        sequence: facts.sequence,
        state: facts.state,
        event_id: facts.event_id,
        event_revision: facts.event_revision,
    }
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
    expect_ledger(validate_retired(&committed, &retirement()), "retired public attempt is not a retryable predecessor");
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

    validate_replay(&wrapper, &request, &retirement(), &retired, &current, None).expect("exact pending replay");

    let mut same_private = current.clone();
    same_private.private_id = retired.private_id;
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &same_private, None),
        "slot one replay reuses retired identity, plan or proof",
    );

    let mut same_plan = current.clone();
    same_plan.plan_digest = retired.plan_digest;
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &same_plan, None),
        "slot one replay reuses retired identity, plan or proof",
    );

    let mut same_proof = current.clone();
    same_proof.proof_digest = retired.proof_digest;
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &same_proof, None),
        "slot one replay reuses retired identity, plan or proof",
    );

    let mut wrong_base = current.clone();
    wrong_base.base_revision = 4;
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &wrong_base, None),
        "slot one replay base revision differs from the retired event",
    );

    let mut wrong_lane = current.clone();
    wrong_lane.lane = IssuerLane::new("another-lane").expect("valid lane");
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &wrong_lane, None),
        "slot one replay switched issuer lanes",
    );

    let mut terminal = current.clone();
    terminal.state = OperationState::Rejected;
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &retired, &terminal, None),
        "slot one replay current attempt is not pending slot one",
    );
}

#[test]
fn recomputed_slot_one_proof_enforces_lane_sequence_base_and_terminal_invariants() {
    let retired = retired_facts();
    let current = pending_facts(&retired);
    let request = public_request();
    let retired_public = public_attempt(&retired);
    let current_public = public_attempt(&current);

    let proof = recompute_slot_one_proof(&request, &retired_public, &current_public).expect("exact proof");
    assert_eq!(proof, current.proof_digest);

    // A legitimate terminal slot-one replay still has to recompute the exact
    // rotation proof; its state/event are outside the proof fields.
    let mut terminal = current_public.clone();
    terminal.state = OperationState::Rejected;
    terminal.event_id = Some(event_one());
    terminal.event_revision = Some(4);
    assert_eq!(recompute_slot_one_proof(&request, &retired_public, &terminal).expect("terminal proof"), proof);

    let mut wrong_lane = current_public.clone();
    wrong_lane.lane = IssuerLane::new("another-lane").expect("valid lane");
    expect_ledger(
        recompute_slot_one_proof(&request, &retired_public, &wrong_lane),
        "slot one replay switched issuer lanes",
    );

    let mut stale_sequence = current_public.clone();
    stale_sequence.sequence = retired_public.sequence;
    expect_ledger(
        recompute_slot_one_proof(&request, &retired_public, &stale_sequence),
        "slot one sequence does not advance the retired attempt",
    );

    let mut overflowed_sequence_retired = retired_public.clone();
    overflowed_sequence_retired.sequence = i64::MAX;
    let mut overflowed_sequence_current = current_public.clone();
    overflowed_sequence_current.sequence = i64::MAX;
    expect_ledger(
        recompute_slot_one_proof(&request, &overflowed_sequence_retired, &overflowed_sequence_current),
        "slot one retired sequence cannot advance",
    );

    let mut wrong_base = current_public.clone();
    wrong_base.base_revision = 4;
    expect_ledger(
        recompute_slot_one_proof(&request, &retired_public, &wrong_base),
        "slot one replay base revision differs from the retired event",
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
fn history_requires_contiguous_slots_and_exact_retirement_links() {
    let request = public_request();
    let mut zero = stored_attempt(0);
    let one = stored_attempt(1);
    assert_eq!(validate_history(0, vec![zero.clone()], &request).expect("single attempt")[0].slot, 0);
    expect_ledger(
        validate_history(1, vec![zero.clone(), one.clone()], &request),
        "public operation prior attempt retirement is missing",
    );
    zero.retired_event_id = Some(event_one());
    expect_ledger(
        validate_history(1, vec![zero.clone(), one.clone()], &request),
        "retired public attempt event differs from the selected retirement",
    );
    zero.retired_event_id = Some(event_zero());
    assert_eq!(validate_history(1, vec![zero.clone(), one.clone()], &request).expect("two slots")[1].slot, 1);

    let mut third = one.clone();
    third.slot = 2;
    expect_ledger(
        validate_history(1, vec![zero.clone(), third], &request),
        "public operation attempt history is not a contiguous prefix",
    );
    expect_ledger(
        validate_history(2, vec![zero, one.clone(), one.clone()], &request),
        "public operation prior attempt retirement is missing",
    );
    expect_ledger(
        validate_history(2, vec![one], &request),
        "public operation attempt inventory does not match its current slot",
    );
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
        "\n        INSERT_RETIREMENT,",
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

#[test]
fn preserved_slot_one_v1_wire_vector() {
    let request = public_request();
    let zero = retired_facts();
    let one = pending_facts(&zero);
    let facts = proof_facts(&request, &zero, &one);
    let fields = slot_one_proof_fields(&facts);

    let mut bytes = b"rootyard-ref-store-request-v1\0".to_vec();
    for field in std::iter::once(SLOT_ONE_PROOF_DOMAIN.as_bytes()).chain(fields.iter().map(Vec::as_slice)) {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    let expected_bytes = include_str!("slot_one_proof_v1_fixture.hex").trim();
    assert_eq!(bytes.len(), 595);
    assert_eq!(hex::encode(bytes), expected_bytes);
    assert_eq!(
        slot_one_proof_digest(&facts).as_hex(),
        "1f7f9c6e1c529900b3e33d2076b39202a06a20a337f7dad71d85c602420bf590"
    );
    assert_eq!(
        recompute_slot_one_proof(&request, &public_attempt(&zero), &public_attempt(&one)).unwrap(),
        slot_one_proof_digest(&facts)
    );
}

fn experimental_slot_two_v1_fields(
    request: &PublicAttemptRequest,
    predecessors: [&AttemptFacts; 2],
    current: &AttemptFacts,
) -> Vec<Vec<u8>> {
    let mut fields = vec![
        request.repository_id.as_bytes().to_vec(),
        request.public_id.as_bytes().to_vec(),
        request.issuer_id.as_bytes().to_vec(),
        request.admission_owner_id.as_bytes().to_vec(),
        current.lane.as_str().as_bytes().to_vec(),
        request.wire_digest.as_bytes().to_vec(),
        request.backend_identity.as_bytes().to_vec(),
        request.object_format.as_str().as_bytes().to_vec(),
        request.history_incarnation.as_bytes().to_vec(),
        request.authority_epoch.to_be_bytes().to_vec(),
        request.group_epoch.to_be_bytes().to_vec(),
        request.restore_incarnation.as_bytes().to_vec(),
        request.request_mode.as_str().as_bytes().to_vec(),
    ];
    for predecessor in predecessors {
        fields.extend([
            predecessor.slot.to_be_bytes().to_vec(),
            predecessor.private_id.as_bytes().to_vec(),
            predecessor.sequence.to_be_bytes().to_vec(),
            predecessor.base_revision.to_be_bytes().to_vec(),
            predecessor.event_id.unwrap().as_bytes().to_vec(),
            predecessor.event_revision.unwrap().to_be_bytes().to_vec(),
            predecessor.plan_digest.as_bytes().to_vec(),
            predecessor.proof_digest.as_bytes().to_vec(),
        ]);
    }
    fields.extend([
        current.slot.to_be_bytes().to_vec(),
        current.private_id.as_bytes().to_vec(),
        current.sequence.to_be_bytes().to_vec(),
        current.base_revision.to_be_bytes().to_vec(),
        current.plan_digest.as_bytes().to_vec(),
    ]);
    fields
}

fn experimental_slot_two_v1_digest(
    request: &PublicAttemptRequest,
    predecessors: [&AttemptFacts; 2],
    current: &AttemptFacts,
) -> RequestDigest {
    // This codec is a qualification fixture. The SQL contract stores opaque
    // digests and does not assign a production slot-two codec version.
    let fields = experimental_slot_two_v1_fields(request, predecessors, current);
    let fields = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("ref-store-slot-two-proof-v1", &fields)
}

#[test]
fn experimental_slot_two_v1_binds_ordered_retirements_wire_and_current() {
    let request = public_request();
    let zero = retired_facts();
    let mut one = pending_facts(&zero);
    one.state = OperationState::Rejected;
    one.event_id = Some(event_one());
    one.event_revision = Some(4);
    one.revision_mismatch_rejection = true;
    let two = AttemptFacts {
        slot: 2,
        private_id: id(11),
        plan_digest: RequestDigest::from_bytes([0x41; 32]),
        proof_digest: RequestDigest::from_bytes([0x42; 32]),
        base_revision: 4,
        lane: lane(),
        sequence: 4, // The database requires strictly increasing, not consecutive, sequences.
        state: OperationState::Pending,
        event_id: None,
        event_revision: None,
        revision_mismatch_rejection: false,
    };
    let original_slot_one = one.proof_digest;
    let expected = experimental_slot_two_v1_digest(&request, [&zero, &one], &two);
    assert_eq!(expected.as_hex(), "b3cf45c3418253089791084f1758e39ff1bbd292235838e7fd330f79af4ba82f");
    assert_ne!(expected, original_slot_one);
    assert_eq!(
        recompute_slot_two_proof(&request, &public_attempt(&zero), &public_attempt(&one), &public_attempt(&two))
            .unwrap(),
        expected,
    );

    let mut stored_two = two.clone();
    stored_two.proof_digest = expected;
    let mut wrapper = wrapper_json();
    wrapper["current_slot"] = json!(2);
    let wrapper: RawWrapper = serde_json::from_value(wrapper).expect("valid slot-two wrapper");
    let retirement_two = PublicAttemptRetirement { event_id: event_one(), event_revision: 4 };
    let receipt = validate_replay(&wrapper, &request, &retirement_two, &one, &stored_two, Some(&zero))
        .expect("replay of the newest rotation");
    assert_eq!(receipt.slot, 2);
    assert!(receipt.replayed);
    expect_ledger(
        validate_replay(&wrapper, &request, &retirement(), &one, &stored_two, Some(&zero)),
        "retired public attempt event differs from the selected retirement",
    );

    let mut forged_zero = zero.clone();
    forged_zero.event_id = Some(id(19));
    assert_ne!(expected, experimental_slot_two_v1_digest(&request, [&forged_zero, &one], &two));
    forged_zero.event_id = zero.event_id;
    forged_zero.proof_digest = RequestDigest::from_bytes([0x23; 32]);
    assert_ne!(expected, experimental_slot_two_v1_digest(&request, [&forged_zero, &one], &two));

    let mut forged_one = one.clone();
    forged_one.event_revision = Some(5);
    assert_ne!(expected, experimental_slot_two_v1_digest(&request, [&zero, &forged_one], &two));
    forged_one.event_revision = one.event_revision;
    forged_one.proof_digest = RequestDigest::from_bytes([0x33; 32]);
    assert_ne!(expected, experimental_slot_two_v1_digest(&request, [&zero, &forged_one], &two));

    let mut other_wire = request.clone();
    other_wire.wire_digest = RequestDigest::from_bytes([0x12; 32]);
    assert_ne!(expected, experimental_slot_two_v1_digest(&other_wire, [&zero, &one], &two));

    let mut forged_two = two.clone();
    forged_two.private_id = id(20);
    assert_ne!(expected, experimental_slot_two_v1_digest(&request, [&zero, &one], &forged_two));
    forged_two.private_id = two.private_id;
    forged_two.plan_digest = RequestDigest::from_bytes([0x43; 32]);
    assert_ne!(expected, experimental_slot_two_v1_digest(&request, [&zero, &one], &forged_two));
    assert_ne!(expected, experimental_slot_two_v1_digest(&request, [&one, &zero], &two));

    assert_eq!(
        recompute_slot_one_proof(&request, &public_attempt(&zero), &public_attempt(&one)).unwrap(),
        original_slot_one
    );
}
