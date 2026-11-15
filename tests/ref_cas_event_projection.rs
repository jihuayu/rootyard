//! Deterministic and PostgreSQL-backed acceptance suite for Ref-CAS Git event
//! replay, PG projection, reliable jobs/webhooks, and truncation closures (#117).

#[path = "ref_cas_projection_support/pg_cases.rs"]
mod pg_cases;
#[path = "ref_cas_projection_support/sm_cases.rs"]
mod sm_cases;

use rootyard::ref_store::core::state_machine::{
    AppliedLogId, CommitRefsCommand, InitializeGateCommand, RefCasCommand, RefCasStateMachine, RepositoryLane,
    SmPackMode, WireCommitRefsRequest, WireGateInit,
};
use rootyard::ref_store::projector::{
    InMemoryProjectionLedger, InMemorySmEventSource, ProjectionError, ProjectionJobKind, ProjectionRealm,
    SimulatedFault, SingleEventOutcome, derive_job_key, derive_operation_event_id, derive_ref_event_id,
};
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName,
    RefPrecondition, RefTarget, RefUpdate,
};
use std::collections::BTreeMap;
use uuid::Uuid;

fn lane() -> IssuerLane {
    IssuerLane::new("projector-test").expect("valid lane")
}

pub(crate) fn oid(byte: u8) -> GitOid {
    GitOid::Sha256([byte; 32])
}

fn ref_name(raw: &str) -> RefName {
    RefName::new(raw).expect("valid ref")
}

pub(crate) fn make_request(
    scope: (Uuid, Uuid, Uuid, Uuid),
    seq: i64,
    op_id: Uuid,
    expected_rev: i64,
    updates: Vec<(&str, Option<GitOid>, Option<GitOid>)>,
) -> CommitRefsRequest {
    let (repo, tenant, issuer, history) = scope;
    let refs = updates
        .into_iter()
        .map(|(name, old, new)| {
            let pre = match old {
                Some(o) => RefPrecondition::Present(o),
                None => RefPrecondition::Absent,
            };
            let tgt = match new {
                Some(n) => RefTarget::Oid(n),
                None => RefTarget::Delete,
            };
            RefUpdate::new(ref_name(name), pre, tgt)
        })
        .collect();
    CommitRefsRequest::new(
        repo,
        tenant,
        issuer,
        lane(),
        seq,
        op_id,
        GitObjectFormat::Sha256,
        history,
        1,
        1,
        expected_rev,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        refs,
    )
    .expect("valid commit request")
}

pub(crate) fn init_sm(repo: Uuid, tenant: Uuid, history: Uuid) -> RefCasStateMachine {
    let mut sm = RefCasStateMachine::new();
    let gate = CoreGateInit::new(
        repo,
        tenant,
        GitObjectFormat::Sha256,
        history,
        1,
        1,
        RefName::branch("refs/heads/main").unwrap(),
    )
    .unwrap();
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&gate),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            authz_floor: 1,
        }),
    )
    .unwrap();
    sm
}

pub(crate) fn apply_commit(sm: &mut RefCasStateMachine, term: u64, index: u64, req: CommitRefsRequest, tick: u64) {
    sm.apply(
        AppliedLogId { term, index },
        RefCasCommand::CommitRefs(CommitRefsCommand {
            request: WireCommitRefsRequest::from(&req),
            decision_id: None,
            required_holds: vec![],
            policy_rejects: BTreeMap::new(),
            logical_tick: tick,
        }),
    )
    .expect("state machine apply succeeds");
}

#[test]
fn deterministic_identity_and_rejected_commit_projection() {
    let repo = Uuid::from_u128(1);
    let tenant = Uuid::from_u128(2);
    let issuer = Uuid::from_u128(3);
    let history = Uuid::from_u128(0xAA);
    let realm = ProjectionRealm::new(history, 42, 1).unwrap();
    let realm_epoch2 = ProjectionRealm::new(history, 42, 2).unwrap();

    let op1 = Uuid::from_u128(101);
    let op2 = Uuid::from_u128(102);

    let id_a = derive_operation_event_id(&realm, 2, op1, repo).unwrap();
    let id_b = derive_operation_event_id(&realm, 2, op1, repo).unwrap();
    let id_epoch2 = derive_operation_event_id(&realm_epoch2, 2, op1, repo).unwrap();
    assert_eq!(id_a, id_b);
    assert_ne!(id_a, id_epoch2);
    assert_ne!(
        derive_ref_event_id(&id_a, 1, "refs/heads/main").unwrap(),
        derive_ref_event_id(&id_a, 1, "refs/heads/other").unwrap()
    );
    assert_eq!(
        derive_job_key(&id_a, ProjectionJobKind::CiSync, "ci:2").unwrap(),
        derive_job_key(&id_a, ProjectionJobKind::CiSync, "ci:2").unwrap()
    );

    let mut sm = init_sm(repo, tenant, history);
    // Expected revision 99 fails CAS cleanly and emits a Rejected terminal event.
    apply_commit(
        &mut sm,
        1,
        2,
        make_request((repo, tenant, issuer, history), 1, op1, 99, vec![("refs/heads/main", None, Some(oid(1)))]),
        100,
    );
    // Valid commit at revision 1 emits Committed terminal event.
    apply_commit(
        &mut sm,
        1,
        3,
        make_request((repo, tenant, issuer, history), 2, op2, 1, vec![("refs/heads/main", None, Some(oid(2)))]),
        101,
    );

    let source = InMemorySmEventSource::from_state_machine(&sm, realm, Some(tenant), None, None).unwrap();
    assert_eq!(source.events.len(), 2);

    let mut ledger = InMemoryProjectionLedger::default();
    let hook = Uuid::from_u128(999);
    ledger.register_push_webhook(repo, tenant, hook);

    let out1 = ledger.apply_event_with_fault(&source.events[0], None).unwrap();
    assert!(matches!(
        out1,
        SingleEventOutcome::Applied { projected_refs: 0, enqueued_webhooks: 0, enqueued_jobs: 0, .. }
    ));
    assert!(ledger.refs.is_empty());

    let out2 = ledger.apply_event_with_fault(&source.events[1], None).unwrap();
    assert!(matches!(
        out2,
        SingleEventOutcome::Applied { projected_refs: 1, enqueued_webhooks: 1, enqueued_jobs: 2, .. }
    ));
    assert_eq!(ledger.refs.get(&(repo, "refs/heads/main".into())).unwrap().oid, Some(oid(2).as_hex()));
}

#[test]
fn single_tx_pre_commit_and_post_commit_crash_replay() {
    let repo = Uuid::from_u128(11);
    let tenant = Uuid::from_u128(12);
    let issuer = Uuid::from_u128(13);
    let history = Uuid::from_u128(0xBB);
    let realm = ProjectionRealm::new(history, 5, 1).unwrap();

    let mut sm = init_sm(repo, tenant, history);
    apply_commit(
        &mut sm,
        1,
        2,
        make_request(
            (repo, tenant, issuer, history),
            1,
            Uuid::from_u128(201),
            1,
            vec![("refs/heads/main", None, Some(oid(5)))],
        ),
        100,
    );
    let source = InMemorySmEventSource::from_state_machine(&sm, realm, Some(tenant), None, None).unwrap();

    let mut ledger = InMemoryProjectionLedger::default();
    let hook = Uuid::from_u128(500);
    ledger.register_push_webhook(repo, tenant, hook);

    // 1. Pre-commit crash leaves all effects, webhooks, jobs, and cursor untouched.
    assert!(ledger.apply_event_with_fault(&source.events[0], Some(SimulatedFault::BeforeCommit)).is_err());
    assert!(ledger.cursor_for(&realm).is_none());
    assert!(ledger.webhook_deliveries.is_empty());
    assert!(ledger.jobs.is_empty());
    assert!(ledger.refs.is_empty());

    // 2. Post-commit disconnect persists once, and retry does not duplicate side effects.
    assert!(ledger.apply_event_with_fault(&source.events[0], Some(SimulatedFault::AfterCommitBeforeAck)).is_err());
    assert_eq!(ledger.cursor_for(&realm).unwrap().applied_event_seq, 1);
    assert_eq!(ledger.webhook_deliveries.len(), 1);
    assert_eq!(ledger.jobs.len(), 2);

    let replay = ledger.apply_event_with_fault(&source.events[0], None).unwrap();
    assert!(matches!(replay, SingleEventOutcome::DuplicateSkipped { .. }));
    assert_eq!(ledger.webhook_deliveries.len(), 1);
    assert_eq!(ledger.jobs.len(), 2);
}

#[test]
fn out_of_order_gap_refused_and_stale_replay_idempotent() {
    let repo = Uuid::from_u128(21);
    let tenant = Uuid::from_u128(22);
    let issuer = Uuid::from_u128(23);
    let history = Uuid::from_u128(0xCC);
    let realm = ProjectionRealm::new(history, 8, 1).unwrap();

    let mut sm = init_sm(repo, tenant, history);
    apply_commit(
        &mut sm,
        1,
        2,
        make_request(
            (repo, tenant, issuer, history),
            1,
            Uuid::from_u128(301),
            1,
            vec![("refs/heads/main", None, Some(oid(1)))],
        ),
        10,
    );
    apply_commit(
        &mut sm,
        1,
        3,
        make_request(
            (repo, tenant, issuer, history),
            2,
            Uuid::from_u128(302),
            2,
            vec![("refs/heads/main", Some(oid(1)), Some(oid(2)))],
        ),
        11,
    );
    apply_commit(
        &mut sm,
        1,
        4,
        make_request(
            (repo, tenant, issuer, history),
            3,
            Uuid::from_u128(303),
            3,
            vec![("refs/heads/main", Some(oid(2)), Some(oid(3)))],
        ),
        12,
    );

    let source = InMemorySmEventSource::from_state_machine(&sm, realm, Some(tenant), None, None).unwrap();
    let mut ledger = InMemoryProjectionLedger::default();
    ledger.register_push_webhook(repo, tenant, Uuid::from_u128(900));

    ledger.apply_event_with_fault(&source.events[0], None).unwrap();
    let gap = ledger.apply_event_with_fault(&source.events[2], None).unwrap_err();
    assert!(matches!(gap, ProjectionError::SequenceGap { expected_min_event_seq: 2, got_event_seq: 3 }));
    assert_eq!(ledger.cursor_for(&realm).unwrap().applied_event_seq, 1);

    ledger.apply_event_with_fault(&source.events[1], None).unwrap();
    let stale_dup = ledger.apply_event_with_fault(&source.events[0], None).unwrap();
    assert!(matches!(stale_dup, SingleEventOutcome::DuplicateSkipped { .. }));
    assert_eq!(ledger.refs.get(&(repo, "refs/heads/main".into())).unwrap().oid, Some(oid(2).as_hex()));
    assert_eq!(ledger.webhook_deliveries.len(), 2);
}
