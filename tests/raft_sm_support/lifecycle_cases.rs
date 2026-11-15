//! Idempotent replay, `DigestConflict`, dropped-reply recovery, scope lifecycle
//! fencing, cancel-versus-begin/commit, and logical-tick decision expiry tests.

use super::*;
use rootyard::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, BeginOperationCommand, CancelCommand, CommitRefsCommand, InitializeGateCommand,
    InstallDecisionCommand, RefCasCommand, RefCasStateMachine, RepositoryLane, ScopeLifecycle,
    SetRepositoryLaneCommand, SmDecisionState, SmPackMode, StateMachineError, WireCommitRefsRequest, WireDecisionKind,
    WireDecisionVerdict, WireGateInit, WireOperationIdentity,
};
use rootyard::ref_store::{
    CommitMode, GitObjectFormat, HeadUpdate, OperationLookup, OperationState, RefStoreError, TerminalKind, VersionCheck,
};
use std::collections::BTreeMap;
use uuid::Uuid;

#[test]
fn idempotent_replay_digest_conflict_dropped_reply_and_lifecycle_fence() {
    let repo = Uuid::from_u128(12);
    let tenant = Uuid::from_u128(22);
    let issuer = Uuid::from_u128(32);
    let history = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
    let mut sm = RefCasStateMachine::new();
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&make_init(repo, tenant, history)),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::PgRefstore,
            authz_floor: 1,
        }),
    )
    .unwrap();

    let op1 = Uuid::from_u128(701);
    let req1 = make_request(
        repo,
        tenant,
        issuer,
        1,
        op1,
        1,
        HeadUpdate::Retarget(ref_name("refs/heads/main")),
        CommitMode::Atomic,
        vec![update("refs/heads/main", None, Some(oid(GitObjectFormat::Sha256, 1)))],
    );
    let r1 = match sm
        .apply(
            AppliedLogId { term: 1, index: 2 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req1),
                decision_id: None,
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 10,
            }),
        )
        .unwrap()
    {
        ApplyResponse::RefsCommitted(receipt) => receipt,
        other => panic!("unexpected {other:?}"),
    };
    assert!(!r1.replayed);
    assert_eq!(r1.terminal.kind, TerminalKind::Committed);

    // Advance lifecycle to Closing and raise authz_floor: historical replay MUST STILL SUCCEED,
    // while new ops must be refused and same-id/different-digest must fail with DigestConflict.
    sm.apply(
        AppliedLogId { term: 1, index: 3 },
        RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
            repository_id: repo,
            tenant_id: tenant,
            lane: RepositoryLane::PgRefstore,
            lifecycle: ScopeLifecycle::Closing,
            authz_floor: 5,
            history_incarnation: history,
            authority_epoch: 2,
            group_epoch: 2,
            pack_mode: SmPackMode::MetadataOnly,
        }),
    )
    .unwrap();

    let replay = match sm
        .apply(
            AppliedLogId { term: 1, index: 4 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req1),
                decision_id: None,
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 20,
            }),
        )
        .unwrap()
    {
        ApplyResponse::RefsCommitted(receipt) => receipt,
        other => panic!("unexpected {other:?}"),
    };
    assert!(replay.replayed);
    assert_eq!(replay.terminal, r1.terminal);

    // Same operation_id with different ref target -> DigestConflict, zero state mutation.
    let conflict_req = make_request(
        repo,
        tenant,
        issuer,
        1,
        op1,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![update("refs/heads/main", None, Some(oid(GitObjectFormat::Sha256, 2)))],
    );
    let err = sm
        .apply(
            AppliedLogId { term: 1, index: 5 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&conflict_req),
                decision_id: None,
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 21,
            }),
        )
        .unwrap_err();
    assert_eq!(err, StateMachineError::Store(RefStoreError::DigestConflict));

    // Fresh operation rejected by ScopeClosingOrClosed; regression Closing -> Open rejected.
    let fresh_req = make_request(
        repo,
        tenant,
        issuer,
        2,
        Uuid::from_u128(702),
        2,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![update("refs/heads/other", None, Some(oid(GitObjectFormat::Sha256, 3)))],
    );
    let err = sm
        .apply(
            AppliedLogId { term: 1, index: 5 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&fresh_req),
                decision_id: None,
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 22,
            }),
        )
        .unwrap_err();
    assert!(matches!(err, StateMachineError::ScopeClosingOrClosed { lifecycle: ScopeLifecycle::Closing, .. }));

    let reg = sm
        .apply(
            AppliedLogId { term: 1, index: 5 },
            RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
                repository_id: repo,
                tenant_id: tenant,
                lane: RepositoryLane::PgRefstore,
                lifecycle: ScopeLifecycle::Open,
                authz_floor: 5,
                history_incarnation: history,
                authority_epoch: 2,
                group_epoch: 2,
                pack_mode: SmPackMode::MetadataOnly,
            }),
        )
        .unwrap_err();
    assert!(matches!(reg, StateMachineError::LifecycleRegression { .. }));

    // After restart from snapshot, dropped Commit reply stays queryable cleanly.
    let snap = sm.snapshot_bytes().unwrap();
    let restarted = RefCasStateMachine::restore_bytes(&snap).unwrap();
    assert_eq!(
        restarted.check_version(repo, tenant, None).unwrap(),
        VersionCheck::Changed(restarted.read_gate_version(repo).unwrap().unwrap())
    );
    assert_eq!(restarted.query_operation(repo, op1).unwrap(), OperationLookup::Known(r1.record));
}

#[test]
fn cancel_versus_begin_commit_and_decision_expiry() {
    let repo = Uuid::from_u128(13);
    let tenant = Uuid::from_u128(23);
    let issuer = Uuid::from_u128(33);
    let history = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
    let mut sm = RefCasStateMachine::new();
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&make_init(repo, tenant, history)),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::PgRefstore,
            authz_floor: 1,
        }),
    )
    .unwrap();

    // Pending op with open decision: Cancel cancels op AND closes open decision cleanly.
    let op_pending = Uuid::from_u128(801);
    let req_pending = make_request(
        repo,
        tenant,
        issuer,
        1,
        op_pending,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![update("refs/heads/main", None, Some(oid(GitObjectFormat::Sha256, 5)))],
    );
    let dec_id = Uuid::from_u128(802);
    sm.apply(
        AppliedLogId { term: 1, index: 2 },
        RefCasCommand::BeginOperation(BeginOperationCommand {
            identity: WireOperationIdentity::from(req_pending.identity()),
            logical_tick: 10,
        }),
    )
    .unwrap();
    sm.apply(
        AppliedLogId { term: 1, index: 3 },
        RefCasCommand::InstallDecision(InstallDecisionCommand {
            decision_id: dec_id,
            repository_id: repo,
            tenant_id: tenant,
            actor_id: issuer,
            operation_id: op_pending,
            kind: WireDecisionKind::Atomic,
            base_revision: 1,
            command_digest: req_pending.digest().as_hex(),
            selection_digest: digest("s"),
            policy_digest: digest("p"),
            facts_digest: digest("f"),
            authz_digest: digest("a"),
            dependencies_digest: digest("d"),
            verdicts: vec![WireDecisionVerdict { ref_name: "refs/heads/main".into(), allowed: true, reason: None }],
            authz_epoch: 1,
            not_after_tick: 50,
            logical_tick: 12,
        }),
    )
    .unwrap();

    let cancelled = sm
        .apply(
            AppliedLogId { term: 1, index: 4 },
            RefCasCommand::Cancel(CancelCommand {
                identity: WireOperationIdentity::from(req_pending.identity()),
                reason: Some("abort".into()),
                logical_tick: 15,
            }),
        )
        .unwrap();
    assert!(matches!(
        cancelled,
        ApplyResponse::OperationCancelled { decision_cancelled: Some(d), ref receipt }
            if d == dec_id && receipt.record.as_ref().unwrap().state() == OperationState::Cancelled
    ));
    assert_eq!(sm.read_decision(dec_id).unwrap().state, SmDecisionState::Cancelled);

    let late = sm
        .apply(
            AppliedLogId { term: 1, index: 5 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req_pending),
                decision_id: Some(dec_id),
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 16,
            }),
        )
        .unwrap_err();
    assert_eq!(late, StateMachineError::Store(RefStoreError::Cancelled { operation_id: op_pending }));

    // Expired decision fails cleanly on logical_tick without changing gate or refs.
    let op_exp = Uuid::from_u128(803);
    let dec_exp = Uuid::from_u128(804);
    let req_exp = make_request(
        repo,
        tenant,
        issuer,
        2,
        op_exp,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![update("refs/heads/exp", None, Some(oid(GitObjectFormat::Sha256, 6)))],
    );
    sm.apply(
        AppliedLogId { term: 1, index: 5 },
        RefCasCommand::InstallDecision(InstallDecisionCommand {
            decision_id: dec_exp,
            repository_id: repo,
            tenant_id: tenant,
            actor_id: issuer,
            operation_id: op_exp,
            kind: WireDecisionKind::Atomic,
            base_revision: 1,
            command_digest: req_exp.digest().as_hex(),
            selection_digest: digest("s2"),
            policy_digest: digest("p2"),
            facts_digest: digest("f2"),
            authz_digest: digest("a2"),
            dependencies_digest: digest("d2"),
            verdicts: vec![WireDecisionVerdict { ref_name: "refs/heads/exp".into(), allowed: true, reason: None }],
            authz_epoch: 1,
            not_after_tick: 30,
            logical_tick: 20,
        }),
    )
    .unwrap();
    let exp_err = sm
        .apply(
            AppliedLogId { term: 1, index: 6 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req_exp),
                decision_id: Some(dec_exp),
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 31,
            }),
        )
        .unwrap_err();
    assert!(matches!(exp_err, StateMachineError::DecisionExpired { not_after_tick: 30, current_tick: 31, .. }));
}
