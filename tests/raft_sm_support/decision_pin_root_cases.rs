//! Regression tests covering P1 decision-verdict binding and P2/P3 replay & state-binding guards.

use super::*;
use rootyard::ref_store::{CommitRejectCode, RefCommitResult, RefStoreError, TerminalKind};

fn base_decision(
    decision_id: Uuid,
    req: &CommitRefsRequest,
    kind: WireDecisionKind,
    base_revision: i64,
    verdicts: Vec<WireDecisionVerdict>,
) -> InstallDecisionCommand {
    InstallDecisionCommand {
        decision_id,
        repository_id: req.repository_id(),
        tenant_id: req.tenant_id(),
        actor_id: req.identity().issuer_id(),
        operation_id: req.identity().operation_id(),
        kind,
        base_revision,
        command_digest: req.digest().as_hex(),
        selection_digest: digest("sel"),
        policy_digest: digest("pol"),
        facts_digest: digest("facts"),
        authz_digest: digest("authz"),
        dependencies_digest: digest("deps"),
        verdicts,
        authz_epoch: 1,
        not_after_tick: 100,
        logical_tick: 10,
    }
}

#[test]
fn decision_verdicts_bind_policy_rejects_and_atomic_refuses_rejected_verdicts() {
    let repo = Uuid::from_u128(1001);
    let tenant = Uuid::from_u128(1002);
    let issuer = Uuid::from_u128(1003);
    let history = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
    let mut sm = RefCasStateMachine::new();
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&make_init(repo, tenant, history)),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            authz_floor: 1,
        }),
    )
    .unwrap();

    let op1 = Uuid::from_u128(1101);
    let req1 = make_request(
        repo,
        tenant,
        issuer,
        1,
        op1,
        1,
        HeadUpdate::Retarget(ref_name("refs/heads/main")),
        CommitMode::AcceptedSubset,
        vec![
            update("refs/heads/main", None, Some(oid(GitObjectFormat::Sha256, 1))),
            update("refs/heads/denied", None, Some(oid(GitObjectFormat::Sha256, 2))),
        ],
    );

    // Invalid WireDecisionVerdict consistency (accepted disagrees with reject_code or duplicate ref) fails InstallDecision.
    let err = sm
        .apply(
            AppliedLogId { term: 1, index: 2 },
            RefCasCommand::InstallDecision(base_decision(
                Uuid::from_u128(1200),
                &req1,
                WireDecisionKind::AcceptedSubset,
                1,
                vec![WireDecisionVerdict {
                    ref_name: "refs/heads/main".into(),
                    accepted: true,
                    reject_code: Some(CommitRejectCode::PolicyDenied),
                }],
            )),
        )
        .unwrap_err();
    assert!(matches!(err, StateMachineError::InvalidInput(_)));

    let err = sm
        .apply(
            AppliedLogId { term: 1, index: 2 },
            RefCasCommand::InstallDecision(base_decision(
                Uuid::from_u128(1201),
                &req1,
                WireDecisionKind::AcceptedSubset,
                1,
                vec![
                    WireDecisionVerdict { ref_name: "refs/heads/main".into(), accepted: true, reject_code: None },
                    WireDecisionVerdict { ref_name: "refs/heads/main".into(), accepted: true, reject_code: None },
                ],
            )),
        )
        .unwrap_err();
    assert!(matches!(err, StateMachineError::InvalidInput(_)));

    // Missing ref in decision verdicts fails verification on CommitRefs.
    let dec_missing = Uuid::from_u128(1202);
    sm.apply(
        AppliedLogId { term: 1, index: 2 },
        RefCasCommand::InstallDecision(base_decision(
            dec_missing,
            &req1,
            WireDecisionKind::AcceptedSubset,
            1,
            vec![WireDecisionVerdict { ref_name: "refs/heads/main".into(), accepted: true, reject_code: None }],
        )),
    )
    .unwrap();
    let err = sm
        .apply(
            AppliedLogId { term: 1, index: 3 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req1),
                decision_id: Some(dec_missing),
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 15,
            }),
        )
        .unwrap_err();
    assert!(matches!(err, StateMachineError::DecisionDigestMismatch { decision_id, .. } if decision_id == dec_missing));

    // Full verdict set on new op enforces exact equality between decision.verdicts and cmd.policy_rejects.
    let op2 = Uuid::from_u128(1102);
    let dec2 = Uuid::from_u128(1203);
    let req2 = make_request(
        repo,
        tenant,
        issuer,
        1,
        op2,
        1,
        HeadUpdate::Retarget(ref_name("refs/heads/main")),
        CommitMode::AcceptedSubset,
        vec![
            update("refs/heads/main", None, Some(oid(GitObjectFormat::Sha256, 1))),
            update("refs/heads/denied", None, Some(oid(GitObjectFormat::Sha256, 2))),
        ],
    );
    sm.apply(
        AppliedLogId { term: 1, index: 3 },
        RefCasCommand::InstallDecision(base_decision(
            dec2,
            &req2,
            WireDecisionKind::AcceptedSubset,
            1,
            vec![
                WireDecisionVerdict { ref_name: "refs/heads/main".into(), accepted: true, reject_code: None },
                WireDecisionVerdict {
                    ref_name: "refs/heads/denied".into(),
                    accepted: false,
                    reject_code: Some(CommitRejectCode::PolicyDenied),
                },
            ],
        )),
    )
    .unwrap();

    // Omitting policy_rejects refuses CommitRefs without mutating refs or consuming decision.
    let err = sm
        .apply(
            AppliedLogId { term: 1, index: 4 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req2),
                decision_id: Some(dec2),
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 16,
            }),
        )
        .unwrap_err();
    assert!(matches!(err, StateMachineError::DecisionDigestMismatch { decision_id, .. } if decision_id == dec2));
    assert!(sm.read_refs(repo).is_empty());

    // Exact matching policy_rejects commits ONLY the accepted ref and closes decision Consumed.
    let mut rejects = BTreeMap::new();
    rejects.insert("refs/heads/denied".into(), CommitRejectCode::PolicyDenied);
    let res = sm
        .apply(
            AppliedLogId { term: 1, index: 4 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req2),
                decision_id: Some(dec2),
                required_holds: vec![],
                policy_rejects: rejects,
                logical_tick: 17,
            }),
        )
        .unwrap();
    let receipt = match res {
        ApplyResponse::RefsCommitted(r) => r,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(receipt.terminal.kind, TerminalKind::Committed);
    assert!(receipt.terminal.refs.iter().any(|r| {
        matches!(r, RefCommitResult::NotApplied { name, reason: CommitRejectCode::PolicyDenied } if name == "refs/heads/denied")
    }));
    let refs = sm.read_refs(repo);
    assert!(refs.contains_key("refs/heads/main"));
    assert!(!refs.contains_key("refs/heads/denied"));
    assert_eq!(sm.read_decision(dec2).unwrap().state, SmDecisionState::Consumed);

    // Atomic mode refuses CommitRefs when installed decision contains any accepted: false verdict.
    let op3 = Uuid::from_u128(1103);
    let dec3 = Uuid::from_u128(1204);
    let req3 = make_request(
        repo,
        tenant,
        issuer,
        2,
        op3,
        2,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![update("refs/heads/other", None, Some(oid(GitObjectFormat::Sha256, 3)))],
    );
    sm.apply(
        AppliedLogId { term: 1, index: 5 },
        RefCasCommand::InstallDecision(base_decision(
            dec3,
            &req3,
            WireDecisionKind::Atomic,
            2,
            vec![WireDecisionVerdict {
                ref_name: "refs/heads/other".into(),
                accepted: false,
                reject_code: Some(CommitRejectCode::PolicyDenied),
            }],
        )),
    )
    .unwrap();
    let mut rejects3 = BTreeMap::new();
    rejects3.insert("refs/heads/other".into(), CommitRejectCode::PolicyDenied);
    let err = sm
        .apply(
            AppliedLogId { term: 1, index: 6 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req3),
                decision_id: Some(dec3),
                required_holds: vec![],
                policy_rejects: rejects3,
                logical_tick: 18,
            }),
        )
        .unwrap_err();
    assert!(matches!(err, StateMachineError::DecisionDigestMismatch { decision_id, .. } if decision_id == dec3));
    assert!(!sm.read_refs(repo).contains_key("refs/heads/other"));
}

#[test]
fn install_decision_and_initialize_gate_replay_check_epochs_ticks_and_authz_floor() {
    let repo = Uuid::from_u128(2001);
    let tenant = Uuid::from_u128(2002);
    let issuer = Uuid::from_u128(2003);
    let history = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
    let mut sm = RefCasStateMachine::new();

    let init_cmd = InitializeGateCommand {
        gate: WireGateInit::from(&make_init(repo, tenant, history)),
        pack_mode: SmPackMode::MetadataOnly,
        lane: RepositoryLane::ServingRefStore,
        authz_floor: 3,
    };
    sm.apply(AppliedLogId { term: 1, index: 1 }, RefCasCommand::InitializeGate(init_cmd.clone())).unwrap();
    let replay_gate = sm.apply(AppliedLogId { term: 1, index: 2 }, RefCasCommand::InitializeGate(init_cmd)).unwrap();
    assert!(matches!(replay_gate, ApplyResponse::GateInitialized { created: false, .. }));

    let gate_mismatch = sm
        .apply(
            AppliedLogId { term: 1, index: 3 },
            RefCasCommand::InitializeGate(InitializeGateCommand {
                gate: WireGateInit::from(&make_init(repo, tenant, history)),
                pack_mode: SmPackMode::MetadataOnly,
                lane: RepositoryLane::ServingRefStore,
                authz_floor: 4,
            }),
        )
        .unwrap_err();
    assert_eq!(gate_mismatch, StateMachineError::Store(RefStoreError::GateConflict));

    let req = make_request(
        repo,
        tenant,
        issuer,
        1,
        Uuid::from_u128(2101),
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![update("refs/heads/main", None, Some(oid(GitObjectFormat::Sha256, 1)))],
    );
    let dec_id = Uuid::from_u128(2201);
    let mut dec_cmd = base_decision(
        dec_id,
        &req,
        WireDecisionKind::Atomic,
        1,
        vec![WireDecisionVerdict { ref_name: "refs/heads/main".into(), accepted: true, reject_code: None }],
    );
    dec_cmd.authz_epoch = 3;
    sm.apply(AppliedLogId { term: 1, index: 3 }, RefCasCommand::InstallDecision(dec_cmd.clone())).unwrap();

    let replay_dec =
        sm.apply(AppliedLogId { term: 1, index: 4 }, RefCasCommand::InstallDecision(dec_cmd.clone())).unwrap();
    assert_eq!(replay_dec, ApplyResponse::DecisionInstalled { decision_id: dec_id, replayed: true });

    let mut bad_authz = dec_cmd.clone();
    bad_authz.authz_epoch = 4;
    assert!(matches!(
        sm.apply(AppliedLogId { term: 1, index: 5 }, RefCasCommand::InstallDecision(bad_authz)).unwrap_err(),
        StateMachineError::DecisionConflict { decision_id, .. } if decision_id == dec_id
    ));

    let mut bad_tick = dec_cmd.clone();
    bad_tick.not_after_tick = 101;
    assert!(matches!(
        sm.apply(AppliedLogId { term: 1, index: 5 }, RefCasCommand::InstallDecision(bad_tick)).unwrap_err(),
        StateMachineError::DecisionConflict { decision_id, .. } if decision_id == dec_id
    ));

    let mut bad_rev = dec_cmd;
    bad_rev.base_revision = 2;
    assert!(matches!(
        sm.apply(AppliedLogId { term: 1, index: 5 }, RefCasCommand::InstallDecision(bad_rev)).unwrap_err(),
        StateMachineError::DecisionConflict { decision_id, .. } if decision_id == dec_id
    ));
}
