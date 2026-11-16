//! Issue #152 integration & E2E qualification suite:
//! - PG `OPEN -> CLOSING` projection & monotonic `close_scope` / `authz_floor`
//! - Versioned signed decision grants (key rotation, mTLS SAN, realm, expiry, anti-replay)
//! - Same-log `Cancel` / `CommitRefs` serialization, recovery, and ReadIndex drain barriers.

mod remote_authz_support;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use rootyard::ref_store::contract::{OperationState, RefStoreError};
use rootyard::ref_store::core::state_machine::{
    ApplyResponse, CancelCommand, CloseAuthScopeCommand, CommitRefsCommand, NoopCommand, RefCasCommand, RefCasLogEntry,
    RefCasStateMachine, ScopeLifecycle, StateMachineError, WireCommitRefsRequest, WireOperationIdentity,
    encode_command,
};
use rootyard::ref_store::projector::{
    AuthoritySourceKind, LinearizableScopeProbe, RemoteAuthzBridgeError, RemoteAuthzGrantError, RevocationDrainStatus,
    await_drain_before_revocation_ack, evaluate_revocation_drain_barrier, verify_signed_decision_grant,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use remote_authz_support::fixtures::{
    build_commit_request, build_grant_payload, init_gate_cmd, log_id, make_test_keyring, make_test_realm,
};

#[test]
fn signed_grant_rejects_tamper_cross_domain_replay_retired_key_and_late_closing() {
    let repo = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let realm = make_test_realm(repo, tenant);
    let mut keyring = make_test_keyring(1);

    let tok1 = Uuid::new_v4();
    let tok2 = Uuid::new_v4();
    let op1 = Uuid::new_v4();
    let dec1 = Uuid::new_v4();
    let req1 = build_commit_request(&realm, actor, "main", 1, op1, "refs/heads/main", 0x1a);
    let grant_v1 = keyring.sign(build_grant_payload(&realm, dec1, &req1, "token", tok1, 4, 500)).expect("sign v1");

    keyring.rotate_key(2, Zeroizing::new([0x55u8; 32]), true).expect("rotate key 1 -> 2");
    assert_eq!(
        verify_signed_decision_grant(&keyring, &grant_v1, &realm, "raft-bridge-svc-a", 10),
        Err(RemoteAuthzGrantError::RetiredSigningKey(1))
    );

    let grant_v2 = keyring.sign(build_grant_payload(&realm, dec1, &req1, "token", tok1, 4, 500)).expect("sign v2");

    let mut forged = grant_v2.clone();
    forged.payload.authz_epoch = 99;
    assert_eq!(
        verify_signed_decision_grant(&keyring, &forged, &realm, "raft-bridge-svc-a", 10),
        Err(RemoteAuthzGrantError::ForgedGrantSignature)
    );
    assert!(matches!(
        verify_signed_decision_grant(&keyring, &grant_v2, &realm, "raft-bridge-wrong", 10),
        Err(RemoteAuthzGrantError::ServiceIdentityMismatch { .. })
    ));
    let mut foreign_realm = realm.clone();
    foreign_realm.history_incarnation = Uuid::new_v4();
    assert_eq!(
        verify_signed_decision_grant(&keyring, &grant_v2, &foreign_realm, "raft-bridge-svc-a", 10),
        Err(RemoteAuthzGrantError::RealmMismatch("signed grant target realm mismatch"))
    );
    assert!(matches!(
        verify_signed_decision_grant(&keyring, &grant_v2, &realm, "raft-bridge-svc-a", 500),
        Err(RemoteAuthzGrantError::GrantExpired { .. })
    ));

    let cmd1 = verify_signed_decision_grant(&keyring, &grant_v2, &realm, "raft-bridge-svc-a", 10).expect("valid v2");
    let mut sm = RefCasStateMachine::new();
    sm.apply(log_id(1), init_gate_cmd(repo, &realm, 1)).expect("init");
    assert_eq!(
        sm.apply(log_id(2), RefCasCommand::InstallScopedDecision(cmd1.clone())).expect("install #1"),
        ApplyResponse::DecisionInstalled { decision_id: dec1, replayed: false }
    );
    let snap = sm.snapshot().expect("snapshot");
    let mut sm2 = RefCasStateMachine::restore(&snap).expect("restore");
    assert_eq!(
        sm2.apply(log_id(3), RefCasCommand::InstallScopedDecision(cmd1)).expect("replay"),
        ApplyResponse::DecisionInstalled { decision_id: dec1, replayed: true }
    );

    let close_resp = sm2
        .apply(
            log_id(4),
            RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
                scope_kind: "token".into(),
                scope_id: tok1,
                repository_id: Some(repo),
                tenant_id: Some(tenant),
                lifecycle: ScopeLifecycle::Closing,
                authz_floor: 7,
                change_id: Uuid::new_v4(),
                logical_tick: 20,
            }),
        )
        .expect("close tok1");
    assert!(matches!(close_resp, ApplyResponse::AuthScopeClosed { authz_floor: 7, .. }));

    let late_commit = RefCasCommand::CommitRefs(CommitRefsCommand {
        request: WireCommitRefsRequest::from(&req1),
        decision_id: Some(dec1),
        required_holds: vec![],
        policy_rejects: BTreeMap::new(),
        logical_tick: 21,
    });
    assert!(matches!(sm2.apply(log_id(5), late_commit), Err(StateMachineError::AuthzFloorViolation { .. })));

    let op_late = Uuid::new_v4();
    let dec_late = Uuid::new_v4();
    let req_late = build_commit_request(&realm, actor, "main", 2, op_late, "refs/heads/other", 0x1b);
    let late_grant =
        keyring.sign(build_grant_payload(&realm, dec_late, &req_late, "token", tok1, 9, 500)).expect("sign late");
    let late_cmd = verify_signed_decision_grant(&keyring, &late_grant, &realm, "raft-bridge-svc-a", 22).unwrap();
    assert!(matches!(
        sm2.apply(log_id(6), RefCasCommand::InstallScopedDecision(late_cmd)),
        Err(StateMachineError::ScopeClosingOrClosed { .. })
    ));

    let op_tok2 = Uuid::new_v4();
    let dec_tok2 = Uuid::new_v4();
    let req_tok2 = build_commit_request(&realm, actor, "main", 3, op_tok2, "refs/heads/independent", 0x2c);
    let grant_tok2 =
        keyring.sign(build_grant_payload(&realm, dec_tok2, &req_tok2, "token", tok2, 8, 500)).expect("sign tok2");
    let cmd_tok2 = verify_signed_decision_grant(&keyring, &grant_tok2, &realm, "raft-bridge-svc-a", 23).unwrap();
    sm2.apply(log_id(7), RefCasCommand::InstallScopedDecision(cmd_tok2)).expect("install tok2");
    assert!(matches!(
        sm2.apply(
            log_id(8),
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req_tok2),
                decision_id: Some(dec_tok2),
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 24,
            }),
        ),
        Ok(ApplyResponse::RefsCommitted(_))
    ));
}

#[test]
fn same_log_cancel_commit_ordering_and_snapshot_recovery_preserve_floor() {
    let repo = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let realm = make_test_realm(repo, tenant);
    let keyring = make_test_keyring(1);
    let scope_id = Uuid::new_v4();

    let op_cancel_first = Uuid::new_v4();
    let dec_cancel_first = Uuid::new_v4();
    let req_a = build_commit_request(&realm, actor, "lane-a", 1, op_cancel_first, "refs/heads/a", 0x3a);
    let grant_a =
        keyring.sign(build_grant_payload(&realm, dec_cancel_first, &req_a, "branch_rules", scope_id, 3, 500)).unwrap();
    let install_a = RefCasCommand::InstallScopedDecision(
        verify_signed_decision_grant(&keyring, &grant_a, &realm, "raft-bridge-svc-a", 5).unwrap(),
    );
    let cancel_a = RefCasCommand::Cancel(CancelCommand {
        identity: WireOperationIdentity::from(req_a.identity()),
        reason: Some("revoked_before_commit".into()),
        logical_tick: 6,
    });
    let commit_a = RefCasCommand::CommitRefs(CommitRefsCommand {
        request: WireCommitRefsRequest::from(&req_a),
        decision_id: Some(dec_cancel_first),
        required_holds: vec![],
        policy_rejects: BTreeMap::new(),
        logical_tick: 7,
    });

    let mut sm = RefCasStateMachine::new();
    sm.apply(log_id(1), init_gate_cmd(repo, &realm, 1)).unwrap();
    sm.apply(log_id(2), install_a).unwrap();
    let cancel_resp = sm.apply(log_id(3), cancel_a).unwrap();
    assert!(matches!(
        cancel_resp,
        ApplyResponse::OperationCancelled { decision_cancelled: Some(d), .. } if d == dec_cancel_first
    ));
    assert_eq!(
        sm.apply(log_id(4), commit_a),
        Err(StateMachineError::Store(RefStoreError::Cancelled { operation_id: op_cancel_first }))
    );

    sm.apply(
        log_id(5),
        RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
            scope_kind: "branch_rules".into(),
            scope_id,
            repository_id: Some(repo),
            tenant_id: Some(tenant),
            lifecycle: ScopeLifecycle::Closed,
            authz_floor: 12,
            change_id: Uuid::new_v4(),
            logical_tick: 10,
        }),
    )
    .unwrap();
    let snap = sm.snapshot().unwrap();
    let mut recovered = RefCasStateMachine::restore(&snap).unwrap();
    recovered
        .recover_entries(vec![RefCasLogEntry {
            log_id: log_id(6),
            payload: encode_command(&RefCasCommand::Noop(NoopCommand { logical_tick: None })).unwrap(),
        }])
        .unwrap();
    assert_eq!(recovered.read_scope_floor("branch_rules", scope_id).unwrap().authz_floor, 12);
    assert!(matches!(
        recovered.apply(
            log_id(7),
            RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
                scope_kind: "branch_rules".into(),
                scope_id,
                repository_id: Some(repo),
                tenant_id: Some(tenant),
                lifecycle: ScopeLifecycle::Closing,
                authz_floor: 12,
                change_id: Uuid::new_v4(),
                logical_tick: 11,
            }),
        ),
        Err(StateMachineError::LifecycleRegression { .. })
    ));
}

#[tokio::test]
async fn drain_barrier_refuses_unknown_quorum_loss_and_pg_fallback() {
    let repo = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let realm = make_test_realm(repo, tenant);
    let keyring = make_test_keyring(1);
    let scope_id = Uuid::new_v4();
    let op_id = Uuid::new_v4();
    let dec_id = Uuid::new_v4();
    let req = build_commit_request(&realm, actor, "main", 1, op_id, "refs/heads/main", 0x55);
    let grant = keyring.sign(build_grant_payload(&realm, dec_id, &req, "pull", scope_id, 3, 500)).unwrap();
    let install_cmd = verify_signed_decision_grant(&keyring, &grant, &realm, "raft-bridge-svc-a", 5).unwrap();

    let mut sm = RefCasStateMachine::new();
    sm.apply(log_id(1), init_gate_cmd(repo, &realm, 1)).unwrap();
    sm.apply(log_id(2), RefCasCommand::InstallScopedDecision(install_cmd)).unwrap();
    sm.apply(
        log_id(3),
        RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
            scope_kind: "pull".into(),
            scope_id,
            repository_id: Some(repo),
            tenant_id: Some(tenant),
            lifecycle: ScopeLifecycle::Closing,
            authz_floor: 5,
            change_id: Uuid::new_v4(),
            logical_tick: 8,
        }),
    )
    .unwrap();

    let open_drain = sm.inspect_scope_drain("pull", scope_id).unwrap();
    for bad_src in [
        AuthoritySourceKind::PgRefsProjection,
        AuthoritySourceKind::RedisCache,
        AuthoritySourceKind::UnverifiedLocalReplica,
    ] {
        let probe = LinearizableScopeProbe {
            source: bad_src,
            read_log_index: Some(3),
            applied_log_index: 3,
            drain: open_drain.clone(),
        };
        assert!(matches!(
            evaluate_revocation_drain_barrier(&probe, "pull", scope_id, 5, 3),
            Err(RemoteAuthzBridgeError::AuthorityViolation(_))
        ));
    }
    let unknown_probe = LinearizableScopeProbe {
        source: AuthoritySourceKind::RaftReadIndexQuorum,
        read_log_index: None,
        applied_log_index: 3,
        drain: open_drain.clone(),
    };
    let s_unknown = evaluate_revocation_drain_barrier(&unknown_probe, "pull", scope_id, 5, 3).unwrap();
    assert!(!s_unknown.can_ack_revocation());
    assert!(matches!(s_unknown, RevocationDrainStatus::UnknownQuorumLoss { .. }));

    let draining_probe = LinearizableScopeProbe {
        source: AuthoritySourceKind::RaftReadIndexQuorum,
        read_log_index: Some(3),
        applied_log_index: 3,
        drain: open_drain,
    };
    let s_draining = evaluate_revocation_drain_barrier(&draining_probe, "pull", scope_id, 5, 3).unwrap();
    assert!(!s_draining.can_ack_revocation());

    sm.apply(
        log_id(4),
        RefCasCommand::Cancel(CancelCommand {
            identity: WireOperationIdentity::from(req.identity()),
            reason: Some("scope_closing".into()),
            logical_tick: 9,
        }),
    )
    .unwrap();
    let drained_snapshot = sm.inspect_scope_drain("pull", scope_id).unwrap();
    let status = await_drain_before_revocation_ack(
        "pull",
        scope_id,
        5,
        3,
        Duration::from_millis(200),
        Duration::from_millis(10),
        || async {
            Ok(LinearizableScopeProbe {
                source: AuthoritySourceKind::RaftReadIndexQuorum,
                read_log_index: Some(4),
                applied_log_index: 4,
                drain: drained_snapshot.clone(),
            })
        },
    )
    .await
    .unwrap();
    assert!(status.can_ack_revocation());
    assert!(matches!(
        status,
        RevocationDrainStatus::DrainedAndConfirmed { confirmed_operations, .. }
        if confirmed_operations.len() == 1 && confirmed_operations[0].state == OperationState::Cancelled
    ));
}

#[tokio::test]
#[ignore = "requires multi-process raft-node binary, openssl, and PostgreSQL 17"]
async fn e2e_pg17_open_to_closing_grant_rotation_crash_restart_and_replay() -> Result<()> {
    remote_authz_support::e2e::run_open_to_closing_grant_rotation_crash_restart().await
}

#[tokio::test]
#[ignore = "requires multi-process raft-node binary, openssl, and PostgreSQL 17"]
async fn e2e_same_log_cancel_commit_partition_drain_barrier_and_clock_independence() -> Result<()> {
    remote_authz_support::e2e::run_cancel_commit_partition_drain_barrier().await
}
