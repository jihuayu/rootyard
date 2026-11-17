//! Deterministic unit tests for crash recovery, monotonic projection, and concurrency (`Refs #156`).

use uuid::Uuid;

use crate::ref_store::core::state_machine::{AppliedLogId, ApplyResponse, CloseAuthScopeCommand, RefCasCommand, ScopeLifecycle};
use crate::ref_store::core::types::GitObjectFormat;

use super::coordinator::{InProcessRefCasBackend, MergeAuthorityBackend, PullRemoteMergeProducer};
use super::projector::{MergeReceiptStore, PullMergeReceiptProjector, RecoverablePullMergeFinalizer};
use super::types::{
    CommittedMergeReceipt, MergeAttemptOutcome, MergeFaultInjection, ProjectedPullRecord, ProjectionOutcome,
    PullMergeState, RejectedMergeReceipt, RemoteMergeError,
};
use super::unit_tests::{build_spec_and_pull, build_spec_with_target, hex_oid, setup_fixture};

#[tokio::test]
async fn crash_recovery_replay_idempotence_and_regression_guards() {
    let f = setup_fixture(GitObjectFormat::Sha256);
    let prod = PullRemoteMergeProducer::new(&f.backend, &f.store, &f.keyring);
    let finalizer = RecoverablePullMergeFinalizer::new(&f.backend, &f.store);
    let (spec_abort, pull) = build_spec_and_pull(&f, 1, 1, 5);

    assert!(matches!(
        prod.execute_merge(&spec_abort, &pull, true, MergeFaultInjection::DisconnectAfterPendingBeforeCas).await,
        Err(RemoteMergeError::UnknownOutcome(_))
    ));
    let rep1 = finalizer.reconcile_pending(f.repo_id, true).await.unwrap();
    assert_eq!((rep1.aborted_before_cas, rep1.committed), (1, 0));
    assert_eq!(
        f.store.load_attempt(f.repo_id, spec_abort.operation_id).await.unwrap().unwrap().state,
        PullMergeState::AbortedBeforeCas
    );
    assert_eq!(f.store.get_pull(f.repo_id, 1).unwrap().state, "open");

    let (spec_ok, pull2) = build_spec_and_pull(&f, 1, 2, 5);
    assert!(matches!(
        prod.execute_merge(&spec_ok, &pull2, true, MergeFaultInjection::CoordinatorTimeoutAfterCasBeforeProjection)
            .await,
        Err(RemoteMergeError::UnknownOutcome(_))
    ));
    assert_eq!(f.store.get_pull(f.repo_id, 1).unwrap().state, "open");
    let rep2 = finalizer.reconcile_pending(f.repo_id, true).await.unwrap();
    assert_eq!((rep2.committed, rep2.aborted_before_cas), (1, 0));
    let p_row = f.store.get_pull(f.repo_id, 1).unwrap();
    assert_eq!((p_row.state.as_str(), p_row.merge_commit_oid.as_deref()), ("merged", Some(f.head_oid.as_str())));

    let attempt = f.store.load_attempt(f.repo_id, spec_ok.operation_id).await.unwrap().unwrap();
    let proj = PullMergeReceiptProjector::new(&f.store);
    let receipt = CommittedMergeReceipt {
        operation_id: spec_ok.operation_id,
        decision_id: spec_ok.decision_id,
        tenant_id: f.tenant_id,
        repository_id: f.repo_id,
        pull_number: 1,
        base_ref: "refs/heads/main".into(),
        previous_base_oid: f.base_oid.clone(),
        merged_oid: f.head_oid.clone(),
        commit_log_index: attempt.commit_log_index.unwrap(),
        commit_log_term: attempt.commit_log_term.unwrap(),
        gate_revision: f.base_revision + 1,
        terminal_digest: attempt.terminal_digest.clone().unwrap(),
        replayed: true,
    };
    assert_eq!(
        proj.project_committed(&receipt, 1, 1, true).await.unwrap(),
        ProjectionOutcome::ProjectedCommitted { replayed: true }
    );
    assert!(matches!(
        proj.project_rejected(&RejectedMergeReceipt {
            operation_id: spec_ok.operation_id,
            repository_id: f.repo_id,
            pull_number: 1,
            commit_log_index: None,
            commit_log_term: None,
            state: PullMergeState::RejectedMerge,
            reason: "late reject".into(),
            terminal_digest: None,
        })
        .await,
        Err(RemoteMergeError::ReceiptRegression(_))
    ));
    let mut equiv_receipt = receipt;
    equiv_receipt.merged_oid = hex_oid(GitObjectFormat::Sha256, 0xee);
    assert!(matches!(proj.project_committed(&equiv_receipt, 1, 1, true).await, Err(RemoteMergeError::Equivocation(_))));
}

#[tokio::test]
async fn late_raft_scope_closure_blocks_pre_minted_grant_commit() {
    let f = setup_fixture(GitObjectFormat::Sha256);
    let (spec, pull) = build_spec_and_pull(&f, 1, 1, 5);
    let mut sm = f.backend.state_machine();
    let next_idx = sm.last_applied().unwrap().index + 1;
    let res = sm
        .apply(
            AppliedLogId { term: 1, index: next_idx },
            RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
                scope_kind: "token".into(),
                scope_id: f.scope_id,
                repository_id: Some(f.repo_id),
                tenant_id: Some(f.tenant_id),
                lifecycle: ScopeLifecycle::Closing,
                authz_floor: 9,
                change_id: Uuid::new_v4(),
                logical_tick: 15,
            }),
        )
        .unwrap();
    assert!(matches!(res, ApplyResponse::AuthScopeClosed { .. }));
    let closed_backend = InProcessRefCasBackend::new(sm);
    let prod = PullRemoteMergeProducer::new(&closed_backend, &f.store, &f.keyring);
    assert!(matches!(
        prod.execute_merge(&spec, &pull, true, MergeFaultInjection::None).await,
        Err(RemoteMergeError::RevokedAuthorization(_))
    ));
    assert_eq!(closed_backend.read_ref_oid(f.repo_id, "refs/heads/main").await.unwrap(), Some(f.base_oid));
}

#[tokio::test]
async fn concurrent_same_ref_merges_elect_single_cas_winner() {
    let f = setup_fixture(GitObjectFormat::Sha256);
    f.store.seed_pull(ProjectedPullRecord {
        tenant_id: f.tenant_id,
        repository_id: f.repo_id,
        pull_number: 2,
        state: "open".into(),
        head_oid: f.head_oid.clone(),
        base_oid: f.base_oid.clone(),
        merge_commit_oid: None,
        merged_storage_generation: None,
        version: 1,
    });
    let (s1, p1) = build_spec_and_pull(&f, 1, 1, 5);
    let (s2, p2) = build_spec_with_target(&f, 2, 2, 5, &hex_oid(GitObjectFormat::Sha256, 0x33));
    let prod = PullRemoteMergeProducer::new(&f.backend, &f.store, &f.keyring);
    let (r1, r2) = tokio::join!(
        prod.execute_merge(&s1, &p1, true, MergeFaultInjection::None),
        prod.execute_merge(&s2, &p2, true, MergeFaultInjection::None),
    );
    let (wins, target_oid) = match (r1, r2) {
        (Ok(MergeAttemptOutcome::Committed(w)), Err(RemoteMergeError::TargetRefMoved { .. }))
        | (Err(RemoteMergeError::TargetRefMoved { .. }), Ok(MergeAttemptOutcome::Committed(w))) => (1usize, w.merged_oid),
        other => panic!("expected 1 winner and 1 TargetRefMoved loser, got {other:?}"),
    };
    assert_eq!(wins, 1);
    assert_eq!(f.backend.read_ref_oid(f.repo_id, "refs/heads/main").await.unwrap(), Some(target_oid));
}

#[tokio::test]
async fn reconcile_and_replay_survive_subsequent_pr_advancing_base_ref() {
    let f = setup_fixture(GitObjectFormat::Sha256);
    f.store.seed_pull(ProjectedPullRecord {
        tenant_id: f.tenant_id,
        repository_id: f.repo_id,
        pull_number: 2,
        state: "open".into(),
        head_oid: hex_oid(GitObjectFormat::Sha256, 0x33),
        base_oid: f.head_oid.clone(),
        merge_commit_oid: None,
        merged_storage_generation: None,
        version: 1,
    });
    let prod = PullRemoteMergeProducer::new(&f.backend, &f.store, &f.keyring);
    let finalizer = RecoverablePullMergeFinalizer::new(&f.backend, &f.store);

    // PR #1 commits base -> oid_1 in Ref-CAS, then crashes before PG projection.
    let (s1, p1) = build_spec_and_pull(&f, 1, 1, 5);
    assert!(matches!(
        prod.execute_merge(&s1, &p1, true, MergeFaultInjection::CoordinatorTimeoutAfterCasBeforeProjection).await,
        Err(RemoteMergeError::UnknownOutcome(_))
    ));
    assert_eq!(f.backend.read_ref_oid(f.repo_id, "refs/heads/main").await.unwrap(), Some(f.head_oid.clone()));

    // Before PR #1 reconciles, PR #2 validly advances base from oid_1 -> oid_2.
    let gv2 = f.backend.state_machine().read_gate_version(f.repo_id).unwrap().unwrap();
    let mut f2 = setup_fixture(GitObjectFormat::Sha256);
    f2.tenant_id = f.tenant_id;
    f2.repo_id = f.repo_id;
    f2.actor_id = f.actor_id;
    f2.scope_id = f.scope_id;
    f2.realm = f.realm.clone();
    f2.svc = f.svc.clone();
    f2.keyring = f.keyring.clone();
    f2.base_oid = f.head_oid.clone();
    f2.head_oid = hex_oid(GitObjectFormat::Sha256, 0x33);
    f2.base_revision = gv2.revision();
    f2.base_gate_digest = gv2.digest().as_hex();
    let (s2, p2) = build_spec_with_target(&f2, 2, 2, 5, &f2.head_oid);
    let MergeAttemptOutcome::Committed(rec2) =
        prod.execute_merge(&s2, &p2, true, MergeFaultInjection::None).await.unwrap()
    else {
        panic!("PR #2 should advance main to oid_2");
    };
    assert_eq!(rec2.merged_oid, f2.head_oid);
    assert_eq!(f.backend.read_ref_oid(f.repo_id, "refs/heads/main").await.unwrap(), Some(f2.head_oid.clone()));

    // Recovery of PR #1 must read oid_1 immutably from CommitTerminal (never oid_2).
    let rep = finalizer.reconcile_pending(f.repo_id, true).await.unwrap();
    assert_eq!((rep.committed, rep.rejected), (1, 0));
    let pr1 = f.store.get_pull(f.repo_id, 1).unwrap();
    assert_eq!((pr1.state.as_str(), pr1.merge_commit_oid.as_deref()), ("merged", Some(f.head_oid.as_str())));

    // Replaying op_1 directly against Ref-CAS must also return oid_1 (`replayed=true`).
    let v1 = super::validation::verify_pull_remote_authz_grant(&s1, &p1, &f.keyring).unwrap();
    let replay_out = f
        .backend
        .install_and_commit_scoped(f.repo_id, &s1.base_ref, v1.install_cmd, v1.commit_cmd)
        .await
        .unwrap();
    assert!(matches!(
        replay_out,
        super::coordinator::AuthorityCommitOutcome::Committed { ref merged_oid, replayed: true, .. }
            if merged_oid == &f.head_oid
    ));
}
