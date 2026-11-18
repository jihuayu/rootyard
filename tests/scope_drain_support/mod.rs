//! Quorum-bound scope-drain API tests for the real three-node backend.
//!
//! This module uses only exported backend/node/requirement APIs and the existing bridge callback.
//! It is an in-process three-node Raft test, not multi-host or production qualification.

use super::*;
use anyhow::{Context, bail};
use rootyard::ref_store::OperationState;
use rootyard::ref_store::core::state_machine::{
    CancelCommand, CloseAuthScopeCommand, InstallDecisionCommand, InstallScopedDecisionCommand,
    WireDecisionGrantCommitment, WireDecisionKind, WireDecisionScopeDep, WireDecisionVerdict, WireOperationIdentity,
};
use rootyard::ref_store::projector::{
    AuthoritySourceKind, RevocationDrainStatus, await_drain_before_revocation_ack, evaluate_revocation_drain_barrier,
};
use rootyard::ref_store::raft_backend::RootRefCasApplied;

use self::failure_phase::{CASE_SCOPE, Class, Operation, PhaseGuard, ScopePhase, observe_call};

pub(crate) mod failure_phase;

#[allow(clippy::too_many_arguments)]
fn install_scoped_command(
    repo: Uuid,
    tenant: Uuid,
    decision_id: Uuid,
    operation_id: Uuid,
    actor_id: Uuid,
    scope_kind: &str,
    scope_id: Uuid,
    base_gate_digest: String,
) -> RefCasCommand {
    RefCasCommand::InstallScopedDecision(InstallScopedDecisionCommand {
        decision: InstallDecisionCommand {
            decision_id,
            repository_id: repo,
            tenant_id: tenant,
            actor_id,
            operation_id,
            kind: WireDecisionKind::Atomic,
            base_revision: 1,
            command_digest: "01".repeat(32),
            selection_digest: "02".repeat(32),
            policy_digest: "03".repeat(32),
            facts_digest: "04".repeat(32),
            authz_digest: "05".repeat(32),
            dependencies_digest: "06".repeat(32),
            verdicts: vec![WireDecisionVerdict {
                ref_name: "refs/heads/main".into(),
                accepted: true,
                reject_code: None,
            }],
            authz_epoch: 1,
            not_after_tick: 1_000_000,
            logical_tick: 0,
        },
        scope_dependencies: vec![WireDecisionScopeDep {
            scope_kind: scope_kind.into(),
            scope_id,
            observed_version: 1,
            observed_digest: "07".repeat(32),
        }],
        grant_commitment: WireDecisionGrantCommitment {
            base_gate_digest,
            packs_digest: "08".repeat(32),
            hold_receipts_digest: "09".repeat(32),
            captured_oid_digest: "0a".repeat(32),
            required_holds: vec![],
        },
    })
}

fn cancel_command(repo: Uuid, operation_id: Uuid, logical_tick: u64) -> RefCasCommand {
    RefCasCommand::Cancel(CancelCommand {
        identity: WireOperationIdentity {
            repository_id: repo,
            issuer_id: Uuid::new_v4(),
            lane: "main".into(),
            sequence: 1,
            operation_id,
            digest: "00".repeat(32),
        },
        reason: Some("settle indexed scope decision".into()),
        logical_tick,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privileged_scope_drain_query_is_quorum_bound_and_multirepo_complete() -> Result<()> {
    let mut phase = PhaseGuard::new(CASE_SCOPE, ScopePhase::Bootstrap);
    let outcome = privileged_scope_drain_query_is_quorum_bound_and_multirepo_complete_body(&mut phase).await;
    match outcome {
        Ok(()) => {
            phase.complete();
            Ok(())
        }
        Err(error) => {
            phase.fail(Class::from_error(&error));
            Err(anyhow::anyhow!("scope drain case failed"))
        }
    }
}

async fn privileged_scope_drain_query_is_quorum_bound_and_multirepo_complete_body(
    phase: &mut PhaseGuard<ScopePhase>,
) -> Result<()> {
    let tenant = Uuid::new_v4();
    let history = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let trust = NodeTrust::new(TEST_GROUP, authority, 1)?;
    let realm = RealmBinding::new(tenant, TEST_GROUP, authority, history, 1, 1, GitObjectFormat::Sha256, 1)?;
    phase.set(ScopePhase::Bootstrap);
    let cluster = TestCluster::start_three(trust.clone()).await?;
    let (leader_id, _) = cluster.wait_leader(Duration::from_secs(20)).await?;
    let options = BackendOptions {
        quorum_timeout: Duration::from_secs(3),
        apply_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(20),
    };

    phase.set(ScopePhase::Provision);
    let repo_a = Uuid::new_v4();
    let repo_b = Uuid::new_v4();
    let backend_a = backend_on(&cluster, leader_id, repo_a, tenant, realm.clone(), options).await?;
    let backend_b = backend_on(&cluster, leader_id, repo_b, tenant, realm.clone(), options).await?;
    let init_a =
        observe_call(phase, &cluster, Operation::ClientWrite, backend_a.propose(init_command(repo_a, tenant, history)))
            .await?;
    assert!(proposal_outcome(&init_a).is_applied());
    let init_b =
        observe_call(phase, &cluster, Operation::ClientWrite, backend_b.propose(init_command(repo_b, tenant, history)))
            .await?;
    assert!(proposal_outcome(&init_b).is_applied());
    let gate_a = observe_call(phase, &cluster, Operation::ReadView, backend_a.read_committed_view())
        .await?
        .read_gate_version()?
        .context("repo A gate after init")?
        .digest()
        .as_hex();
    let gate_b = observe_call(phase, &cluster, Operation::ReadView, backend_b.read_committed_view())
        .await?
        .read_gate_version()?
        .context("repo B gate after init")?
        .digest()
        .as_hex();

    let scope_kind = "token";
    let scope_id = Uuid::new_v4();
    let decision_a = Uuid::new_v4();
    let operation_a = Uuid::new_v4();
    let decision_b = Uuid::new_v4();
    let operation_b = Uuid::new_v4();
    phase.set(ScopePhase::Install);
    let install_a =
        install_scoped_command(repo_a, tenant, decision_a, operation_a, Uuid::new_v4(), scope_kind, scope_id, gate_a);
    let install_b =
        install_scoped_command(repo_b, tenant, decision_b, operation_b, Uuid::new_v4(), scope_kind, scope_id, gate_b);
    assert!(proposal_outcome(&backend_a.propose(install_a).await?).is_applied());
    assert!(proposal_outcome(&backend_b.propose(install_b).await?).is_applied());

    phase.set(ScopePhase::Close);
    let close = RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
        scope_kind: scope_kind.into(),
        scope_id,
        repository_id: Some(repo_a),
        tenant_id: Some(tenant),
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 1,
        change_id: Uuid::new_v4(),
        logical_tick: 1,
    });
    let close_outcome = backend_a.propose(close).await?;
    let close_summary = match proposal_outcome(&close_outcome) {
        RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosedV2 { drain_summary, .. }) => {
            assert_eq!(drain_summary.open_decision_count, 2);
            assert_eq!(drain_summary.pending_operation_count, 2);
            assert!(drain_summary.validate().is_ok());
            drain_summary.clone()
        }
        other => panic!("close did not emit a compact acknowledgment: {other:?}"),
    };
    assert_eq!(close_summary.open_decision_count, 2);
    let close_index = close_outcome.log_id.index;

    phase.set(ScopePhase::Recover);
    let requirement = backend_a.recover_scope_close_requirement(close_outcome.proposal_id.clone()).await?;
    assert_eq!(requirement.close_log_id(), close_outcome.log_id);
    assert_eq!(requirement.application_domain(), ROOT_REF_CAS_DOMAIN);
    assert_eq!(requirement.application_version(), ROOT_REF_CAS_VERSION);
    assert_eq!(requirement.scope_kind(), scope_kind);
    assert_eq!(requirement.scope_id(), scope_id);
    assert_eq!(requirement.required_authz_floor(), 1);
    assert_eq!(requirement.trust(), &trust);
    assert_eq!(requirement.group_id(), TEST_GROUP);
    assert_eq!(requirement.authority_id(), authority);
    assert_eq!(requirement.storage_generation(), 1);

    phase.set(ScopePhase::RecoveryRejections);
    let non_close_id = observe_call(phase, &cluster, Operation::Prepare, backend_a.prepare_proposal_id()).await?;
    let non_close = observe_call(
        phase,
        &cluster,
        Operation::ClientWrite,
        backend_a.propose_with_id(non_close_id.clone(), RefCasCommand::Noop(NoopCommand { logical_tick: None })),
    )
    .await?;
    assert!(proposal_outcome(&non_close).is_applied());
    assert!(matches!(
        backend_a.recover_scope_close_requirement(non_close.proposal_id.clone()).await,
        Err(RaftBackendError::ScopeCloseNotRecoverable(_))
    ));
    let never_observed = observe_call(phase, &cluster, Operation::Prepare, backend_a.prepare_proposal_id()).await?;
    assert!(matches!(
        backend_a.recover_scope_close_requirement(never_observed).await,
        Err(RaftBackendError::RecoveryNotObserved(_))
    ));
    let mut malformed = observe_call(phase, &cluster, Operation::Prepare, backend_a.prepare_proposal_id()).await?;
    malformed.group_id = "bad!".into();
    assert!(matches!(
        backend_a.recover_scope_close_requirement(malformed).await,
        Err(RaftBackendError::InvalidProposal(_))
    ));

    phase.set(ScopePhase::InitialDrain);
    let leader_node = cluster.node(leader_id).node.clone();
    let committed = leader_node.read_scope_drain(&requirement, options).await?;
    assert!(committed.read_log_index().is_some());
    assert!(committed.read_log_index().is_some_and(|read| committed.applied_log_index() >= read));
    assert!(committed.applied_log_index() >= close_index);
    assert_eq!(committed.requirement(), &requirement);
    assert_eq!(committed.group_id(), TEST_GROUP);
    assert_eq!(committed.authority_id(), authority);
    assert_eq!(committed.storage_generation(), 1);
    let drain = committed.drain();
    let floor = drain.scope.as_ref().context("scope floor after close")?;
    assert_eq!(floor.key.scope_kind, scope_kind);
    assert_eq!(floor.key.scope_id, scope_id);
    assert_eq!(floor.lifecycle, ScopeLifecycle::Closing);
    assert_eq!(floor.authz_floor, 1);
    assert_eq!(
        drain.open_decision_ids.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([decision_a, decision_b])
    );
    assert_eq!(
        drain.pending_operation_ids.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([operation_a, operation_b])
    );
    assert!(drain.settled_terminal_operations.is_empty());

    let probe = committed.clone().into_linearizable_scope_probe(&requirement)?;
    assert_eq!(probe.source, AuthoritySourceKind::RaftReadIndexQuorum);
    assert_eq!(probe.read_log_index, committed.read_log_index());
    assert_eq!(probe.applied_log_index, committed.applied_log_index());
    assert_eq!(&probe.drain, committed.drain());

    phase.set(ScopePhase::BindingRejections);
    let wrong_scope_id = Uuid::new_v4();
    let wrong_close = RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
        scope_kind: scope_kind.into(),
        scope_id: wrong_scope_id,
        repository_id: Some(repo_a),
        tenant_id: Some(tenant),
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 2,
        change_id: Uuid::new_v4(),
        logical_tick: 2,
    });
    let wrong_close_outcome = backend_a.propose(wrong_close).await?;
    assert!(proposal_outcome(&wrong_close_outcome).is_applied());
    let wrong_requirement = backend_a.recover_scope_close_requirement(wrong_close_outcome.proposal_id.clone()).await?;
    assert_eq!(wrong_requirement.scope_id(), wrong_scope_id);
    assert_eq!(wrong_requirement.required_authz_floor(), 2);
    assert!(matches!(
        committed.clone().into_linearizable_scope_probe(&wrong_requirement),
        Err(RaftBackendError::ScopeDrainBindingMismatch("close requirement"))
    ));
    let wrong_committed = leader_node.read_scope_drain(&wrong_requirement, options).await?;
    assert!(matches!(
        wrong_committed.into_linearizable_scope_probe(&requirement),
        Err(RaftBackendError::ScopeDrainBindingMismatch("close requirement"))
    ));

    phase.set(ScopePhase::ForeignBootstrap);
    let foreign_group = "group-175-foreign";
    let foreign_authority = Uuid::new_v4();
    let foreign_storage = 2;
    let foreign_trust = NodeTrust::new(foreign_group, foreign_authority, foreign_storage)?;
    let foreign_tenant = Uuid::new_v4();
    let foreign_history = Uuid::new_v4();
    let foreign_realm = RealmBinding::new(
        foreign_tenant,
        foreign_group,
        foreign_authority,
        foreign_history,
        1,
        1,
        GitObjectFormat::Sha256,
        foreign_storage,
    )?;
    let foreign_cluster = TestCluster::start_three(foreign_trust.clone()).await?;
    let (foreign_leader, _) = foreign_cluster.wait_leader(Duration::from_secs(20)).await?;
    let foreign_repo = Uuid::new_v4();
    let foreign_backend =
        backend_on(&foreign_cluster, foreign_leader, foreign_repo, foreign_tenant, foreign_realm, options).await?;
    let foreign_init = observe_call(
        phase,
        &foreign_cluster,
        Operation::ClientWrite,
        foreign_backend.propose(init_command(foreign_repo, foreign_tenant, foreign_history)),
    )
    .await?;
    assert!(proposal_outcome(&foreign_init).is_applied());
    phase.set(ScopePhase::ForeignAdvance);
    let mut foreign_rounds = 0_u64;
    while foreign_cluster
        .node(foreign_leader)
        .node
        .metrics()
        .last_applied
        .is_none_or(|log_id| log_id.index <= close_index)
    {
        assert!(
            proposal_outcome(&foreign_backend.propose(RefCasCommand::Noop(NoopCommand { logical_tick: None })).await?)
                .is_applied()
        );
        foreign_rounds += 1;
        if foreign_rounds > 64 {
            bail!("foreign cluster did not advance past the close coordinate");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    wait_applied_through(&foreign_cluster, close_index + 1, Duration::from_secs(10)).await?;
    let foreign_applied =
        foreign_cluster.node(foreign_leader).node.metrics().last_applied.map(|log_id| log_id.index).unwrap_or(0);
    assert!(foreign_applied > close_index);
    phase.set(ScopePhase::ForeignRejection);
    assert!(matches!(
        foreign_cluster.node(foreign_leader).node.read_scope_drain(&requirement, options).await,
        Err(RaftBackendError::ScopeDrainBindingMismatch("node trust"))
    ));
    let _ = foreign_cluster.shutdown().await;

    phase.set(ScopePhase::PendingBridge);
    let polled_node = leader_node.clone();
    let polled_requirement = requirement.clone();
    let status = await_drain_before_revocation_ack(
        polled_requirement.scope_kind(),
        polled_requirement.scope_id(),
        polled_requirement.required_authz_floor(),
        polled_requirement.close_log_id().index,
        Duration::from_secs(2),
        Duration::from_millis(20),
        || {
            let node = polled_node.clone();
            let requirement = polled_requirement.clone();
            async move {
                node.read_scope_drain(&requirement, options)
                    .await
                    .and_then(|committed| committed.into_linearizable_scope_probe(&requirement))
                    .map_err(|error| error.to_string())
            }
        },
    )
    .await?;
    assert!(matches!(&status, RevocationDrainStatus::DrainInProgress { .. }));
    assert!(!status.can_ack_revocation());

    phase.set(ScopePhase::Cancel);
    let cancel_a = cancel_command(repo_a, operation_a, 2);
    let cancel_b = cancel_command(repo_b, operation_b, 3);
    assert!(proposal_outcome(&backend_a.propose(cancel_a).await?).is_applied());
    assert!(proposal_outcome(&backend_b.propose(cancel_b).await?).is_applied());

    phase.set(ScopePhase::SettledDrain);
    let drained = leader_node.read_scope_drain(&requirement, options).await?;
    assert!(drained.drain().open_decision_ids.is_empty());
    assert!(drained.drain().pending_operation_ids.is_empty());
    assert_eq!(drained.drain().settled_terminal_operations.len(), 2);
    assert_eq!(drained.drain().settled_terminal_operations.get(&operation_a), Some(&OperationState::Cancelled));
    assert_eq!(drained.drain().settled_terminal_operations.get(&operation_b), Some(&OperationState::Cancelled));
    assert!(drained.drain().settled_terminal_operations.values().all(|state| state.is_terminal()));

    phase.set(ScopePhase::SettledEvaluate);
    let drained_probe = drained.clone().into_linearizable_scope_probe(&requirement)?;
    let evaluated = evaluate_revocation_drain_barrier(
        &drained_probe,
        requirement.scope_kind(),
        requirement.scope_id(),
        requirement.required_authz_floor(),
        requirement.close_log_id().index,
    )?;
    assert!(evaluated.can_ack_revocation());
    match &evaluated {
        RevocationDrainStatus::DrainedAndConfirmed { confirmed_operations, .. } => {
            let confirmed: BTreeSet<Uuid> = confirmed_operations.iter().map(|terminal| terminal.operation_id).collect();
            assert_eq!(confirmed, BTreeSet::from([operation_a, operation_b]));
            assert!(confirmed_operations.iter().all(|terminal| terminal.state.is_terminal()));
        }
        other => panic!("checked drained probe was not confirmed: {other:?}"),
    }

    phase.set(ScopePhase::SettledBridge);
    let drained_node = leader_node.clone();
    let drained_requirement = requirement.clone();
    let final_status = await_drain_before_revocation_ack(
        drained_requirement.scope_kind(),
        drained_requirement.scope_id(),
        drained_requirement.required_authz_floor(),
        drained_requirement.close_log_id().index,
        Duration::from_secs(2),
        Duration::from_millis(20),
        || {
            let node = drained_node.clone();
            let requirement = drained_requirement.clone();
            async move {
                node.read_scope_drain(&requirement, options)
                    .await
                    .and_then(|committed| committed.into_linearizable_scope_probe(&requirement))
                    .map_err(|error| error.to_string())
            }
        },
    )
    .await?;
    assert!(final_status.can_ack_revocation());
    match &final_status {
        RevocationDrainStatus::DrainedAndConfirmed { confirmed_operations, .. } => {
            let confirmed: BTreeSet<Uuid> = confirmed_operations.iter().map(|terminal| terminal.operation_id).collect();
            assert_eq!(confirmed, BTreeSet::from([operation_a, operation_b]));
            assert!(confirmed_operations.iter().all(|terminal| terminal.state.is_terminal()));
        }
        other => panic!("await drain did not confirm the drained scope: {other:?}"),
    }

    phase.set(ScopePhase::Follower);
    let follower_id = cluster.first_follower_id(leader_id);
    assert!(matches!(
        cluster.node(follower_id).node.read_scope_drain(&requirement, options).await,
        Err(RaftBackendError::FollowerRedirect(Some(id))) if id == leader_id
    ));

    phase.set(ScopePhase::InvalidOptions);
    let invalid_options = BackendOptions {
        quorum_timeout: Duration::ZERO,
        apply_timeout: Duration::from_millis(100),
        poll_interval: Duration::from_millis(10),
    };
    assert!(matches!(
        leader_node.read_scope_drain(&requirement, invalid_options).await,
        Err(RaftBackendError::InvalidConfig(_))
    ));

    phase.set(ScopePhase::Partition);
    let (current_leader, _) = cluster.wait_leader(Duration::from_secs(10)).await?;
    let isolated = cluster.node(current_leader).node.clone();
    let no_quorum_options = BackendOptions {
        quorum_timeout: Duration::from_millis(300),
        apply_timeout: Duration::from_millis(300),
        poll_interval: Duration::from_millis(20),
    };
    cluster.partition_node(current_leader);
    let no_quorum = isolated.read_scope_drain(&requirement, no_quorum_options).await;
    assert!(
        matches!(no_quorum, Err(RaftBackendError::QuorumUnavailable(_)) | Err(RaftBackendError::FollowerRedirect(_))),
        "isolated scope drain must fail closed: {no_quorum:?}"
    );
    cluster.heal_partitions();
    phase.set(ScopePhase::Heal);
    let _ = cluster.wait_leader(Duration::from_secs(20)).await?;
    phase.set(ScopePhase::Shutdown);
    let _ = cluster.shutdown().await;
    Ok(())
}
