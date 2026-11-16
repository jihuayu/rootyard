//! Quorum-bound scope-drain API tests for the real three-node backend.
//!
//! This module uses only the exported `RootRaftNode::read_scope_drain` /
//! `CommittedScopeDrain::into_linearizable_scope_probe` surface and the existing bridge callback.
//! It is an in-process three-node Raft test, not multi-host or production qualification.

use super::*;
use anyhow::Context;
use rootyard::ref_store::core::state_machine::{
    CloseAuthScopeCommand, InstallDecisionCommand, InstallScopedDecisionCommand, WireDecisionGrantCommitment,
    WireDecisionKind, WireDecisionScopeDep, WireDecisionVerdict,
};
use rootyard::ref_store::projector::{AuthoritySourceKind, RevocationDrainStatus, await_drain_before_revocation_ack};
use rootyard::ref_store::raft_backend::RootRefCasApplied;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privileged_scope_drain_query_is_quorum_bound_and_multirepo_complete() -> Result<()> {
    let tenant = Uuid::new_v4();
    let history = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let trust = NodeTrust::new(TEST_GROUP, authority, 1)?;
    let realm = RealmBinding::new(tenant, TEST_GROUP, authority, history, 1, 1, GitObjectFormat::Sha256, 1)?;
    let cluster = TestCluster::start_three(trust.clone()).await?;
    let (leader_id, _) = cluster.wait_leader(Duration::from_secs(20)).await?;
    let options = BackendOptions {
        quorum_timeout: Duration::from_secs(3),
        apply_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(20),
    };

    let repo_a = Uuid::new_v4();
    let repo_b = Uuid::new_v4();
    let backend_a = backend_on(&cluster, leader_id, repo_a, tenant, realm.clone(), options).await?;
    let backend_b = backend_on(&cluster, leader_id, repo_b, tenant, realm.clone(), options).await?;
    assert!(proposal_outcome(&backend_a.propose(init_command(repo_a, tenant, history)).await?).is_applied());
    assert!(proposal_outcome(&backend_b.propose(init_command(repo_b, tenant, history)).await?).is_applied());
    let gate_a = backend_a
        .read_committed_view()
        .await?
        .read_gate_version()?
        .context("repo A gate after init")?
        .digest()
        .as_hex();
    let gate_b = backend_b
        .read_committed_view()
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
    let install_a =
        install_scoped_command(repo_a, tenant, decision_a, operation_a, Uuid::new_v4(), scope_kind, scope_id, gate_a);
    let install_b =
        install_scoped_command(repo_b, tenant, decision_b, operation_b, Uuid::new_v4(), scope_kind, scope_id, gate_b);
    assert!(proposal_outcome(&backend_a.propose(install_a).await?).is_applied());
    assert!(proposal_outcome(&backend_b.propose(install_b).await?).is_applied());

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

    let leader_node = cluster.node(leader_id).node.clone();
    let committed = leader_node.read_scope_drain(scope_kind, scope_id, close_index, options).await?;
    assert!(committed.read_log_index().is_some());
    assert!(committed.read_log_index().is_some_and(|read| committed.applied_log_index() >= read));
    assert!(committed.applied_log_index() >= close_index);
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

    let probe = committed.clone().into_linearizable_scope_probe();
    assert_eq!(probe.source, AuthoritySourceKind::RaftReadIndexQuorum);
    assert_eq!(probe.read_log_index, committed.read_log_index());
    assert_eq!(probe.applied_log_index, committed.applied_log_index());
    assert_eq!(&probe.drain, committed.drain());

    let polled_node = leader_node.clone();
    let status = await_drain_before_revocation_ack(
        scope_kind,
        scope_id,
        1,
        close_index,
        Duration::from_secs(2),
        Duration::from_millis(20),
        || {
            let node = polled_node.clone();
            async move {
                node.read_scope_drain(scope_kind, scope_id, close_index, options)
                    .await
                    .map(|committed| committed.into_linearizable_scope_probe())
                    .map_err(|error| error.to_string())
            }
        },
    )
    .await?;
    assert!(matches!(&status, RevocationDrainStatus::DrainInProgress { .. }));
    assert!(!status.can_ack_revocation());

    let follower_id = cluster.first_follower_id(leader_id);
    assert!(matches!(
        cluster
            .node(follower_id)
            .node
            .read_scope_drain(scope_kind, scope_id, close_index, options)
            .await,
        Err(RaftBackendError::FollowerRedirect(Some(id))) if id == leader_id
    ));

    let invalid_options = BackendOptions {
        quorum_timeout: Duration::ZERO,
        apply_timeout: Duration::from_millis(100),
        poll_interval: Duration::from_millis(10),
    };
    assert!(matches!(
        leader_node.read_scope_drain(scope_kind, scope_id, close_index, invalid_options).await,
        Err(RaftBackendError::InvalidConfig(_))
    ));
    assert!(matches!(
        leader_node.read_scope_drain("unknown-scope-kind", scope_id, close_index, options).await,
        Err(RaftBackendError::Command(_))
    ));
    assert!(matches!(
        leader_node.read_scope_drain(scope_kind, Uuid::nil(), close_index, options).await,
        Err(RaftBackendError::Command(_))
    ));

    let (current_leader, _) = cluster.wait_leader(Duration::from_secs(10)).await?;
    let isolated = cluster.node(current_leader).node.clone();
    let no_quorum_options = BackendOptions {
        quorum_timeout: Duration::from_millis(300),
        apply_timeout: Duration::from_millis(300),
        poll_interval: Duration::from_millis(20),
    };
    cluster.partition_node(current_leader);
    let no_quorum = isolated.read_scope_drain(scope_kind, scope_id, close_index, no_quorum_options).await;
    assert!(
        matches!(no_quorum, Err(RaftBackendError::QuorumUnavailable(_)) | Err(RaftBackendError::FollowerRedirect(_))),
        "isolated scope drain must fail closed: {no_quorum:?}"
    );
    cluster.heal_partitions();
    let _ = cluster.wait_leader(Duration::from_secs(20)).await?;
    let _ = cluster.shutdown().await;
    Ok(())
}
