//! Production Ref-CAS PR-merge fixture over a live 3-node Raft cluster: forced scans (#122).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use anyhow::{Result, ensure};
use rootyard::{
    AppState,
    pulls::remote_merge_finalizer::{
        CheckRunSnapshot, InMemoryMergeStore, LiveAuthzScopeState, MergeAttemptOutcome, MergeAttemptSpec,
        MergeBindingInputs, MergeFaultInjection, MergePullSnapshot, MergeStrategy, ProjectedPullRecord,
        PullRemoteMergeProducer, compute_merge_binding_digest,
    },
    ref_store::{
        CommitRefsRequest, IssuerLane,
        core::{
            contract::CommitMode,
            state_machine::{
                CommitRefsCommand, InitializeGateCommand, RefCasCommand, RefCasStateMachine, RepositoryLane,
                ScopeLifecycle, SmPackMode, WireCommitRefsRequest, WireDecisionKind, WireDecisionScopeDep,
                WireDecisionVerdict, WireGateInit,
            },
            types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate},
        },
        projector::{DecisionGrantKeyring, GrantExpectedRealm, SignedDecisionGrantPayload},
    },
    storage_lifecycle::{models::Policy, scheduler},
};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::raft_voter_cluster::{LiveRaft3MergeBackend, LiveRaftVoterCluster};

pub(super) async fn force_scan_and_schedule(
    state: &Arc<AppState>,
    pool: &deadpool_postgres::Pool,
    policy: &Policy,
    repo_id: Uuid,
) -> Result<()> {
    pool.get()
        .await?
        .execute("UPDATE storage_maintenance_repo_state SET last_scan_at = NULL WHERE repository_id = $1", &[&repo_id])
        .await?;
    assert_eq!(scheduler::schedule_once(state, policy).await?, 1);
    Ok(())
}

/// Reusable live Raft authority for a production Ref-CAS merge test.
pub(super) struct RefCasMergeRig {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub backend: LiveRaft3MergeBackend,
    pub keyring: DecisionGrantKeyring,
    pub token_scope_id: Uuid,
}

/// Seed the Ref-CAS gate and `refs/heads/main = base_oid` through the live Raft log.
pub(super) async fn build_refcas_merge_rig(
    cluster: Arc<AsyncMutex<LiveRaftVoterCluster>>,
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
    base_oid: &str,
) -> Result<RefCasMergeRig> {
    let fmt = GitObjectFormat::Sha1;
    let token_scope_id = Uuid::new_v4();
    let keyring = DecisionGrantKeyring::new([(1, Zeroizing::new([0x5a; 32]))], 1, BTreeSet::new()).unwrap();
    let backend = LiveRaft3MergeBackend::new(cluster);
    let init = RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit {
            repository_id: repo_id,
            tenant_id,
            object_format: fmt,
            history_incarnation: history_id,
            authority_epoch: 1,
            group_epoch: 1,
            head_ref: "refs/heads/main".into(),
        },
        lane: RepositoryLane::ServingRefStore,
        pack_mode: SmPackMode::MetadataOnly,
        authz_floor: 1,
    });
    let seed_req = CommitRefsRequest::new(
        repo_id,
        tenant_id,
        tenant_id,
        IssuerLane::new("seed").unwrap(),
        1,
        Uuid::new_v4(),
        fmt,
        history_id,
        1,
        1,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![RefUpdate::new(
            RefName::branch("refs/heads/main").unwrap(),
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::parse(fmt, base_oid).unwrap()),
        )],
    )
    .unwrap();
    let seed = RefCasCommand::CommitRefs(CommitRefsCommand {
        request: WireCommitRefsRequest::from(&seed_req),
        decision_id: None,
        required_holds: vec![],
        policy_rejects: BTreeMap::new(),
        logical_tick: 1,
    });
    backend.apply_repo_command(init).await.map_err(|err| anyhow::anyhow!("seed Ref-CAS gate through Raft: {err}"))?;
    backend
        .apply_repo_command(seed)
        .await
        .map_err(|err| anyhow::anyhow!("seed refs/heads/main through Raft: {err}"))?;
    ensure!(
        backend.state_machine().await?.read_refs(repo_id).get("refs/heads/main").map(String::as_str) == Some(base_oid),
        "Raft Ref-CAS state machine did not seed refs/heads/main"
    );
    Ok(RefCasMergeRig { tenant_id, repo_id, history_id, backend, keyring, token_scope_id })
}

/// Build the production attempt spec + pull snapshot for a fast-forward `base_oid -> head_oid`.
pub(super) async fn build_refcas_merge_attempt(
    rig: &RefCasMergeRig,
    base_oid: &str,
    head_oid: &str,
    candidate_target_oid: &str,
    pull_number: i64,
    sequence: i64,
    scope_id: Uuid,
) -> Result<(MergeAttemptSpec, MergePullSnapshot)> {
    let tenant_id = rig.tenant_id;
    let repo_id = rig.repo_id;
    let history_id = rig.history_id;
    let fmt = GitObjectFormat::Sha1;
    let realm = GrantExpectedRealm {
        tenant_id,
        repository_id: repo_id,
        group_id: 0,
        group_epoch: 1,
        history_incarnation: history_id,
        authority_epoch: 1,
    };
    let gv = rig.backend.state_machine().await?.read_gate_version(repo_id)?.ok_or_else(|| {
        anyhow::anyhow!("seeded Ref-CAS gate has no version; rebuild the merge rig after seeding the gate")
    })?;
    let checks = vec!["ci/verify".to_owned()];
    let pull = MergePullSnapshot {
        tenant_id,
        repository_id: repo_id,
        pull_number,
        state: "open".into(),
        head_ref: format!("refs/heads/pr-{pull_number}"),
        base_ref: "refs/heads/main".into(),
        head_oid: head_oid.into(),
        base_oid: base_oid.into(),
        merge_commit_oid: None,
        version: 1,
        storage_generation: 1,
        object_format: fmt,
        live_head_ref_oid: head_oid.into(),
        live_base_ref_oid: base_oid.into(),
        require_fast_forward: true,
        required_checks: checks.clone(),
        min_check_sequence: 1,
        observed_checks: vec![CheckRunSnapshot {
            context: "ci/verify".into(),
            commit_oid: head_oid.into(),
            base_oid: Some(base_oid.into()),
            status: "completed".into(),
            conclusion: Some("success".into()),
            sequence: 1,
            attempt: 1,
            trusted: true,
        }],
    };
    let (op, dec) = (Uuid::new_v4(), Uuid::new_v4());
    let d = "11".repeat(32);
    let creq = CommitRefsRequest::new(
        repo_id,
        tenant_id,
        tenant_id,
        IssuerLane::new("pull-merge").unwrap(),
        sequence,
        op,
        fmt,
        history_id,
        1,
        1,
        gv.revision(),
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![RefUpdate::new(
            RefName::branch("refs/heads/main").unwrap(),
            RefPrecondition::Present(GitOid::parse(fmt, base_oid).unwrap()),
            RefTarget::Oid(GitOid::parse(fmt, candidate_target_oid).unwrap()),
        )],
    )
    .unwrap();
    let facts = compute_merge_binding_digest(&MergeBindingInputs {
        tenant_id,
        repository_id: repo_id,
        pull_number,
        actor_id: tenant_id,
        operation_id: op,
        decision_id: dec,
        base_ref: "refs/heads/main",
        expected_head_oid: head_oid,
        expected_base_oid: base_oid,
        candidate_target_oid,
        strategy: MergeStrategy::FastForward,
        expected_version: 1,
        expected_storage_generation: 1,
        required_checks: &checks,
        min_check_sequence: 1,
        observed_checks: &pull.observed_checks,
        authz_epoch: 3,
        pack_sha256: &d,
    });
    let grant = rig
        .keyring
        .sign(SignedDecisionGrantPayload {
            format_version: 1,
            key_id: 1,
            issuer_id: tenant_id,
            service_mtls_identity: "raft-bridge-pulls-it".into(),
            decision_id: dec,
            tenant_id,
            repository_id: repo_id,
            actor_id: tenant_id,
            operation_id: op,
            group_id: 0,
            group_epoch: 1,
            history_incarnation: history_id,
            authority_epoch: 1,
            authz_epoch: 3,
            base_revision: gv.revision(),
            kind: WireDecisionKind::Atomic,
            not_after_tick: 1000,
            command_digest: creq.digest().as_hex(),
            selection_digest: d.clone(),
            policy_digest: d.clone(),
            facts_digest: facts,
            authz_digest: d.clone(),
            dependencies_digest: d.clone(),
            packs_digest: d.clone(),
            hold_receipts_digest: d.clone(),
            captured_oid_digest: d.clone(),
            base_gate_digest: gv.digest().as_hex(),
            required_holds: vec![],
            verdicts: vec![WireDecisionVerdict {
                ref_name: "refs/heads/main".into(),
                accepted: true,
                reject_code: None,
            }],
            scope_dependencies: vec![WireDecisionScopeDep {
                scope_kind: "token".into(),
                scope_id,
                observed_version: 1,
                observed_digest: d.clone(),
            }],
        })
        .unwrap();
    let spec = MergeAttemptSpec {
        attempt_id: Uuid::new_v4(),
        operation_id: op,
        decision_id: dec,
        tenant_id,
        repository_id: repo_id,
        actor_id: tenant_id,
        lane: "pull-merge".into(),
        sequence,
        pull_number,
        base_ref: "refs/heads/main".into(),
        expected_head_oid: head_oid.into(),
        expected_base_oid: base_oid.into(),
        candidate_target_oid: candidate_target_oid.into(),
        expected_version: 1,
        expected_storage_generation: 1,
        expected_base_revision: gv.revision(),
        strategy: MergeStrategy::FastForward,
        object_format: fmt,
        realm,
        expected_service_san: "raft-bridge-pulls-it".into(),
        grant,
        current_logical_tick: 10,
        live_scopes: vec![LiveAuthzScopeState {
            scope_kind: "token".into(),
            scope_id,
            lifecycle: ScopeLifecycle::Open,
            authz_floor: 1,
        }],
        cancelled_operations: BTreeSet::new(),
        pack_sha256: d,
    };
    Ok((spec, pull))
}

/// Commit `refs/heads/main` (`base_oid -> main_oid`) through the production
/// `PullRemoteMergeProducer::execute_merge` path, with the OpenRaft log as the sole commit point.
pub(super) async fn production_refcas_pr_merge(
    rig: &RefCasMergeRig,
    base_oid: &str,
    main_oid: &str,
) -> Result<RefCasStateMachine> {
    let merge_store = InMemoryMergeStore::new();
    merge_store.seed_pull(ProjectedPullRecord {
        tenant_id: rig.tenant_id,
        repository_id: rig.repo_id,
        pull_number: 1,
        state: "open".into(),
        head_oid: main_oid.into(),
        base_oid: base_oid.into(),
        merge_commit_oid: None,
        merged_storage_generation: None,
        version: 1,
    });
    let (spec, pull) = build_refcas_merge_attempt(rig, base_oid, main_oid, main_oid, 1, 1, rig.token_scope_id).await?;
    let merge_out = PullRemoteMergeProducer::new(&rig.backend, &merge_store, &rig.keyring)
        .execute_merge(&spec, &pull, true, MergeFaultInjection::None)
        .await?;
    ensure!(matches!(merge_out, MergeAttemptOutcome::Committed(_)), "production Ref-CAS PR merge was not committed");
    let sm = rig.backend.state_machine().await?;
    ensure!(
        sm.read_refs(rig.repo_id).get("refs/heads/main").map(String::as_str) == Some(main_oid),
        "Raft Ref-CAS state machine did not commit refs/heads/main"
    );
    Ok(sm)
}
