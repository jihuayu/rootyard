//! Trusted repository/tenant/realm command-scope validation before Raft append.

use uuid::Uuid;

use crate::ref_store::CoreGateVersion;
use crate::ref_store::core::state_machine::{RefCasCommand, SetRepositoryLaneCommand, WireCommitRefsRequest};
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::raft_backend::error::RaftBackendError;
use crate::ref_store::raft_backend::outcome::RootRefCasRefusalKind;
use crate::ref_store::raft_backend::proposal::ProposalId;
use crate::ref_store::raft_backend::realm::RealmBinding;

struct CommandScope {
    repository_id: Option<Uuid>,
    identity_repository_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    group_epoch: Option<i64>,
    authority_id: Option<Uuid>,
    history_incarnation: Option<Uuid>,
    authority_epoch: Option<i64>,
    object_format: Option<GitObjectFormat>,
}

fn base(
    repository_id: Uuid,
    tenant_id: Option<Uuid>,
    group_epoch: Option<i64>,
    authority_id: Option<Uuid>,
) -> CommandScope {
    CommandScope {
        repository_id: Some(repository_id),
        identity_repository_id: None,
        tenant_id,
        group_epoch,
        authority_id,
        history_incarnation: None,
        authority_epoch: None,
        object_format: None,
    }
}

fn commit_request_scope(request: &WireCommitRefsRequest) -> CommandScope {
    CommandScope {
        // The operation identity duplicates the request repository. Bind it here as well so a
        // malformed command fails backend preflight instead of relying only on the core
        // conversion, which keeps its own InvalidIdentity defense.
        identity_repository_id: Some(request.identity.repository_id),
        history_incarnation: Some(request.history_incarnation),
        authority_epoch: Some(request.authority_epoch),
        object_format: Some(request.object_format),
        ..base(request.repository_id, Some(request.tenant_id), Some(request.group_epoch), None)
    }
}

/// Commands that are the controlled gate transition (or gate-independent) cannot be blocked by
/// the old live gate. Every other command must pass a live-gate ReadIndex precheck.
pub(crate) fn requires_live_gate_precheck(command: &RefCasCommand) -> bool {
    !matches!(command, RefCasCommand::InitializeGate(_) | RefCasCommand::Noop(_) | RefCasCommand::SetRepositoryLane(_))
}

/// Rejects a command whose business coordinates are outside the backend's trusted binding.
/// It never infers a tenant from a caller-supplied string or from a Raft term.
pub(crate) fn validate_command_scope(
    command: &RefCasCommand,
    repository_id: Uuid,
    tenant_id: Uuid,
    realm: &RealmBinding,
) -> Result<(), RaftBackendError> {
    let scope = match command {
        RefCasCommand::Noop(_) => return Ok(()),
        RefCasCommand::InitializeGate(cmd) => CommandScope {
            history_incarnation: Some(cmd.gate.history_incarnation),
            authority_epoch: Some(cmd.gate.authority_epoch),
            object_format: Some(cmd.gate.object_format),
            ..base(cmd.gate.repository_id, Some(cmd.gate.tenant_id), Some(cmd.gate.group_epoch), None)
        },
        RefCasCommand::SetRepositoryLane(cmd) => CommandScope {
            history_incarnation: Some(cmd.history_incarnation),
            authority_epoch: Some(cmd.authority_epoch),
            ..base(cmd.repository_id, Some(cmd.tenant_id), Some(cmd.group_epoch), None)
        },
        RefCasCommand::BeginOperation(cmd) => base(cmd.identity.repository_id, None, None, None),
        RefCasCommand::CommitRefs(cmd) => commit_request_scope(&cmd.request),
        RefCasCommand::CommitScopedRefs(cmd) => commit_request_scope(&cmd.commit.request),
        RefCasCommand::Cancel(cmd) => base(cmd.identity.repository_id, None, None, None),
        RefCasCommand::AdvanceCancelCutoff(cmd) => base(cmd.repository_id, None, None, None),
        RefCasCommand::InstallDecision(cmd) => base(cmd.repository_id, Some(cmd.tenant_id), None, None),
        RefCasCommand::InstallScopedDecision(cmd) => {
            base(cmd.decision.repository_id, Some(cmd.decision.tenant_id), None, None)
        }
        RefCasCommand::CloseAuthScope(cmd) => CommandScope {
            // A closing-auth-scope row may name a global scope; only the optional axes actually
            // present are constrained. The proposal identity is still live-gate fenced.
            repository_id: cmd.repository_id,
            identity_repository_id: None,
            tenant_id: cmd.tenant_id,
            group_epoch: None,
            authority_id: None,
            history_incarnation: None,
            authority_epoch: None,
            object_format: None,
        },
        RefCasCommand::CreateSnapshotPin(cmd) => CommandScope {
            history_incarnation: Some(cmd.history_incarnation),
            authority_epoch: Some(cmd.authority_epoch),
            object_format: Some(cmd.object_format),
            ..base(cmd.repository_id, Some(cmd.tenant_id), Some(cmd.group_epoch), None)
        },
        RefCasCommand::RenewPin(cmd) => base(cmd.repository_id, Some(cmd.tenant_id), None, None),
        RefCasCommand::ReleasePin(cmd) => base(cmd.repository_id, Some(cmd.tenant_id), None, None),
        RefCasCommand::RegisterRoot(cmd) => CommandScope {
            history_incarnation: Some(cmd.history_incarnation),
            authority_epoch: Some(cmd.authority_epoch),
            object_format: Some(cmd.object_format),
            ..base(cmd.repository_id, Some(cmd.tenant_id), Some(cmd.group_epoch), None)
        },
        RefCasCommand::ReleaseRoot(cmd) => base(cmd.repository_id, Some(cmd.tenant_id), None, None),
        RefCasCommand::AcquireHoldBatch(cmd) => {
            base(cmd.repository_id, Some(cmd.tenant_id), None, Some(cmd.authority_id))
        }
        RefCasCommand::MarkHoldConsumed(cmd) => base(cmd.repository_id, Some(cmd.tenant_id), None, None),
        RefCasCommand::RetireHoldBatch(cmd) => base(cmd.repository_id, Some(cmd.tenant_id), None, None),
    };

    if let (Some(outer_repository_id), Some(identity_repository_id)) =
        (scope.repository_id, scope.identity_repository_id)
        && outer_repository_id != identity_repository_id
    {
        return Err(RaftBackendError::ScopeMismatch("repository_id"));
    }
    if scope.repository_id.is_some_and(|value| value != repository_id) {
        return Err(RaftBackendError::ScopeMismatch("repository_id"));
    }
    if scope.tenant_id.is_some_and(|value| value != tenant_id) {
        return Err(RaftBackendError::ScopeMismatch("tenant_id"));
    }
    if let Some(epoch) = scope.group_epoch {
        let expected = i64::try_from(realm.group_epoch())
            .map_err(|_| RaftBackendError::InvalidConfig("group_epoch does not fit command i64"))?;
        if epoch != expected {
            return Err(RaftBackendError::ScopeMismatch("group_epoch"));
        }
    }
    if let Some(authority_id) = scope.authority_id
        && authority_id != realm.authority_id()
    {
        return Err(RaftBackendError::ScopeMismatch("authority_id"));
    }
    if scope.history_incarnation.is_some_and(|value| value != realm.history_id()) {
        return Err(RaftBackendError::ScopeMismatch("history_incarnation"));
    }
    if scope.authority_epoch.is_some_and(|value| value != realm.authority_epoch()) {
        return Err(RaftBackendError::ScopeMismatch("authority_epoch"));
    }
    if scope.object_format.is_some_and(|value| value != realm.object_format()) {
        return Err(RaftBackendError::ScopeMismatch("object_format"));
    }
    Ok(())
}

/// Atomic apply-time fence. Called after First-receipt replay/conflict and after command/identity
/// matching, immediately before first business execution. A `Some` result is a bounded typed
/// refusal; the caller advances only the no-tick coordinate.
pub(crate) fn fence_proposal_against_gate(
    live: Option<&CoreGateVersion>,
    proposal: &ProposalId,
    command: &RefCasCommand,
) -> Option<RootRefCasRefusalKind> {
    match command {
        RefCasCommand::InitializeGate(_) => None,
        RefCasCommand::Noop(command) if command.logical_tick.is_none() => None,
        RefCasCommand::SetRepositoryLane(command) => fence_set_lane(
            live,
            command.repository_id,
            command.tenant_id,
            command.history_incarnation,
            command.group_epoch,
            command.authority_epoch,
            Some(proposal.object_format),
        ),
        _ => {
            let Some(live) = live else {
                return Some(RootRefCasRefusalKind::RepositoryNotFound);
            };
            if proposal_matches_live_gate(live, proposal) {
                None
            } else {
                Some(RootRefCasRefusalKind::GateScopeRefused)
            }
        }
    }
}

/// Raw legacy commands carry no stable full proposal identity. Apply the minimum SetRepositoryLane
/// monotonic history/epoch fence only; do not claim a full scope check that the wire cannot prove.
pub(crate) fn fence_legacy_set_lane(
    live: Option<&CoreGateVersion>,
    command: &SetRepositoryLaneCommand,
) -> Option<RootRefCasRefusalKind> {
    fence_set_lane(
        live,
        command.repository_id,
        command.tenant_id,
        command.history_incarnation,
        command.group_epoch,
        command.authority_epoch,
        None,
    )
}

fn fence_set_lane(
    live: Option<&CoreGateVersion>,
    repository_id: Uuid,
    tenant_id: Uuid,
    history: Uuid,
    group_epoch: i64,
    authority_epoch: i64,
    object_format: Option<GitObjectFormat>,
) -> Option<RootRefCasRefusalKind> {
    let Some(live) = live else {
        return Some(RootRefCasRefusalKind::RepositoryNotFound);
    };
    if live.repository_id() != repository_id || live.tenant_id() != tenant_id {
        return Some(RootRefCasRefusalKind::GateTransitionRefused);
    }
    if group_epoch < live.group_epoch() || authority_epoch < live.authority_epoch() {
        return Some(RootRefCasRefusalKind::GateTransitionRefused);
    }
    if history != live.history_incarnation()
        && group_epoch == live.group_epoch()
        && authority_epoch == live.authority_epoch()
    {
        return Some(RootRefCasRefusalKind::GateTransitionRefused);
    }
    if object_format.is_some_and(|format| format != live.object_format()) {
        return Some(RootRefCasRefusalKind::GateTransitionRefused);
    }
    None
}

fn proposal_matches_live_gate(live: &CoreGateVersion, proposal: &ProposalId) -> bool {
    live.repository_id() == proposal.repository_id
        && live.tenant_id() == proposal.tenant_id
        && live.history_incarnation() == proposal.history_id
        && i64::try_from(proposal.group_epoch).is_ok_and(|epoch| epoch == live.group_epoch())
        && live.authority_epoch() == proposal.authority_epoch
        && live.object_format() == proposal.object_format
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::CommitMode;
    use crate::ref_store::core::contract::CoreGate;
    use crate::ref_store::core::state_machine::{
        CloseAuthScopeCommand, CommitRefsCommand, CommitScopedRefsCommand, InitializeGateCommand,
        InstallDecisionCommand, InstallScopedDecisionCommand, NoopCommand, RepositoryLane, ScopeLifecycle,
        SetRepositoryLaneCommand, SmPackMode, WireCommitRefsRequest, WireDecisionGrantCommitment, WireDecisionKind,
        WireDecisionScopeDep, WireDecisionVerdict, WireGateInit, WireHeadUpdate, WireHeadUpdateKind,
        WireOperationIdentity,
    };
    use crate::ref_store::{CommitRefsRequest, CoreGateInit, RefName, RefStoreError};
    use std::collections::BTreeMap;

    fn live_gate(
        repo: Uuid,
        tenant: Uuid,
        history: Uuid,
        group_epoch: i64,
        authority_epoch: i64,
        format: GitObjectFormat,
    ) -> CoreGateVersion {
        CoreGate::new(
            repo,
            tenant,
            format,
            history,
            authority_epoch,
            group_epoch,
            RefName::branch("refs/heads/main").unwrap(),
            1,
        )
        .unwrap()
        .version()
    }

    fn proposal(
        repo: Uuid,
        tenant: Uuid,
        history: Uuid,
        group_epoch: u64,
        authority_epoch: i64,
        format: GitObjectFormat,
    ) -> ProposalId {
        ProposalId::new(
            repo,
            tenant,
            history,
            "group-a",
            group_epoch,
            Uuid::from_u128(4),
            authority_epoch,
            1,
            format,
            0,
            Uuid::from_u128(5),
        )
        .unwrap()
    }

    fn lane_command(repo: Uuid, tenant: Uuid, history: Uuid, group_epoch: i64, authority_epoch: i64) -> RefCasCommand {
        RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
            repository_id: repo,
            tenant_id: tenant,
            lane: RepositoryLane::ServingRefStore,
            lifecycle: ScopeLifecycle::Closing,
            authz_floor: 1,
            history_incarnation: history,
            authority_epoch,
            group_epoch,
            pack_mode: SmPackMode::MetadataOnly,
        })
    }

    #[test]
    fn set_lane_fence_is_componentwise_monotonic() {
        let repo = Uuid::from_u128(10);
        let tenant = Uuid::from_u128(20);
        let history = Uuid::from_u128(30);
        let live = live_gate(repo, tenant, history, 2, 2, GitObjectFormat::Sha256);
        let base = proposal(repo, tenant, history, 2, 2, GitObjectFormat::Sha256);

        // Group or authority regression, even if the other axis rises.
        assert_eq!(
            fence_proposal_against_gate(Some(&live), &base, &lane_command(repo, tenant, Uuid::from_u128(31), 1, 2)),
            Some(RootRefCasRefusalKind::GateTransitionRefused)
        );
        assert_eq!(
            fence_proposal_against_gate(Some(&live), &base, &lane_command(repo, tenant, Uuid::from_u128(31), 2, 1)),
            Some(RootRefCasRefusalKind::GateTransitionRefused)
        );
        // A new history with no strict epoch increase has no UUID ordering and is refused.
        assert_eq!(
            fence_proposal_against_gate(Some(&live), &base, &lane_command(repo, tenant, Uuid::from_u128(31), 2, 2)),
            Some(RootRefCasRefusalKind::GateTransitionRefused)
        );
        // Same history/equal epochs and ordinary lane changes are allowed.
        assert_eq!(fence_proposal_against_gate(Some(&live), &base, &lane_command(repo, tenant, history, 2, 2)), None);
        // A new history is allowed only with a strict epoch increase.
        assert_eq!(
            fence_proposal_against_gate(Some(&live), &base, &lane_command(repo, tenant, Uuid::from_u128(31), 3, 2)),
            None
        );
        assert_eq!(
            fence_proposal_against_gate(Some(&live), &base, &lane_command(repo, tenant, Uuid::from_u128(31), 2, 3)),
            None
        );
        // Same history with one epoch increase is allowed.
        assert_eq!(fence_proposal_against_gate(Some(&live), &base, &lane_command(repo, tenant, history, 3, 2)), None);
        assert_eq!(fence_proposal_against_gate(Some(&live), &base, &lane_command(repo, tenant, history, 2, 3)), None);
        // SetLane cannot change object format.
        let sha1 = proposal(repo, tenant, Uuid::from_u128(31), 3, 2, GitObjectFormat::Sha1);
        assert_eq!(
            fence_proposal_against_gate(Some(&live), &sha1, &lane_command(repo, tenant, Uuid::from_u128(31), 3, 2)),
            Some(RootRefCasRefusalKind::GateTransitionRefused)
        );
        // Repository/tenant must match the actual live gate exactly.
        assert_eq!(
            fence_proposal_against_gate(Some(&live), &base, &lane_command(repo, Uuid::from_u128(21), history, 3, 2)),
            Some(RootRefCasRefusalKind::GateTransitionRefused)
        );
        assert_eq!(
            fence_proposal_against_gate(Some(&live), &base, &lane_command(Uuid::from_u128(11), tenant, history, 3, 2)),
            Some(RootRefCasRefusalKind::GateTransitionRefused)
        );
        // Missing live gate is a normal typed refusal.
        assert_eq!(
            fence_proposal_against_gate(None, &base, &lane_command(repo, tenant, history, 3, 2)),
            Some(RootRefCasRefusalKind::RepositoryNotFound)
        );
    }

    #[test]
    fn legacy_set_lane_fence_has_no_identity_or_format_claim() {
        let repo = Uuid::from_u128(10);
        let tenant = Uuid::from_u128(20);
        let history = Uuid::from_u128(30);
        let live = live_gate(repo, tenant, history, 2, 2, GitObjectFormat::Sha256);
        let RefCasCommand::SetRepositoryLane(command) = lane_command(repo, tenant, history, 2, 2) else {
            unreachable!()
        };
        assert_eq!(fence_legacy_set_lane(Some(&live), &command), None);
        let RefCasCommand::SetRepositoryLane(old) = lane_command(repo, tenant, history, 1, 1) else { unreachable!() };
        assert_eq!(fence_legacy_set_lane(Some(&live), &old), Some(RootRefCasRefusalKind::GateTransitionRefused));
        let RefCasCommand::SetRepositoryLane(foreign) = lane_command(repo, tenant, Uuid::from_u128(31), 2, 2) else {
            unreachable!()
        };
        assert_eq!(fence_legacy_set_lane(Some(&live), &foreign), Some(RootRefCasRefusalKind::GateTransitionRefused));
        let RefCasCommand::SetRepositoryLane(newer) = lane_command(repo, tenant, Uuid::from_u128(31), 3, 2) else {
            unreachable!()
        };
        assert_eq!(fence_legacy_set_lane(Some(&live), &newer), None);
    }

    #[test]
    fn ordinary_apply_fence_includes_ticking_noop_but_not_coordinate_noop() {
        let repo = Uuid::from_u128(10);
        let tenant = Uuid::from_u128(20);
        let history = Uuid::from_u128(30);
        let live = live_gate(repo, tenant, history, 1, 2, GitObjectFormat::Sha256);
        let stale = proposal(repo, tenant, Uuid::from_u128(31), 1, 2, GitObjectFormat::Sha256);
        let ticking = RefCasCommand::Noop(NoopCommand { logical_tick: Some(7) });
        assert_eq!(
            fence_proposal_against_gate(Some(&live), &stale, &ticking),
            Some(RootRefCasRefusalKind::GateScopeRefused)
        );
        let matching = proposal(repo, tenant, history, 1, 2, GitObjectFormat::Sha256);
        assert_eq!(fence_proposal_against_gate(Some(&live), &matching, &ticking), None);
        let coordinate = RefCasCommand::Noop(NoopCommand { logical_tick: None });
        assert_eq!(fence_proposal_against_gate(Some(&live), &stale, &coordinate), None);
        assert_eq!(
            fence_proposal_against_gate(None, &matching, &ticking),
            Some(RootRefCasRefusalKind::RepositoryNotFound)
        );

        let gate = CoreGateInit::new(
            repo,
            tenant,
            GitObjectFormat::Sha256,
            history,
            2,
            1,
            RefName::branch("refs/heads/main").unwrap(),
        )
        .unwrap();
        let initialize = RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&gate),
            lane: RepositoryLane::ServingRefStore,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 1,
        });
        assert_eq!(fence_proposal_against_gate(Some(&live), &stale, &initialize), None);
    }

    fn grant_commitment() -> WireDecisionGrantCommitment {
        WireDecisionGrantCommitment {
            base_gate_digest: "07".repeat(32),
            packs_digest: "08".repeat(32),
            hold_receipts_digest: "09".repeat(32),
            captured_oid_digest: "0a".repeat(32),
            required_holds: Vec::new(),
        }
    }

    fn install_scoped_command(repo: Uuid, tenant: Uuid) -> InstallScopedDecisionCommand {
        InstallScopedDecisionCommand {
            decision: InstallDecisionCommand {
                decision_id: Uuid::from_u128(40),
                repository_id: repo,
                tenant_id: tenant,
                actor_id: Uuid::from_u128(41),
                operation_id: Uuid::from_u128(42),
                kind: WireDecisionKind::Atomic,
                base_revision: 1,
                command_digest: "00".repeat(32),
                selection_digest: "01".repeat(32),
                policy_digest: "02".repeat(32),
                facts_digest: "03".repeat(32),
                authz_digest: "04".repeat(32),
                dependencies_digest: "05".repeat(32),
                verdicts: vec![WireDecisionVerdict {
                    ref_name: "refs/heads/main".to_owned(),
                    accepted: true,
                    reject_code: None,
                }],
                authz_epoch: 1,
                not_after_tick: 100,
                logical_tick: 1,
            },
            scope_dependencies: vec![WireDecisionScopeDep {
                scope_kind: "token".to_owned(),
                scope_id: Uuid::from_u128(43),
                observed_version: 1,
                observed_digest: "06".repeat(32),
            }],
            grant_commitment: grant_commitment(),
        }
    }

    fn commit_scoped_command(repo: Uuid, tenant: Uuid, history: Uuid) -> CommitScopedRefsCommand {
        CommitScopedRefsCommand {
            commit: CommitRefsCommand {
                request: WireCommitRefsRequest {
                    identity: WireOperationIdentity {
                        repository_id: repo,
                        issuer_id: Uuid::from_u128(44),
                        lane: "main".to_owned(),
                        sequence: 1,
                        operation_id: Uuid::from_u128(45),
                        digest: "0b".repeat(32),
                    },
                    repository_id: repo,
                    tenant_id: tenant,
                    object_format: GitObjectFormat::Sha256,
                    history_incarnation: history,
                    authority_epoch: 2,
                    group_epoch: 1,
                    expected_revision: 1,
                    head: WireHeadUpdate { kind: WireHeadUpdateKind::Keep, target_ref: None },
                    mode: CommitMode::Atomic,
                    refs: Vec::new(),
                },
                decision_id: Some(Uuid::from_u128(46)),
                required_holds: Vec::new(),
                policy_rejects: BTreeMap::new(),
                logical_tick: 1,
            },
            expected_commitment: grant_commitment(),
        }
    }

    fn close_scope_command(repo: Uuid, tenant: Uuid) -> CloseAuthScopeCommand {
        CloseAuthScopeCommand {
            scope_kind: "token".to_owned(),
            scope_id: Uuid::from_u128(47),
            repository_id: Some(repo),
            tenant_id: Some(tenant),
            lifecycle: ScopeLifecycle::Closing,
            authz_floor: 1,
            change_id: Uuid::from_u128(48),
            logical_tick: 1,
        }
    }

    #[test]
    fn commit_variants_reject_foreign_nested_identity_repository() {
        let repo = Uuid::from_u128(10);
        let tenant = Uuid::from_u128(20);
        let history = Uuid::from_u128(30);
        let realm = RealmBinding::new(tenant, "group-a", Uuid::from_u128(4), history, 1, 2, GitObjectFormat::Sha256, 1)
            .unwrap();
        let proposal = proposal(repo, tenant, history, 1, 2, GitObjectFormat::Sha256);

        for (name, command) in [
            ("CommitRefs", RefCasCommand::CommitRefs(commit_scoped_command(repo, tenant, history).commit)),
            ("CommitScopedRefs", RefCasCommand::CommitScopedRefs(commit_scoped_command(repo, tenant, history))),
        ] {
            assert!(proposal.matches_command(&command), "{name} matching outer request was not accepted");
            assert!(
                validate_command_scope(&command, repo, tenant, &realm).is_ok(),
                "{name} matching outer request failed preflight"
            );

            let mut foreign_inner = command;
            let request = match &mut foreign_inner {
                RefCasCommand::CommitRefs(command) => &mut command.request,
                RefCasCommand::CommitScopedRefs(command) => &mut command.commit.request,
                _ => unreachable!(),
            };
            assert_eq!(request.repository_id, repo, "{name} fixture lost the valid outer repository");
            request.identity.repository_id = Uuid::from_u128(11);

            assert!(
                !proposal.matches_command(&foreign_inner),
                "{name} matcher accepted a foreign nested identity repository"
            );
            assert_eq!(
                validate_command_scope(&foreign_inner, repo, tenant, &realm),
                Err(RaftBackendError::ScopeMismatch("repository_id")),
                "{name} preflight accepted a foreign nested identity repository"
            );

            let request = match &foreign_inner {
                RefCasCommand::CommitRefs(command) => &command.request,
                RefCasCommand::CommitScopedRefs(command) => &command.commit.request,
                _ => unreachable!(),
            };
            assert!(
                matches!(CommitRefsRequest::try_from(request), Err(RefStoreError::InvalidIdentity(_))),
                "{name} core conversion no longer rejects the foreign nested identity repository"
            );
        }
    }

    #[test]
    fn current_scoped_commands_bind_present_axes_and_delegate_embedded_requests() {
        let repo = Uuid::from_u128(10);
        let tenant = Uuid::from_u128(20);
        let history = Uuid::from_u128(30);
        let realm = RealmBinding::new(tenant, "group-a", Uuid::from_u128(4), history, 1, 2, GitObjectFormat::Sha256, 1)
            .unwrap();
        let proposal = proposal(repo, tenant, history, 1, 2, GitObjectFormat::Sha256);

        let install = RefCasCommand::InstallScopedDecision(install_scoped_command(repo, tenant));
        assert!(proposal.matches_command(&install));
        assert!(validate_command_scope(&install, repo, tenant, &realm).is_ok());
        assert!(requires_live_gate_precheck(&install));

        let mut foreign_repo = install_scoped_command(repo, tenant);
        foreign_repo.decision.repository_id = Uuid::from_u128(11);
        let foreign_repo = RefCasCommand::InstallScopedDecision(foreign_repo);
        assert!(!proposal.matches_command(&foreign_repo));
        assert_eq!(
            validate_command_scope(&foreign_repo, repo, tenant, &realm),
            Err(RaftBackendError::ScopeMismatch("repository_id"))
        );

        let mut foreign_tenant = install_scoped_command(repo, tenant);
        foreign_tenant.decision.tenant_id = Uuid::from_u128(21);
        let foreign_tenant = RefCasCommand::InstallScopedDecision(foreign_tenant);
        assert!(!proposal.matches_command(&foreign_tenant));
        assert_eq!(
            validate_command_scope(&foreign_tenant, repo, tenant, &realm),
            Err(RaftBackendError::ScopeMismatch("tenant_id"))
        );

        let commit = RefCasCommand::CommitScopedRefs(commit_scoped_command(repo, tenant, history));
        assert!(proposal.matches_command(&commit));
        assert!(validate_command_scope(&commit, repo, tenant, &realm).is_ok());
        assert!(requires_live_gate_precheck(&commit));

        for axis in ["repository_id", "tenant_id", "history_incarnation", "authority_epoch", "group_epoch"] {
            let mut changed = commit_scoped_command(repo, tenant, history);
            match axis {
                "repository_id" => changed.commit.request.repository_id = Uuid::from_u128(11),
                "tenant_id" => changed.commit.request.tenant_id = Uuid::from_u128(21),
                "history_incarnation" => changed.commit.request.history_incarnation = Uuid::from_u128(31),
                "authority_epoch" => changed.commit.request.authority_epoch = 3,
                "group_epoch" => changed.commit.request.group_epoch = 2,
                _ => unreachable!(),
            }
            let changed = RefCasCommand::CommitScopedRefs(changed);
            assert!(!proposal.matches_command(&changed), "nested {axis} was not bound");
            assert!(validate_command_scope(&changed, repo, tenant, &realm).is_err(), "nested {axis} passed scope");
        }

        let mut changed_format = commit_scoped_command(repo, tenant, history);
        changed_format.commit.request.object_format = GitObjectFormat::Sha1;
        let changed_format = RefCasCommand::CommitScopedRefs(changed_format);
        assert!(!proposal.matches_command(&changed_format));
        assert_eq!(
            validate_command_scope(&changed_format, repo, tenant, &realm),
            Err(RaftBackendError::ScopeMismatch("object_format"))
        );

        let close = RefCasCommand::CloseAuthScope(close_scope_command(repo, tenant));
        assert!(proposal.matches_command(&close));
        assert!(validate_command_scope(&close, repo, tenant, &realm).is_ok());
        assert!(requires_live_gate_precheck(&close));

        let mut unscoped = close_scope_command(repo, tenant);
        unscoped.repository_id = None;
        unscoped.tenant_id = None;
        assert!(proposal.matches_command(&RefCasCommand::CloseAuthScope(unscoped.clone())));
        assert!(validate_command_scope(&RefCasCommand::CloseAuthScope(unscoped), repo, tenant, &realm).is_ok());

        let mut foreign_repo_scope = close_scope_command(repo, tenant);
        foreign_repo_scope.repository_id = Some(Uuid::from_u128(11));
        let foreign_repo_scope = RefCasCommand::CloseAuthScope(foreign_repo_scope);
        assert!(!proposal.matches_command(&foreign_repo_scope));
        assert_eq!(
            validate_command_scope(&foreign_repo_scope, repo, tenant, &realm),
            Err(RaftBackendError::ScopeMismatch("repository_id"))
        );

        let mut foreign_tenant_scope = close_scope_command(repo, tenant);
        foreign_tenant_scope.tenant_id = Some(Uuid::from_u128(21));
        let foreign_tenant_scope = RefCasCommand::CloseAuthScope(foreign_tenant_scope);
        assert!(!proposal.matches_command(&foreign_tenant_scope));
        assert_eq!(
            validate_command_scope(&foreign_tenant_scope, repo, tenant, &realm),
            Err(RaftBackendError::ScopeMismatch("tenant_id"))
        );
    }

    #[test]
    fn new_ordinary_commands_are_still_fenced_against_the_live_gate() {
        let repo = Uuid::from_u128(10);
        let tenant = Uuid::from_u128(20);
        let live = live_gate(repo, tenant, Uuid::from_u128(30), 1, 2, GitObjectFormat::Sha256);
        let stale = proposal(repo, tenant, Uuid::from_u128(31), 1, 2, GitObjectFormat::Sha256);

        for command in [
            RefCasCommand::InstallScopedDecision(install_scoped_command(repo, tenant)),
            RefCasCommand::CommitScopedRefs(commit_scoped_command(repo, tenant, Uuid::from_u128(31))),
            RefCasCommand::CloseAuthScope(close_scope_command(repo, tenant)),
        ] {
            assert_eq!(
                fence_proposal_against_gate(Some(&live), &stale, &command),
                Some(RootRefCasRefusalKind::GateScopeRefused)
            );
        }
    }
}
