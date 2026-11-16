//! Trusted repository/tenant/realm command-scope validation before Raft append.

use uuid::Uuid;

use crate::ref_store::core::state_machine::RefCasCommand;
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::raft_backend::error::RaftBackendError;
use crate::ref_store::raft_backend::realm::RealmBinding;

struct CommandScope {
    repository_id: Uuid,
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
        repository_id,
        tenant_id,
        group_epoch,
        authority_id,
        history_incarnation: None,
        authority_epoch: None,
        object_format: None,
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
        RefCasCommand::CommitRefs(cmd) => CommandScope {
            history_incarnation: Some(cmd.request.history_incarnation),
            authority_epoch: Some(cmd.request.authority_epoch),
            object_format: Some(cmd.request.object_format),
            ..base(cmd.request.repository_id, Some(cmd.request.tenant_id), Some(cmd.request.group_epoch), None)
        },
        RefCasCommand::Cancel(cmd) => base(cmd.identity.repository_id, None, None, None),
        RefCasCommand::AdvanceCancelCutoff(cmd) => base(cmd.repository_id, None, None, None),
        RefCasCommand::InstallDecision(cmd) => base(cmd.repository_id, Some(cmd.tenant_id), None, None),
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

    if scope.repository_id != repository_id {
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
