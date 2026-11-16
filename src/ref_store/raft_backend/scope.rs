//! Trusted repository/tenant/realm command-scope validation before Raft append.

use uuid::Uuid;

use crate::ref_store::core::state_machine::RefCasCommand;
use crate::ref_store::raft_backend::error::RaftBackendError;
use crate::ref_store::raft_backend::realm::RealmBinding;

struct CommandScope {
    repository_id: Uuid,
    tenant_id: Option<Uuid>,
    group_epoch: Option<i64>,
    authority_id: Option<Uuid>,
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
            repository_id: cmd.gate.repository_id,
            tenant_id: Some(cmd.gate.tenant_id),
            group_epoch: Some(cmd.gate.group_epoch),
            authority_id: None,
        },
        RefCasCommand::SetRepositoryLane(cmd) => CommandScope {
            repository_id: cmd.repository_id,
            tenant_id: Some(cmd.tenant_id),
            group_epoch: Some(cmd.group_epoch),
            authority_id: None,
        },
        RefCasCommand::BeginOperation(cmd) => CommandScope {
            repository_id: cmd.identity.repository_id,
            tenant_id: None,
            group_epoch: None,
            authority_id: None,
        },
        RefCasCommand::CommitRefs(cmd) => CommandScope {
            repository_id: cmd.request.repository_id,
            tenant_id: Some(cmd.request.tenant_id),
            group_epoch: Some(cmd.request.group_epoch),
            authority_id: None,
        },
        RefCasCommand::Cancel(cmd) => CommandScope {
            repository_id: cmd.identity.repository_id,
            tenant_id: None,
            group_epoch: None,
            authority_id: None,
        },
        RefCasCommand::AdvanceCancelCutoff(cmd) => {
            CommandScope { repository_id: cmd.repository_id, tenant_id: None, group_epoch: None, authority_id: None }
        }
        RefCasCommand::InstallDecision(cmd) => CommandScope {
            repository_id: cmd.repository_id,
            tenant_id: Some(cmd.tenant_id),
            group_epoch: None,
            authority_id: None,
        },
        RefCasCommand::CreateSnapshotPin(cmd) => CommandScope {
            repository_id: cmd.repository_id,
            tenant_id: Some(cmd.tenant_id),
            group_epoch: Some(cmd.group_epoch),
            authority_id: None,
        },
        RefCasCommand::RenewPin(cmd) => CommandScope {
            repository_id: cmd.repository_id,
            tenant_id: Some(cmd.tenant_id),
            group_epoch: None,
            authority_id: None,
        },
        RefCasCommand::ReleasePin(cmd) => CommandScope {
            repository_id: cmd.repository_id,
            tenant_id: Some(cmd.tenant_id),
            group_epoch: None,
            authority_id: None,
        },
        RefCasCommand::RegisterRoot(cmd) => CommandScope {
            repository_id: cmd.repository_id,
            tenant_id: Some(cmd.tenant_id),
            group_epoch: Some(cmd.group_epoch),
            authority_id: None,
        },
        RefCasCommand::ReleaseRoot(cmd) => CommandScope {
            repository_id: cmd.repository_id,
            tenant_id: Some(cmd.tenant_id),
            group_epoch: None,
            authority_id: None,
        },
        RefCasCommand::AcquireHoldBatch(cmd) => CommandScope {
            repository_id: cmd.repository_id,
            tenant_id: Some(cmd.tenant_id),
            group_epoch: None,
            authority_id: Some(cmd.authority_id),
        },
        RefCasCommand::MarkHoldConsumed(cmd) => CommandScope {
            repository_id: cmd.repository_id,
            tenant_id: Some(cmd.tenant_id),
            group_epoch: None,
            authority_id: None,
        },
        RefCasCommand::RetireHoldBatch(cmd) => CommandScope {
            repository_id: cmd.repository_id,
            tenant_id: Some(cmd.tenant_id),
            group_epoch: None,
            authority_id: None,
        },
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
    Ok(())
}
