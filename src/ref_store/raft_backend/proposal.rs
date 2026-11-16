//! Bounded caller-stable proposal identity and durable receipt window.
//!
//! The Raft-selected exact generic response type is unchanged: the adapter carries a versioned
//! proposal envelope inside the existing application command payload and records at most one
//! bounded receipt per normal application entry. A fixed Raft-index window bounds state without
//! silently re-executing an identity whose first result is still promised or has expired.

use rootyard_refcas_log::state_machine::{ApplicationError, ApplicationLogId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::RefCasCommand;
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::raft_backend::outcome::RootRefCasOutcome;

/// Strict proposal envelope format inside the generic application command payload.
pub const PROPOSAL_FORMAT: &str = "rootyard-refcas-proposal/1";
/// Fixed protocol window. `expires_at_index = issued_at_index + PROPOSAL_WINDOW`.
pub const PROPOSAL_WINDOW: u64 = 32;
/// Maximum serialized attempt/receipt weight. The full wrapper is checked separately.
pub const MAX_PROPOSAL_RECEIPT_BYTES: usize = 80 * 1024;
/// Hard adapter state ceiling, below the generic 8 MiB application-state hard stop.
pub const MAX_ADAPTER_STATE_BYTES: usize = 7 * 1024 * 1024;
/// Encoded Root contribution budget. `4 MiB + 32 * 80 KiB < 7 MiB`.
pub const MAX_ROOT_STATE_BYTES: usize = 4 * 1024 * 1024;
/// The generic application envelope carries this proposal wrapper and must remain <= 256 KiB.
pub const MAX_PROPOSAL_ENVELOPE_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalId {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub history_id: Uuid,
    pub group_id: String,
    pub group_epoch: u64,
    pub authority_id: Uuid,
    pub authority_epoch: i64,
    pub storage_generation: u64,
    pub object_format: GitObjectFormat,
    pub issued_at_index: u64,
    pub nonce: Uuid,
}

impl ProposalId {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: Uuid,
        tenant_id: Uuid,
        history_id: Uuid,
        group_id: impl Into<String>,
        group_epoch: u64,
        authority_id: Uuid,
        authority_epoch: i64,
        storage_generation: u64,
        object_format: GitObjectFormat,
        issued_at_index: u64,
        nonce: Uuid,
    ) -> Result<Self, ApplicationError> {
        let id = Self {
            repository_id,
            tenant_id,
            history_id,
            group_id: group_id.into(),
            group_epoch,
            authority_id,
            authority_epoch,
            storage_generation,
            object_format,
            issued_at_index,
            nonce,
        };
        id.validate_shape()?;
        Ok(id)
    }

    pub fn validate_shape(&self) -> Result<(), ApplicationError> {
        if self.repository_id.is_nil()
            || self.tenant_id.is_nil()
            || self.history_id.is_nil()
            || self.authority_id.is_nil()
            || self.nonce.is_nil()
        {
            return Err(ApplicationError::new("proposal ids and nonce must be non-nil"));
        }
        if self.group_id.is_empty() || self.group_id.len() > 64 {
            return Err(ApplicationError::new("proposal group_id is empty or too long"));
        }
        if !self.group_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
            return Err(ApplicationError::new("proposal group_id contains unsupported bytes"));
        }
        if self.group_epoch == 0 || self.group_epoch > i64::MAX as u64 {
            return Err(ApplicationError::new("proposal group_epoch is outside 1..=i64::MAX"));
        }
        if self.authority_epoch <= 0 {
            return Err(ApplicationError::new("proposal authority_epoch must be positive"));
        }
        if self.storage_generation == 0 {
            return Err(ApplicationError::new("proposal storage_generation must be positive"));
        }
        Ok(())
    }

    pub fn expires_at_index(&self) -> Option<u64> {
        self.issued_at_index.checked_add(PROPOSAL_WINDOW)
    }

    /// A proposal may execute only at `issued_at_index < committed_index <= expires_at_index`.
    pub fn is_valid_at(&self, committed_index: u64) -> bool {
        self.expires_at_index()
            .is_some_and(|expires| self.issued_at_index < committed_index && committed_index <= expires)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn matches_scope(
        &self,
        repository_id: Uuid,
        tenant_id: Uuid,
        history_id: Uuid,
        group_id: &str,
        group_epoch: u64,
        authority_id: Uuid,
        authority_epoch: i64,
        storage_generation: u64,
        object_format: GitObjectFormat,
    ) -> bool {
        self.repository_id == repository_id
            && self.tenant_id == tenant_id
            && self.history_id == history_id
            && self.group_id == group_id
            && self.group_epoch == group_epoch
            && self.authority_id == authority_id
            && self.authority_epoch == authority_epoch
            && self.storage_generation == storage_generation
            && self.object_format == object_format
    }

    /// Compares the command axes that are actually represented on the decoded command. Group id,
    /// authority id, and storage generation are not fields of every command and remain bound by
    /// the trusted backend/receipt scope checks instead of being invented here.
    pub fn matches_command(&self, command: &RefCasCommand) -> bool {
        match command {
            RefCasCommand::Noop(_) => true,
            RefCasCommand::InitializeGate(cmd) => {
                self.repository_id == cmd.gate.repository_id
                    && self.tenant_id == cmd.gate.tenant_id
                    && self.history_id == cmd.gate.history_incarnation
                    && self.group_epoch == u64::try_from(cmd.gate.group_epoch).unwrap_or(0)
                    && self.authority_epoch == cmd.gate.authority_epoch
                    && self.object_format == cmd.gate.object_format
            }
            RefCasCommand::SetRepositoryLane(cmd) => {
                self.repository_id == cmd.repository_id
                    && self.tenant_id == cmd.tenant_id
                    && self.history_id == cmd.history_incarnation
                    && self.group_epoch == u64::try_from(cmd.group_epoch).unwrap_or(0)
                    && self.authority_epoch == cmd.authority_epoch
            }
            RefCasCommand::BeginOperation(cmd) => self.repository_id == cmd.identity.repository_id,
            RefCasCommand::CommitRefs(cmd) => {
                self.repository_id == cmd.request.repository_id
                    && self.tenant_id == cmd.request.tenant_id
                    && self.history_id == cmd.request.history_incarnation
                    && self.group_epoch == u64::try_from(cmd.request.group_epoch).unwrap_or(0)
                    && self.authority_epoch == cmd.request.authority_epoch
                    && self.object_format == cmd.request.object_format
            }
            RefCasCommand::Cancel(cmd) => self.repository_id == cmd.identity.repository_id,
            RefCasCommand::AdvanceCancelCutoff(cmd) => self.repository_id == cmd.repository_id,
            RefCasCommand::InstallDecision(cmd) => {
                self.repository_id == cmd.repository_id && self.tenant_id == cmd.tenant_id
            }
            RefCasCommand::CreateSnapshotPin(cmd) => {
                self.repository_id == cmd.repository_id
                    && self.tenant_id == cmd.tenant_id
                    && self.history_id == cmd.history_incarnation
                    && self.group_epoch == u64::try_from(cmd.group_epoch).unwrap_or(0)
                    && self.authority_epoch == cmd.authority_epoch
                    && self.object_format == cmd.object_format
            }
            RefCasCommand::RenewPin(cmd) => self.repository_id == cmd.repository_id && self.tenant_id == cmd.tenant_id,
            RefCasCommand::ReleasePin(cmd) => {
                self.repository_id == cmd.repository_id && self.tenant_id == cmd.tenant_id
            }
            RefCasCommand::RegisterRoot(cmd) => {
                self.repository_id == cmd.repository_id
                    && self.tenant_id == cmd.tenant_id
                    && self.history_id == cmd.history_incarnation
                    && self.group_epoch == u64::try_from(cmd.group_epoch).unwrap_or(0)
                    && self.authority_epoch == cmd.authority_epoch
                    && self.object_format == cmd.object_format
            }
            RefCasCommand::ReleaseRoot(cmd) => {
                self.repository_id == cmd.repository_id && self.tenant_id == cmd.tenant_id
            }
            RefCasCommand::AcquireHoldBatch(cmd) => {
                self.repository_id == cmd.repository_id
                    && self.tenant_id == cmd.tenant_id
                    && self.authority_id == cmd.authority_id
            }
            RefCasCommand::MarkHoldConsumed(cmd) => {
                self.repository_id == cmd.repository_id && self.tenant_id == cmd.tenant_id
            }
            RefCasCommand::RetireHoldBatch(cmd) => {
                self.repository_id == cmd.repository_id && self.tenant_id == cmd.tenant_id
            }
        }
    }
}

/// Strict versioned proposal wire carried inside the existing generic application payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalEnvelope {
    pub format: String,
    pub proposal_id: ProposalId,
    pub command_digest_hex: String,
    pub command: String,
}

impl ProposalEnvelope {
    pub fn encode(proposal_id: &ProposalId, command_payload: &[u8]) -> Result<Vec<u8>, ApplicationError> {
        let command = std::str::from_utf8(command_payload)
            .map_err(|_| ApplicationError::new("canonical command payload is not UTF-8 JSON"))?
            .to_owned();
        let command_digest_hex = command_digest_hex(command.as_bytes());
        let envelope =
            Self { format: PROPOSAL_FORMAT.to_owned(), proposal_id: proposal_id.clone(), command_digest_hex, command };
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|e| ApplicationError::new(format!("encode proposal envelope: {e}")))?;
        if bytes.len() > MAX_PROPOSAL_ENVELOPE_BYTES {
            return Err(ApplicationError::new("proposal envelope exceeds 256 KiB"));
        }
        Ok(bytes)
    }

    /// Returns `None` only when the payload is not a proposal envelope (legacy raw command).
    pub fn decode(payload: &[u8]) -> Result<Option<(ProposalId, Vec<u8>)>, ApplicationError> {
        #[derive(Deserialize)]
        struct Probe {
            format: String,
        }
        let probe = serde_json::from_slice::<Probe>(payload).ok();
        if let Some(probe) = probe.as_ref() {
            if probe.format == PROPOSAL_FORMAT {
                let envelope: Self = serde_json::from_slice(payload)
                    .map_err(|e| ApplicationError::new(format!("decode proposal envelope: {e}")))?;
                let command = envelope.command.into_bytes();
                let actual = command_digest_hex(&command);
                if actual != envelope.command_digest_hex {
                    return Err(ApplicationError::new("proposal command digest mismatch"));
                }
                return Ok(Some((envelope.proposal_id, command)));
            }
            if probe.format.starts_with("rootyard-refcas-proposal/") {
                return Err(ApplicationError::new(format!("unknown proposal envelope format {:?}", probe.format)));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalAttemptKind {
    First,
    Replayed,
    Conflict,
    Expired,
    Capacity,
    Legacy,
}

/// One bounded receipt for one normal application entry. `observed_log_id` is the entry that
/// produced this record; `original_log_id` is the first accepted decision for the identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalAttempt {
    pub proposal_id: Option<ProposalId>,
    pub command_digest_hex: String,
    pub original_log_id: ApplicationLogId,
    pub observed_log_id: ApplicationLogId,
    pub kind: ProposalAttemptKind,
    pub outcome: RootRefCasOutcome,
}

impl ProposalAttempt {
    pub fn serialized_len(&self) -> Result<usize, ApplicationError> {
        serde_json::to_vec(self)
            .map(|bytes| bytes.len())
            .map_err(|e| ApplicationError::new(format!("serialize proposal attempt: {e}")))
    }
}

/// Exact lookup result for a caller-stable proposal identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalLookup {
    Found {
        proposal_id: ProposalId,
        command_digest_hex: String,
        original_log_id: ApplicationLogId,
        observed_log_id: ApplicationLogId,
        outcome: RootRefCasOutcome,
    },
    NotObserved {
        proposal_id: ProposalId,
        current_index: u64,
    },
    Expired {
        proposal_id: ProposalId,
        current_index: u64,
        expires_at_index: u64,
    },
    Invalid {
        proposal_id: ProposalId,
        reason: &'static str,
    },
}

/// One actual proposal result returned by the scoped backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalOutcome {
    pub proposal_id: ProposalId,
    /// Observed committed attempt coordinate.
    pub log_id: ApplicationLogId,
    /// First decision coordinate for this identity, when retained.
    pub original_log_id: Option<ApplicationLogId>,
    pub decision: ProposalAttemptKind,
    /// `None` only for a late ACK whose exact result has expired.
    pub outcome: Option<RootRefCasOutcome>,
}

/// Canonical command digest bound into the proposal envelope and receipts.
pub fn command_digest_hex(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::core::state_machine::NoopCommand;

    fn id(issued: u64) -> ProposalId {
        ProposalId::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            "group-a",
            1,
            Uuid::from_u128(4),
            1,
            1,
            GitObjectFormat::Sha256,
            issued,
            Uuid::from_u128(5),
        )
        .unwrap()
    }

    #[test]
    fn window_boundaries_are_fixed_and_non_refreshing() {
        let id = id(10);
        assert_eq!(id.expires_at_index(), Some(10 + PROPOSAL_WINDOW));
        assert!(!id.is_valid_at(10));
        assert!(id.is_valid_at(11));
        assert!(id.is_valid_at(10 + PROPOSAL_WINDOW));
        assert!(!id.is_valid_at(10 + PROPOSAL_WINDOW + 1));
        assert_eq!(id.expires_at_index(), Some(10 + PROPOSAL_WINDOW));
    }

    #[test]
    fn envelope_binds_canonical_command_digest() {
        let command = crate::ref_store::core::state_machine::encode_command(&RefCasCommand::Noop(NoopCommand {
            logical_tick: None,
        }))
        .unwrap();
        let envelope = ProposalEnvelope::encode(&id(0), &command).unwrap();
        let (decoded, bytes) = ProposalEnvelope::decode(&envelope).unwrap().unwrap();
        assert_eq!(decoded, id(0));
        assert_eq!(bytes, command);
        let mut tampered = serde_json::from_slice::<serde_json::Value>(&envelope).unwrap();
        tampered["command_digest_hex"] = serde_json::Value::String("00".repeat(32));
        assert!(ProposalEnvelope::decode(&serde_json::to_vec(&tampered).unwrap()).is_err());
    }
}
