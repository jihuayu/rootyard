//! Real Root Ref-CAS reducer applied inside the persistent Raft state-machine callback.

use std::any::Any;
use std::collections::BTreeMap;

use rootyard_refcas_log::state_machine::{ApplicationError, ApplicationLogId, ApplicationStateMachine};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, NoopCommand, RefCasCommand, RefCasStateMachine, StateMachineError, decode_command, encode_command,
};
use crate::ref_store::raft_backend::adapter_state::{
    LegacyAdapterState, adapter_state_digest_v3, export_adapter_state_v3, restore_adapter_state, root_only_state_v3,
};
use crate::ref_store::raft_backend::outcome::{
    RootRefCasApplied, RootRefCasOutcome, RootRefCasRefusal, RootRefCasRefusalKind,
};
use crate::ref_store::raft_backend::proposal::{
    MAX_ADAPTER_STATE_BYTES, MAX_PROPOSAL_RECEIPT_BYTES, PROPOSAL_WINDOW, ProposalAttempt, ProposalAttemptKind,
    ProposalEnvelope, ProposalId, ProposalLookup, command_digest_hex,
};
use crate::ref_store::raft_backend::scope::{fence_legacy_set_lane, fence_proposal_against_gate};

/// Stable application domain for Root Ref-CAS business commands.
pub const ROOT_REF_CAS_DOMAIN: &str = "rootyard.ref_store.ref_cas";
/// Application schema/command version; any mismatch fails closed in the seam.
pub const ROOT_REF_CAS_VERSION: u16 = 1;

/// Adapter that actually applies committed `RefCasCommand` values to the Root deterministic
/// state machine. It never runs Git/Blob/PG/Redis IO and never reads a wall clock.
///
/// This is a fresh homogeneous `/3` adapter protocol. A writer/version that does not enforce the
/// same apply-time gate fence is not transparently compatible; mixed-version deployments must not
/// be treated as having these fencing guarantees.
#[derive(Clone, Debug, Default)]
pub struct RootRefCasStateMachine {
    machine: RefCasStateMachine,
    attempts: BTreeMap<ApplicationLogId, ProposalAttempt>,
    legacy: Option<LegacyAdapterState>,
}

impl RootRefCasStateMachine {
    pub fn new() -> Self {
        Self { machine: RefCasStateMachine::new(), attempts: BTreeMap::new(), legacy: None }
    }

    /// Applied consensus coordinate of the underlying Root state machine.
    pub fn last_applied_coordinate(&self) -> Option<ApplicationLogId> {
        self.machine.last_applied().map(|log_id| ApplicationLogId::new(log_id.term, log_id.index))
    }

    /// Read refs from this local reducer snapshot. This is local inspection, **not** an
    /// authoritative committed view and must not substitute for a quorum ReadIndex.
    pub fn read_refs(&self, repository_id: Uuid) -> BTreeMap<String, String> {
        self.machine.read_refs(repository_id)
    }

    /// Read HEAD from this local reducer snapshot. This is local inspection, **not** an
    /// authoritative committed view and must not substitute for a quorum ReadIndex.
    pub fn read_head_ref(&self, repository_id: Uuid) -> Option<String> {
        self.machine.read_head_ref(repository_id)
    }

    /// Deterministic Root gate/refs state digest (local inspection, not a committed view).
    pub fn root_state_digest_hex(&self) -> Result<String, StateMachineError> {
        self.machine.state_digest()
    }

    /// Deterministic logical clock floor (log-derived; never a wall clock).
    pub fn logical_clock_floor(&self) -> u64 {
        self.machine.logical_clock_floor()
    }

    /// Digest covering the Root snapshot and, when present, the bounded receipt window.
    pub fn adapter_state_digest_hex(&self) -> Result<String, ApplicationError> {
        if let Some(legacy) = self.legacy.as_ref() {
            return Ok(legacy.digest_hex.clone());
        }
        let root_digest = self.machine.state_digest().map_err(map_state_error)?;
        let root_snapshot = self.machine.snapshot_bytes().map_err(map_state_error)?;
        let bytes = export_adapter_state_v3(root_snapshot, &self.attempts)?;
        adapter_state_digest_v3(&root_digest, &bytes)
    }

    /// Exact retained attempt at one application coordinate, if present.
    pub fn query_attempt(&self, log_id: ApplicationLogId) -> Option<&ProposalAttempt> {
        self.attempts.get(&log_id)
    }

    /// Exact caller-stable proposal lookup by first-decision identity.
    pub fn query_proposal(&self, proposal_id: &ProposalId) -> ProposalLookup {
        let current_index = self.last_applied_coordinate().map(|coordinate| coordinate.index).unwrap_or(0);
        if proposal_id.validate_shape().is_err() {
            return ProposalLookup::Invalid { proposal_id: proposal_id.clone(), reason: "malformed proposal id" };
        }
        let Some(expires_at_index) = proposal_id.expires_at_index() else {
            return ProposalLookup::Invalid { proposal_id: proposal_id.clone(), reason: "proposal expiry overflow" };
        };
        if current_index > expires_at_index {
            return ProposalLookup::Expired { proposal_id: proposal_id.clone(), current_index, expires_at_index };
        }
        if let Some(first) = self.attempts.values().find(|attempt| {
            attempt.kind == ProposalAttemptKind::First && attempt.proposal_id.as_ref() == Some(proposal_id)
        }) {
            return ProposalLookup::Found {
                proposal_id: proposal_id.clone(),
                command_digest_hex: first.command_digest_hex.clone(),
                original_log_id: first.original_log_id,
                observed_log_id: first.observed_log_id,
                outcome: first.outcome.clone(),
            };
        }
        ProposalLookup::NotObserved { proposal_id: proposal_id.clone(), current_index }
    }

    pub fn retained_attempt_count(&self) -> usize {
        self.attempts.len()
    }

    pub(crate) fn machine(&self) -> &RefCasStateMachine {
        &self.machine
    }

    fn ensure_v3(&mut self) -> Result<(), ApplicationError> {
        if self.legacy.is_some() {
            let root = self.machine.snapshot_bytes().map_err(map_state_error)?;
            root_only_state_v3(&root)?;
            self.legacy = None;
            self.attempts.clear();
        }
        Ok(())
    }

    fn prune_attempts(&mut self, current_index: u64) {
        let cutoff = current_index.saturating_sub(PROPOSAL_WINDOW);
        self.attempts.retain(|log_id, _| log_id.index > cutoff);
    }

    fn attempt_fits(&self, attempt: &ProposalAttempt) -> Result<bool, ApplicationError> {
        if attempt.serialized_len()? > MAX_PROPOSAL_RECEIPT_BYTES {
            return Ok(false);
        }
        let root = self.machine.snapshot_bytes().map_err(map_state_error)?;
        if root_only_state_v3(&root).is_err() {
            return Ok(false);
        }
        Ok(export_adapter_state_v3(root, &self.attempts).is_ok_and(|bytes| bytes.len() <= MAX_ADAPTER_STATE_BYTES))
    }

    fn insert_with_fallback(
        &mut self,
        attempt: ProposalAttempt,
        fallback: ProposalAttempt,
    ) -> Result<(), ApplicationError> {
        let prior_attempts = self.attempts.clone();
        let observed = attempt.observed_log_id;
        if self.attempts.insert(observed, attempt.clone()).is_some() {
            return Err(ApplicationError::new("duplicate proposal attempt coordinate"));
        }
        self.prune_attempts(observed.index);
        if self.attempt_fits(&attempt)? {
            return Ok(());
        }
        self.attempts = prior_attempts;
        let observed = fallback.observed_log_id;
        if self.attempts.insert(observed, fallback.clone()).is_some() {
            return Err(ApplicationError::new("duplicate capacity refusal attempt coordinate"));
        }
        self.prune_attempts(observed.index);
        if self.attempt_fits(&fallback)? {
            Ok(())
        } else {
            Err(ApplicationError::new("bounded adapter state cannot admit a capacity refusal"))
        }
    }

    fn commit_business_attempt(
        &mut self,
        log_id: ApplicationLogId,
        prior_machine: RefCasStateMachine,
        attempt: ProposalAttempt,
        fallback: ProposalAttempt,
    ) -> Result<(), ApplicationError> {
        let prior_attempts = self.attempts.clone();
        if self.attempts.insert(log_id, attempt.clone()).is_some() {
            return Err(ApplicationError::new("duplicate proposal attempt coordinate"));
        }
        self.prune_attempts(log_id.index);
        if self.attempt_fits(&attempt)? {
            return Ok(());
        }
        self.attempts = prior_attempts;
        self.machine = prior_machine;
        self.apply_noop(log_id)?;
        if self.attempts.insert(log_id, fallback.clone()).is_some() {
            return Err(ApplicationError::new("duplicate capacity refusal attempt coordinate"));
        }
        self.prune_attempts(log_id.index);
        if self.attempt_fits(&fallback)? {
            Ok(())
        } else {
            Err(ApplicationError::new("bounded adapter state cannot admit a capacity refusal"))
        }
    }

    fn apply_noop(&mut self, log_id: ApplicationLogId) -> Result<(), ApplicationError> {
        let applied = AppliedLogId { term: log_id.term, index: log_id.index };
        self.machine
            .apply(applied, RefCasCommand::Noop(NoopCommand { logical_tick: None }))
            .map_err(map_state_error)?;
        if self.last_applied_coordinate() != Some(log_id) {
            return Err(ApplicationError::new("root Ref-CAS coordinate did not advance to the committed log id"));
        }
        Ok(())
    }

    fn apply_core(
        &mut self,
        log_id: ApplicationLogId,
        command: RefCasCommand,
        prior_machine: RefCasStateMachine,
    ) -> Result<RootRefCasOutcome, ApplicationError> {
        let applied = AppliedLogId { term: log_id.term, index: log_id.index };
        match self.machine.apply(applied, command) {
            Ok(response) => {
                if self.last_applied_coordinate() != Some(log_id) {
                    return Err(ApplicationError::new(
                        "root Ref-CAS coordinate did not advance to the committed log id",
                    ));
                }
                Ok(RootRefCasOutcome::Applied(RootRefCasApplied::from_response(response)))
            }
            Err(error) => {
                let Some(kind) = RootRefCasRefusalKind::from_state_machine(&error) else {
                    return Err(map_state_error(error));
                };
                // Expected semantic/business refusal: discard any staged mutation, advance only
                // the applied coordinate with a no-tick Noop, and retain a fixed typed outcome.
                self.machine = prior_machine;
                self.apply_noop(log_id)?;
                Ok(RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(kind)))
            }
        }
    }

    fn commit_protocol_refusal(
        &mut self,
        log_id: ApplicationLogId,
        proposal_id: ProposalId,
        digest_hex: String,
        refusal: RootRefCasRefusalKind,
        kind: ProposalAttemptKind,
    ) -> Result<(), ApplicationError> {
        let attempt = ProposalAttempt {
            proposal_id: Some(proposal_id.clone()),
            command_digest_hex: digest_hex.clone(),
            original_log_id: log_id,
            observed_log_id: log_id,
            kind,
            outcome: RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(refusal)),
        };
        let fallback = ProposalAttempt {
            proposal_id: Some(proposal_id),
            command_digest_hex: digest_hex,
            original_log_id: log_id,
            observed_log_id: log_id,
            kind: ProposalAttemptKind::Capacity,
            outcome: RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(RootRefCasRefusalKind::StateCapacity)),
        };
        self.apply_noop(log_id)?;
        self.insert_with_fallback(attempt, fallback)
    }

    fn apply_proposal(
        &mut self,
        log_id: ApplicationLogId,
        proposal_id: ProposalId,
        command: RefCasCommand,
        digest_hex: String,
    ) -> Result<(), ApplicationError> {
        let current_index = log_id.index;
        if proposal_id.validate_shape().is_err()
            || proposal_id.expires_at_index().is_none()
            || proposal_id.issued_at_index >= current_index
        {
            return self.commit_protocol_refusal(
                log_id,
                proposal_id,
                digest_hex,
                RootRefCasRefusalKind::ProposalInvalid,
                ProposalAttemptKind::First,
            );
        }
        let expires_at_index = proposal_id.expires_at_index().expect("checked proposal expiry");
        if current_index > expires_at_index {
            return self.commit_protocol_refusal(
                log_id,
                proposal_id,
                digest_hex,
                RootRefCasRefusalKind::ProposalExpired,
                ProposalAttemptKind::Expired,
            );
        }

        let first = self
            .attempts
            .values()
            .find(|attempt| {
                attempt.kind == ProposalAttemptKind::First && attempt.proposal_id.as_ref() == Some(&proposal_id)
            })
            .cloned();
        if let Some(first) = first {
            if first.command_digest_hex == digest_hex {
                let attempt = ProposalAttempt {
                    proposal_id: Some(proposal_id.clone()),
                    command_digest_hex: digest_hex.clone(),
                    original_log_id: first.original_log_id,
                    observed_log_id: log_id,
                    kind: ProposalAttemptKind::Replayed,
                    outcome: first.outcome.clone(),
                };
                let fallback = ProposalAttempt {
                    proposal_id: Some(proposal_id),
                    command_digest_hex: digest_hex,
                    original_log_id: first.original_log_id,
                    observed_log_id: log_id,
                    kind: ProposalAttemptKind::Capacity,
                    outcome: RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(
                        RootRefCasRefusalKind::StateCapacity,
                    )),
                };
                self.apply_noop(log_id)?;
                return self.insert_with_fallback(attempt, fallback);
            }
            let attempt = ProposalAttempt {
                proposal_id: Some(proposal_id.clone()),
                command_digest_hex: digest_hex.clone(),
                original_log_id: first.original_log_id,
                observed_log_id: log_id,
                kind: ProposalAttemptKind::Conflict,
                outcome: RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(
                    RootRefCasRefusalKind::ProposalConflict,
                )),
            };
            let fallback = ProposalAttempt {
                proposal_id: Some(proposal_id),
                command_digest_hex: digest_hex,
                original_log_id: first.original_log_id,
                observed_log_id: log_id,
                kind: ProposalAttemptKind::Capacity,
                outcome: RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(RootRefCasRefusalKind::StateCapacity)),
            };
            self.apply_noop(log_id)?;
            return self.insert_with_fallback(attempt, fallback);
        }

        if !proposal_id.matches_command(&command) {
            return self.commit_protocol_refusal(
                log_id,
                proposal_id,
                digest_hex,
                RootRefCasRefusalKind::ProposalScopeMismatch,
                ProposalAttemptKind::First,
            );
        }

        let live_gate = self.machine.read_gate_version(proposal_id.repository_id).map_err(map_state_error)?;
        if let Some(refusal) = fence_proposal_against_gate(live_gate.as_ref(), &proposal_id, &command) {
            return self.commit_protocol_refusal(log_id, proposal_id, digest_hex, refusal, ProposalAttemptKind::First);
        }

        let prior_machine = self.machine.clone();
        let outcome = self.apply_core(log_id, command, prior_machine.clone())?;
        let attempt = ProposalAttempt {
            proposal_id: Some(proposal_id.clone()),
            command_digest_hex: digest_hex.clone(),
            original_log_id: log_id,
            observed_log_id: log_id,
            kind: ProposalAttemptKind::First,
            outcome: outcome.clone(),
        };
        let fallback = ProposalAttempt {
            proposal_id: Some(proposal_id),
            command_digest_hex: digest_hex,
            original_log_id: log_id,
            observed_log_id: log_id,
            kind: ProposalAttemptKind::First,
            outcome: RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(RootRefCasRefusalKind::StateCapacity)),
        };
        self.commit_business_attempt(log_id, prior_machine, attempt, fallback)
    }

    fn commit_legacy_refusal(
        &mut self,
        log_id: ApplicationLogId,
        digest_hex: String,
        refusal: RootRefCasRefusalKind,
    ) -> Result<(), ApplicationError> {
        let attempt = ProposalAttempt {
            proposal_id: None,
            command_digest_hex: digest_hex.clone(),
            original_log_id: log_id,
            observed_log_id: log_id,
            kind: ProposalAttemptKind::Legacy,
            outcome: RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(refusal)),
        };
        let fallback = ProposalAttempt {
            proposal_id: None,
            command_digest_hex: digest_hex,
            original_log_id: log_id,
            observed_log_id: log_id,
            kind: ProposalAttemptKind::Legacy,
            outcome: RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(RootRefCasRefusalKind::StateCapacity)),
        };
        self.apply_noop(log_id)?;
        self.insert_with_fallback(attempt, fallback)
    }

    fn apply_legacy(
        &mut self,
        log_id: ApplicationLogId,
        command: RefCasCommand,
        digest_hex: String,
    ) -> Result<(), ApplicationError> {
        if let RefCasCommand::SetRepositoryLane(command) = &command {
            let live = self.machine.read_gate_version(command.repository_id).map_err(map_state_error)?;
            if let Some(refusal) = fence_legacy_set_lane(live.as_ref(), command) {
                return self.commit_legacy_refusal(log_id, digest_hex, refusal);
            }
        }
        let prior_machine = self.machine.clone();
        let outcome = self.apply_core(log_id, command, prior_machine.clone())?;
        let attempt = ProposalAttempt {
            proposal_id: None,
            command_digest_hex: digest_hex.clone(),
            original_log_id: log_id,
            observed_log_id: log_id,
            kind: ProposalAttemptKind::Legacy,
            outcome: outcome.clone(),
        };
        let fallback = ProposalAttempt {
            proposal_id: None,
            command_digest_hex: digest_hex,
            original_log_id: log_id,
            observed_log_id: log_id,
            kind: ProposalAttemptKind::Legacy,
            outcome: RootRefCasOutcome::Refused(RootRefCasRefusal::from_kind(RootRefCasRefusalKind::StateCapacity)),
        };
        self.commit_business_attempt(log_id, prior_machine, attempt, fallback)
    }
}

fn map_state_error(error: StateMachineError) -> ApplicationError {
    ApplicationError::new(format!("root Ref-CAS refusal: {error}"))
}

impl ApplicationStateMachine for RootRefCasStateMachine {
    fn domain(&self) -> &'static str {
        ROOT_REF_CAS_DOMAIN
    }

    fn version(&self) -> u16 {
        ROOT_REF_CAS_VERSION
    }

    fn apply(&mut self, log_id: ApplicationLogId, payload: &[u8]) -> Result<(), ApplicationError> {
        if let Some((proposal_id, command_bytes)) = ProposalEnvelope::decode(payload)? {
            let command = decode_command(&command_bytes).map_err(map_state_error)?;
            let digest_hex = command_digest_hex(&command_bytes);
            self.ensure_v3()?;
            self.apply_proposal(log_id, proposal_id, command, digest_hex)
        } else {
            let command = decode_command(payload).map_err(map_state_error)?;
            let digest_hex = command_digest_hex(payload);
            self.ensure_v3()?;
            self.apply_legacy(log_id, command, digest_hex)
        }
    }

    fn advance_applied(&mut self, log_id: ApplicationLogId) -> Result<(), ApplicationError> {
        // Raft blank/membership entries advance deterministic expiry/pruning but add no receipt.
        self.ensure_v3()?;
        let applied = AppliedLogId { term: log_id.term, index: log_id.index };
        self.machine
            .apply(applied, RefCasCommand::Noop(NoopCommand { logical_tick: None }))
            .map_err(map_state_error)?;
        if self.last_applied_coordinate() != Some(log_id) {
            return Err(ApplicationError::new("root Ref-CAS coordinate did not advance for a blank/membership entry"));
        }
        self.prune_attempts(log_id.index);
        Ok(())
    }

    fn export_state(&self) -> Result<Vec<u8>, ApplicationError> {
        if let Some(legacy) = self.legacy.as_ref() {
            return Ok(legacy.bytes.clone());
        }
        let root_snapshot = self.machine.snapshot_bytes().map_err(map_state_error)?;
        export_adapter_state_v3(root_snapshot, &self.attempts)
    }

    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), ApplicationError> {
        let restored = restore_adapter_state(bytes)?;
        self.machine = restored.machine;
        self.attempts = restored.attempts;
        self.legacy = restored.legacy;
        Ok(())
    }

    fn last_applied(&self) -> Option<ApplicationLogId> {
        self.last_applied_coordinate()
    }

    fn state_digest_hex(&self) -> Result<String, ApplicationError> {
        self.adapter_state_digest_hex()
    }

    fn clone_box(&self) -> Box<dyn ApplicationStateMachine> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Validates that a business command will round-trip through the canonical wire codec before it
/// reaches Raft. This is a codec check, not an authorization decision.
pub fn validate_ref_cas_command(command: &RefCasCommand) -> Result<(), ApplicationError> {
    let payload = encode_command(command).map_err(map_state_error)?;
    decode_command(&payload).map_err(map_state_error).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::core::state_machine::{
        InitializeGateCommand, NoopCommand, RefCasCommand, RepositoryLane, SmPackMode, WireGateInit, encode_command,
    };
    use crate::ref_store::core::types::GitObjectFormat;
    use crate::ref_store::raft_backend::outcome::{RootRefCasApplied, RootRefCasOutcome, RootRefCasRefusalKind};
    use crate::ref_store::raft_backend::proposal::{
        PROPOSAL_WINDOW, ProposalAttemptKind, ProposalEnvelope, ProposalId, ProposalLookup,
    };
    use crate::ref_store::{CoreGateInit, RefName};
    use rootyard_refcas_log::state_machine::{ApplicationLogId, ApplicationStateMachine};
    use uuid::Uuid;

    fn proposal_id(repo: Uuid, tenant: Uuid, history: Uuid, issued_at_index: u64) -> ProposalId {
        ProposalId::new(
            repo,
            tenant,
            history,
            "group-a",
            1,
            Uuid::from_u128(4),
            1,
            1,
            GitObjectFormat::Sha256,
            issued_at_index,
            Uuid::from_u128(5),
        )
        .unwrap()
    }

    fn scoped_id(
        repo: Uuid,
        tenant: Uuid,
        history: Uuid,
        group_epoch: u64,
        authority_epoch: i64,
        object_format: GitObjectFormat,
        issued_at_index: u64,
        nonce: u128,
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
            object_format,
            issued_at_index,
            Uuid::from_u128(nonce),
        )
        .unwrap()
    }

    fn init_command(
        repo: Uuid,
        tenant: Uuid,
        history: Uuid,
        group_epoch: i64,
        authority_epoch: i64,
        object_format: GitObjectFormat,
    ) -> RefCasCommand {
        let gate = CoreGateInit::new(
            repo,
            tenant,
            object_format,
            history,
            authority_epoch,
            group_epoch,
            RefName::branch("refs/heads/main").unwrap(),
        )
        .unwrap();
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&gate),
            lane: RepositoryLane::ServingRefStore,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 1,
        })
    }

    fn envelope(id: &ProposalId, command: &RefCasCommand) -> Vec<u8> {
        ProposalEnvelope::encode(id, &encode_command(command).unwrap()).unwrap()
    }

    #[test]
    fn expired_proposal_does_not_execute_or_relabel_itself() {
        let mut app = RootRefCasStateMachine::new();
        for index in 1..=PROPOSAL_WINDOW + 2 {
            app.advance_applied(ApplicationLogId::new(1, index)).unwrap();
        }
        let repo = Uuid::from_u128(10);
        let tenant = Uuid::from_u128(20);
        let history = Uuid::from_u128(30);
        let payload = ProposalEnvelope::encode(
            &proposal_id(repo, tenant, history, 0),
            &encode_command(&RefCasCommand::Noop(NoopCommand { logical_tick: None })).unwrap(),
        )
        .unwrap();
        let expired_log = ApplicationLogId::new(1, PROPOSAL_WINDOW + 3);
        app.apply(expired_log, &payload).unwrap();
        let attempt = app.query_attempt(expired_log).expect("expired attempt retained");
        assert_eq!(attempt.kind, ProposalAttemptKind::Expired);
        assert!(matches!(
            &attempt.outcome,
            RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::ProposalExpired
        ));
        assert!(matches!(app.query_proposal(&proposal_id(repo, tenant, history, 0)), ProposalLookup::Expired { .. }));

        let later_log = ApplicationLogId::new(1, PROPOSAL_WINDOW + 4);
        app.apply(later_log, &payload).unwrap();
        assert_eq!(app.query_attempt(later_log).expect("later expired attempt").kind, ProposalAttemptKind::Expired);
    }

    #[test]
    fn same_identity_and_digest_replays_without_reexecuting_business() {
        let mut app = RootRefCasStateMachine::new();
        let repo = Uuid::from_u128(10);
        let tenant = Uuid::from_u128(20);
        let history = Uuid::from_u128(30);
        let gate = CoreGateInit::new(
            repo,
            tenant,
            GitObjectFormat::Sha256,
            history,
            1,
            1,
            RefName::branch("refs/heads/main").unwrap(),
        )
        .unwrap();
        let command = RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&gate),
            lane: RepositoryLane::ServingRefStore,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 1,
        });
        let payload =
            ProposalEnvelope::encode(&proposal_id(repo, tenant, history, 0), &encode_command(&command).unwrap())
                .unwrap();
        let first_log = ApplicationLogId::new(1, 1);
        app.apply(first_log, &payload).unwrap();
        let first = app.query_attempt(first_log).expect("first attempt").outcome.clone();
        assert!(matches!(&first, RootRefCasOutcome::Applied(RootRefCasApplied::GateInitialized { created: true, .. })));

        let replay_log = ApplicationLogId::new(1, 2);
        app.apply(replay_log, &payload).unwrap();
        let replay = app.query_attempt(replay_log).expect("replay attempt");
        assert_eq!(replay.kind, ProposalAttemptKind::Replayed);
        assert_eq!(replay.original_log_id, first_log);
        assert_eq!(replay.outcome, first);
        assert_eq!(
            app.query_proposal(&proposal_id(repo, tenant, history, 0)),
            ProposalLookup::Found {
                proposal_id: proposal_id(repo, tenant, history, 0),
                command_digest_hex: replay.command_digest_hex.clone(),
                original_log_id: first_log,
                observed_log_id: first_log,
                outcome: first,
            }
        );
    }

    #[test]
    fn stale_ordinary_proposal_and_ticking_noop_are_fenced_at_apply() {
        let mut app = RootRefCasStateMachine::new();
        let repo = Uuid::from_u128(10);
        let tenant = Uuid::from_u128(20);
        let live_history = Uuid::from_u128(30);
        let live_id = scoped_id(repo, tenant, live_history, 1, 2, GitObjectFormat::Sha256, 0, 5);
        let live_init = init_command(repo, tenant, live_history, 1, 2, GitObjectFormat::Sha256);
        app.apply(ApplicationLogId::new(1, 1), &envelope(&live_id, &live_init)).unwrap();
        assert_eq!(app.logical_clock_floor(), 0);

        let stale_id = scoped_id(repo, tenant, Uuid::from_u128(31), 1, 1, GitObjectFormat::Sha256, 1, 6);
        let tick = RefCasCommand::Noop(NoopCommand { logical_tick: Some(7) });
        app.apply(ApplicationLogId::new(1, 2), &envelope(&stale_id, &tick)).unwrap();
        let refused = app.query_attempt(ApplicationLogId::new(1, 2)).expect("fenced attempt");
        assert_eq!(refused.kind, ProposalAttemptKind::First);
        assert!(matches!(
            &refused.outcome,
            RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::GateScopeRefused
        ));
        assert_eq!(app.logical_clock_floor(), 0);
        let gate = app.machine().read_gate_version(repo).unwrap().expect("live gate");
        assert_eq!(gate.history_incarnation(), live_history);
        assert_eq!(gate.authority_epoch(), 2);

        // Noop(None) is the explicit coordinate-only exception; it does not mutate the clock and
        // deliberately does not require a full live scope match.
        let coordinate_id = scoped_id(repo, tenant, Uuid::from_u128(31), 1, 1, GitObjectFormat::Sha256, 2, 7);
        let coordinate = RefCasCommand::Noop(NoopCommand { logical_tick: None });
        app.apply(ApplicationLogId::new(1, 3), &envelope(&coordinate_id, &coordinate)).unwrap();
        let applied = app.query_attempt(ApplicationLogId::new(1, 3)).expect("coordinate attempt");
        assert_eq!(applied.kind, ProposalAttemptKind::First);
        assert!(applied.outcome.is_applied());
        assert_eq!(app.logical_clock_floor(), 0);
    }

    #[test]
    fn legacy_set_lane_is_fenced_before_business_mutation() {
        let mut app = RootRefCasStateMachine::new();
        let repo = Uuid::from_u128(10);
        let tenant = Uuid::from_u128(20);
        let live_history = Uuid::from_u128(30);
        let live_id = scoped_id(repo, tenant, live_history, 1, 2, GitObjectFormat::Sha256, 0, 5);
        let live_init = init_command(repo, tenant, live_history, 1, 2, GitObjectFormat::Sha256);
        app.apply(ApplicationLogId::new(1, 1), &envelope(&live_id, &live_init)).unwrap();

        let old_lane =
            RefCasCommand::SetRepositoryLane(crate::ref_store::core::state_machine::SetRepositoryLaneCommand {
                repository_id: repo,
                tenant_id: tenant,
                lane: RepositoryLane::ServingRefStore,
                lifecycle: crate::ref_store::core::state_machine::ScopeLifecycle::Closing,
                authz_floor: 1,
                history_incarnation: Uuid::from_u128(31),
                authority_epoch: 1,
                group_epoch: 1,
                pack_mode: SmPackMode::MetadataOnly,
            });
        app.apply(ApplicationLogId::new(1, 2), &encode_command(&old_lane).unwrap()).unwrap();
        let refused = app.query_attempt(ApplicationLogId::new(1, 2)).expect("legacy fenced attempt");
        assert_eq!(refused.kind, ProposalAttemptKind::Legacy);
        assert!(matches!(
            &refused.outcome,
            RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::GateTransitionRefused
        ));
        let gate = app.machine().read_gate_version(repo).unwrap().expect("live gate");
        assert_eq!(gate.history_incarnation(), live_history);
        assert_eq!(gate.authority_epoch(), 2);
        assert_eq!(app.logical_clock_floor(), 0);
    }
}
