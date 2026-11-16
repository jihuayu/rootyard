//! Real Root Ref-CAS reducer applied inside the persistent Raft state-machine callback.

use std::any::Any;
use std::collections::BTreeMap;

use rootyard_refcas_log::state_machine::{ApplicationError, ApplicationLogId, ApplicationStateMachine};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, NoopCommand, RefCasCommand, RefCasStateMachine, StateMachineError, decode_command, encode_command,
};
use crate::ref_store::raft_backend::adapter_state::{
    adapter_state_digest_hex, export_adapter_state, restore_adapter_state,
};
use crate::ref_store::raft_backend::outcome::{
    OutcomeKey, OutcomeQuery, RootRefCasApplied, RootRefCasOutcome, RootRefCasRefusal, RootRefCasRefusalKind,
    StoredOutcome, command_digest_hex, outcome_key,
};

/// Stable application domain for Root Ref-CAS business commands.
pub const ROOT_REF_CAS_DOMAIN: &str = "rootyard.ref_store.ref_cas";
/// Application schema/command version; any mismatch fails closed in the seam.
pub const ROOT_REF_CAS_VERSION: u16 = 1;

/// Adapter that actually applies committed `RefCasCommand` values to the Root deterministic
/// state machine. It never runs Git/Blob/PG/Redis IO and never reads a wall clock.
#[derive(Clone, Debug, Default)]
pub struct RootRefCasStateMachine {
    machine: RefCasStateMachine,
    outcomes: BTreeMap<ApplicationLogId, StoredOutcome>,
}

impl RootRefCasStateMachine {
    pub fn new() -> Self {
        Self { machine: RefCasStateMachine::new(), outcomes: BTreeMap::new() }
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

    /// Digest covering the Root snapshot and, when present, the typed outcome ledger.
    pub fn adapter_state_digest_hex(&self) -> Result<String, ApplicationError> {
        let root_digest = self.machine.state_digest().map_err(map_state_error)?;
        let root_snapshot = self.machine.snapshot_bytes().map_err(map_state_error)?;
        let bytes = export_adapter_state(root_snapshot, &self.outcomes)?;
        adapter_state_digest_hex(&root_digest, &bytes, self.outcomes.is_empty())
    }

    /// Idempotent lookup of the actual replicated typed outcome.
    pub fn query_outcome(&self, query: &OutcomeQuery) -> Option<&StoredOutcome> {
        match query {
            OutcomeQuery::LogId(log_id) => self.outcomes.get(log_id),
            _ => self.outcomes.values().rev().find(|outcome| outcome.matches(query)),
        }
    }

    pub(crate) fn machine(&self) -> &RefCasStateMachine {
        &self.machine
    }

    fn apply_command(
        &mut self,
        log_id: ApplicationLogId,
        command: RefCasCommand,
        digest_hex: String,
        key: Option<OutcomeKey>,
    ) -> Result<(), ApplicationError> {
        let applied = AppliedLogId { term: log_id.term, index: log_id.index };
        let prior = self.machine.clone();
        match self.machine.apply(applied, command) {
            Ok(response) => {
                if self.last_applied_coordinate() != Some(log_id) {
                    return Err(ApplicationError::new(
                        "root Ref-CAS coordinate did not advance to the committed log id",
                    ));
                }
                self.record_outcome(
                    log_id,
                    digest_hex,
                    key,
                    RootRefCasOutcome::Applied(RootRefCasApplied::from_response(response)),
                )
            }
            Err(error) => {
                let Some(kind) = RootRefCasRefusalKind::from_state_machine(&error) else {
                    return Err(map_state_error(error));
                };
                // Expected business refusal: discard any staged mutation, advance only the applied
                // coordinate with a no-tick Noop, and persist the typed refusal. Never turn this
                // into a StorageError, which would terminate OpenRaft's apply worker.
                self.machine = prior;
                self.machine
                    .apply(applied, RefCasCommand::Noop(NoopCommand { logical_tick: None }))
                    .map_err(map_state_error)?;
                if self.last_applied_coordinate() != Some(log_id) {
                    return Err(ApplicationError::new(
                        "root Ref-CAS coordinate did not advance after a typed business refusal",
                    ));
                }
                let refusal = RootRefCasRefusal { kind, detail: error.to_string() };
                self.record_outcome(log_id, digest_hex, key, RootRefCasOutcome::Refused(refusal))
            }
        }
    }

    fn record_outcome(
        &mut self,
        log_id: ApplicationLogId,
        command_digest_hex: String,
        key: Option<OutcomeKey>,
        outcome: RootRefCasOutcome,
    ) -> Result<(), ApplicationError> {
        let stored = StoredOutcome { log_id, command_digest_hex, key, outcome };
        if self.outcomes.insert(log_id, stored).is_some() {
            return Err(ApplicationError::new("duplicate typed outcome at one application coordinate"));
        }
        Ok(())
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
        let command = decode_command(payload).map_err(map_state_error)?;
        let digest_hex = command_digest_hex(payload);
        let key = outcome_key(&command);
        self.apply_command(log_id, command, digest_hex, key)
    }

    fn advance_applied(&mut self, log_id: ApplicationLogId) -> Result<(), ApplicationError> {
        // Raft blank/membership entries are deterministic coordinate advances. A Noop with no
        // logical tick does not change business state or the outcome ledger.
        let applied = AppliedLogId { term: log_id.term, index: log_id.index };
        self.machine
            .apply(applied, RefCasCommand::Noop(NoopCommand { logical_tick: None }))
            .map_err(map_state_error)?;
        if self.last_applied_coordinate() != Some(log_id) {
            return Err(ApplicationError::new("root Ref-CAS coordinate did not advance for a blank/membership entry"));
        }
        Ok(())
    }

    fn export_state(&self) -> Result<Vec<u8>, ApplicationError> {
        let root_snapshot = self.machine.snapshot_bytes().map_err(map_state_error)?;
        export_adapter_state(root_snapshot, &self.outcomes)
    }

    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), ApplicationError> {
        let (machine, outcomes) = restore_adapter_state(bytes)?;
        self.machine = machine;
        self.outcomes = outcomes;
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
