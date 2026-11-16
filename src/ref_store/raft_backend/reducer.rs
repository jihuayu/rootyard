//! Real Root Ref-CAS reducer applied inside the persistent Raft state-machine callback.

use std::any::Any;
use std::collections::BTreeMap;

use rootyard_refcas_log::state_machine::{ApplicationError, ApplicationLogId, ApplicationStateMachine};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, NoopCommand, RefCasCommand, RefCasStateMachine, StateMachineError, decode_command, encode_command,
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
}

impl RootRefCasStateMachine {
    pub fn new() -> Self {
        Self { machine: RefCasStateMachine::new() }
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

    /// Deterministic Root state digest (local inspection, not a committed view).
    pub fn root_state_digest_hex(&self) -> Result<String, StateMachineError> {
        self.machine.state_digest()
    }

    pub(crate) fn machine(&self) -> &RefCasStateMachine {
        &self.machine
    }

    fn apply_command(&mut self, log_id: ApplicationLogId, command: RefCasCommand) -> Result<(), ApplicationError> {
        let applied = AppliedLogId { term: log_id.term, index: log_id.index };
        self.machine.apply(applied, command).map_err(map_state_error)?;
        if self.last_applied_coordinate() != Some(log_id) {
            return Err(ApplicationError::new("root Ref-CAS coordinate did not advance to the committed log id"));
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
        self.apply_command(log_id, command)
    }

    fn advance_applied(&mut self, log_id: ApplicationLogId) -> Result<(), ApplicationError> {
        // Raft blank/membership entries are deterministic coordinate advances. A Noop with no
        // logical tick does not change business state.
        self.apply_command(log_id, RefCasCommand::Noop(NoopCommand { logical_tick: None }))
    }

    fn export_state(&self) -> Result<Vec<u8>, ApplicationError> {
        self.machine.snapshot_bytes().map_err(map_state_error)
    }

    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), ApplicationError> {
        let restored = RefCasStateMachine::restore_bytes(bytes).map_err(map_state_error)?;
        self.machine = restored;
        Ok(())
    }

    fn last_applied(&self) -> Option<ApplicationLogId> {
        self.last_applied_coordinate()
    }

    fn state_digest_hex(&self) -> Result<String, ApplicationError> {
        self.machine.state_digest().map_err(map_state_error)
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
