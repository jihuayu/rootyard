//! Production Ref-CAS commit cutpoint publisher (#122).

use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, RefCasCommand, RefCasLogEntry, RefCasStateMachine,
};

use super::super::SafeGcError;
use super::persist_refcas_cutpoint_snapshot;

/// Production Ref-CAS commit cutpoint publisher sealing `<storage_root>/safe-gc/refcas/<repo_id>.json`
/// whenever an authoritative `RefCasStateMachine` commits repository state.
#[derive(Clone, Debug)]
pub struct RefCasCommitCutpointPublisher {
    storage_root: PathBuf,
    group_id: i64,
}

impl RefCasCommitCutpointPublisher {
    pub fn new(storage_root: impl Into<PathBuf>, group_id: i64) -> Result<Self, SafeGcError> {
        if group_id < 0 {
            return Err(SafeGcError::InvalidInput("Ref-CAS cutpoint group_id must be non-negative".into()));
        }
        Ok(Self { storage_root: storage_root.into(), group_id })
    }

    pub fn group_id(&self) -> i64 {
        self.group_id
    }

    pub fn storage_root(&self) -> &Path {
        &self.storage_root
    }

    pub fn publish_committed_state(
        &self,
        repo_id: Uuid,
        sm: &RefCasStateMachine,
        wal_tail: &[RefCasLogEntry],
    ) -> Result<PathBuf, SafeGcError> {
        persist_refcas_cutpoint_snapshot(&self.storage_root, repo_id, self.group_id, sm, wal_tail)
    }

    pub fn apply_and_publish(
        &self,
        sm: &mut RefCasStateMachine,
        repo_id: Uuid,
        log_id: AppliedLogId,
        cmd: RefCasCommand,
    ) -> Result<ApplyResponse, SafeGcError> {
        let resp = sm
            .apply(log_id, cmd)
            .map_err(|e| SafeGcError::InvalidInput(format!("Ref-CAS state machine apply failed: {e}")))?;
        self.publish_committed_state(repo_id, sm, &[])?;
        Ok(resp)
    }
}
