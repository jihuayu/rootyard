//! Monotonic non-reusable physical Blob key registry preventing ABA races (#122).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    SafeGcError,
    model::{SAFE_GC_SCHEMA_VERSION, validate_bounded_name, validate_sha256_hex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyLifecycleState {
    CompactionStaging,
    ActiveServing,
    RetiredPendingProof,
    DeletePendingBarrier,
    PhysicallyDeletedTombstone,
}

/// Immutable anti-ABA physical key descriptor bound to tenant, repo, history,
/// incarnation epoch, strictly monotonic sequence, and unique allocation nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalBlobKey {
    pub schema_version: u32,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub incarnation_epoch: u64,
    pub allocation_seq: u64,
    pub nonce: Uuid,
    pub role: String,
    pub object_sha256: String,
    pub object_path: String,
    pub state: KeyLifecycleState,
}

impl PhysicalBlobKey {
    pub fn canonical_path(
        scope: (Uuid, Uuid, Uuid, u64),
        allocation_seq: u64,
        nonce: Uuid,
        role: &str,
        object_sha256: &str,
    ) -> String {
        let (tenant_id, repo_id, history_id, incarnation_epoch) = scope;
        format!(
            "tenants/{tenant_id}/repos/{repo_id}/hist/{history_id}/inc-{incarnation_epoch:016x}/seq-{allocation_seq:016x}-{nonce}-{role}-{object_sha256}"
        )
    }
}

/// Persistent non-reuse registry refusing ABA key collisions across restarts,
/// compaction retries, and identical-content re-uploads after deletion.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiAbaKeyRegistry {
    pub max_incarnation_epoch: u64,
    pub next_allocation_seq: u64,
    pub keys_by_path: BTreeMap<String, PhysicalBlobKey>,
    pub deleted_tombstones: BTreeSet<String>,
}

impl AntiAbaKeyRegistry {
    pub fn new() -> Self {
        Self {
            max_incarnation_epoch: 0,
            next_allocation_seq: 1,
            keys_by_path: BTreeMap::new(),
            deleted_tombstones: BTreeSet::new(),
        }
    }

    pub fn advance_incarnation_epoch(&mut self, next_epoch: u64) -> Result<(), SafeGcError> {
        if next_epoch <= self.max_incarnation_epoch {
            return Err(SafeGcError::StaleIncarnation("incarnation epoch must increase monotonically"));
        }
        self.max_incarnation_epoch = next_epoch;
        Ok(())
    }

    pub fn mint_immutable_key(
        &mut self,
        scope: (Uuid, Uuid, Uuid, u64),
        role: &str,
        object_sha256: &str,
        initial_state: KeyLifecycleState,
    ) -> Result<PhysicalBlobKey, SafeGcError> {
        let (tenant_id, repo_id, history_id, incarnation_epoch) = scope;
        if tenant_id.is_nil() || repo_id.is_nil() || history_id.is_nil() || incarnation_epoch == 0 {
            return Err(SafeGcError::InvalidInput("physical key requires valid scopes and epoch".into()));
        }
        validate_bounded_name("key_role", role)?;
        validate_sha256_hex(object_sha256)?;
        if incarnation_epoch < self.max_incarnation_epoch {
            return Err(SafeGcError::StaleIncarnation("refusing key mint on stale incarnation epoch"));
        }
        self.max_incarnation_epoch = self.max_incarnation_epoch.max(incarnation_epoch);
        let seq = self.next_allocation_seq.max(1);
        self.next_allocation_seq =
            seq.checked_add(1).ok_or_else(|| SafeGcError::InvalidInput("allocation seq overflow".into()))?;
        let nonce = Uuid::new_v4();
        let object_path = PhysicalBlobKey::canonical_path(scope, seq, nonce, role, object_sha256);
        if self.keys_by_path.contains_key(&object_path) || self.deleted_tombstones.contains(&object_path) {
            return Err(SafeGcError::AbaKeyReuseDetected(format!("duplicate physical key {object_path}")));
        }
        let key = PhysicalBlobKey {
            schema_version: SAFE_GC_SCHEMA_VERSION,
            tenant_id,
            repo_id,
            history_id,
            incarnation_epoch,
            allocation_seq: seq,
            nonce,
            role: role.to_owned(),
            object_sha256: object_sha256.to_owned(),
            object_path: object_path.clone(),
            state: initial_state,
        };
        self.keys_by_path.insert(object_path, key.clone());
        Ok(key)
    }

    pub fn register_verified_key(&mut self, key: PhysicalBlobKey) -> Result<(), SafeGcError> {
        if self.deleted_tombstones.contains(&key.object_path) || self.keys_by_path.contains_key(&key.object_path) {
            return Err(SafeGcError::AbaKeyReuseDetected(format!(
                "physical key `{}` was previously used or deleted",
                key.object_path
            )));
        }
        if key.allocation_seq == 0 || key.incarnation_epoch < self.max_incarnation_epoch {
            return Err(SafeGcError::AbaKeyReuseDetected("external key has non-monotonic seq or stale epoch".into()));
        }
        if key.allocation_seq >= self.next_allocation_seq {
            self.next_allocation_seq = key
                .allocation_seq
                .checked_add(1)
                .ok_or_else(|| SafeGcError::InvalidInput("allocation seq overflow".into()))?;
        }
        self.max_incarnation_epoch = self.max_incarnation_epoch.max(key.incarnation_epoch);
        self.keys_by_path.insert(key.object_path.clone(), key);
        Ok(())
    }

    pub fn transition_state(
        &mut self,
        path: &str,
        expected: KeyLifecycleState,
        next: KeyLifecycleState,
    ) -> Result<(), SafeGcError> {
        let entry = self
            .keys_by_path
            .get_mut(path)
            .ok_or_else(|| SafeGcError::InvalidInput(format!("unknown physical key `{path}`")))?;
        if entry.state != expected {
            return Err(SafeGcError::AbaKeyReuseDetected(format!("unexpected key state transition for `{path}`")));
        }
        entry.state = next;
        if next == KeyLifecycleState::PhysicallyDeletedTombstone {
            self.deleted_tombstones.insert(path.to_owned());
        }
        Ok(())
    }

    pub fn assert_late_put_allowed(&self, key_path: &str, writer_epoch: u64) -> Result<(), SafeGcError> {
        if writer_epoch < self.max_incarnation_epoch {
            return Err(SafeGcError::StaleIncarnation("late PUT from stale incarnation rejected"));
        }
        if self.deleted_tombstones.contains(key_path) {
            return Err(SafeGcError::AbaKeyReuseDetected(format!(
                "late PUT refused on already-deleted tombstone `{key_path}`"
            )));
        }
        if let Some(existing) = self.keys_by_path.get(key_path)
            && matches!(
                existing.state,
                KeyLifecycleState::DeletePendingBarrier
                    | KeyLifecycleState::PhysicallyDeletedTombstone
                    | KeyLifecycleState::ActiveServing
            )
        {
            return Err(SafeGcError::AbaKeyReuseDetected(format!(
                "late PUT refused on committed/tombstoned key `{key_path}`"
            )));
        }
        Ok(())
    }

    pub fn assert_delete_allowed(&self, key_path: &str, deleter_epoch: u64) -> Result<(), SafeGcError> {
        if deleter_epoch != self.max_incarnation_epoch {
            return Err(SafeGcError::StaleDeleterFenced("late DELETE from stale incarnation refused"));
        }
        if self.deleted_tombstones.contains(key_path) {
            return Err(SafeGcError::AbaKeyReuseDetected(format!("key `{key_path}` already physically deleted")));
        }
        let entry = self
            .keys_by_path
            .get(key_path)
            .ok_or_else(|| SafeGcError::InvalidInput(format!("unknown delete target `{key_path}`")))?;
        if !matches!(entry.state, KeyLifecycleState::RetiredPendingProof | KeyLifecycleState::DeletePendingBarrier) {
            return Err(SafeGcError::ProtectionOverlap(format!(
                "cannot delete key `{key_path}` in state {:?}",
                entry.state
            )));
        }
        Ok(())
    }
}
