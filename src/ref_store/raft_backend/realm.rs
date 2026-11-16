//! Trusted configured realm binding for one real Raft Ref-CAS backend.

use uuid::Uuid;

use crate::ref_store::raft_backend::error::RaftBackendError;

const MAX_GROUP_BYTES: usize = 64;

/// Immutable trusted realm/authority/storage-generation context owned by a backend.
///
/// Every field is private. There is no `Deserialize`, default, or arbitrary-bytes constructor, so
/// a caller cannot mint a view by presenting an unverified realm object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmBinding {
    tenant_id: Uuid,
    group_id: String,
    authority_id: Uuid,
    history_id: Uuid,
    group_epoch: u64,
    storage_generation: u64,
}

impl RealmBinding {
    /// Validates one trusted realm binding. All ids are non-nil and epochs are positive.
    pub fn new(
        tenant_id: Uuid,
        group_id: impl Into<String>,
        authority_id: Uuid,
        history_id: Uuid,
        group_epoch: u64,
        storage_generation: u64,
    ) -> Result<Self, RaftBackendError> {
        if tenant_id.is_nil() || authority_id.is_nil() || history_id.is_nil() {
            return Err(RaftBackendError::InvalidConfig("realm ids must be non-nil"));
        }
        let group_id = group_id.into();
        validate_group_id(&group_id)?;
        if group_epoch == 0 || group_epoch > i64::MAX as u64 {
            return Err(RaftBackendError::InvalidConfig("group_epoch must be in 1..=i64::MAX"));
        }
        if storage_generation == 0 {
            return Err(RaftBackendError::InvalidConfig("storage_generation must be positive"));
        }
        Ok(Self { tenant_id, group_id, authority_id, history_id, group_epoch, storage_generation })
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    pub fn authority_id(&self) -> Uuid {
        self.authority_id
    }

    pub fn history_id(&self) -> Uuid {
        self.history_id
    }

    pub fn group_epoch(&self) -> u64 {
        self.group_epoch
    }

    pub fn storage_generation(&self) -> u64 {
        self.storage_generation
    }
}

fn validate_group_id(group_id: &str) -> Result<(), RaftBackendError> {
    if group_id.is_empty() || group_id.len() > MAX_GROUP_BYTES {
        return Err(RaftBackendError::InvalidConfig("group_id is empty or too long"));
    }
    if !group_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
        return Err(RaftBackendError::InvalidConfig("group_id contains unsupported bytes"));
    }
    Ok(())
}
