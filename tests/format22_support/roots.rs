//! Actor-owned retention-root facade requests for the format22 source.
//!
//! The public `PgServingRetentionRoots::*_actor_owned` methods derive the
//! durable root owner from the authenticated producer. The fixture supplies
//! only repository owner/name selectors, the real source snapshot id, purpose,
//! selector, root release target and bounded idempotency keys. No owner-id
//! field or direct SQL/root scope is constructed here.

use anyhow::{Result, ensure};
use rootyard::ref_store::core::retention_root::{RootPurpose, RootSelector};
use rootyard::ref_store::serving::{
    ServingRootCreate, ServingRootIntent, ServingRootRead, ServingRootRelease, ServingRootReleaseTarget,
};
use uuid::Uuid;

pub fn create_input(owner: &str, name: &str, snapshot_id: Uuid, key: &str) -> ServingRootCreate {
    ServingRootCreate {
        owner: owner.to_owned(),
        name: name.to_owned(),
        intent: ServingRootIntent {
            source_snapshot_id: snapshot_id,
            selector: RootSelector::Snapshot,
            purpose: RootPurpose::Backup,
            idempotency_key: key.to_owned(),
        },
    }
}

pub fn read_input(owner: &str, name: &str, root_id: Uuid) -> ServingRootRead {
    ServingRootRead { owner: owner.to_owned(), name: name.to_owned(), root_id }
}

pub fn release_input(owner: &str, name: &str, root_id: Uuid, key: &str, reason: &str) -> ServingRootRelease {
    ServingRootRelease {
        owner: owner.to_owned(),
        name: name.to_owned(),
        target: ServingRootReleaseTarget::Existing { root_id },
        idempotency_key: key.to_owned(),
        reason: reason.to_owned(),
    }
}

/// The facade derives the root id; this local helper exists only to keep the
/// seed's marker assertions explicit without duplicating root-id logic.
pub fn ensure_root_id(receipt_root_id: Uuid, record_root_id: Uuid) -> Result<()> {
    ensure!(receipt_root_id == record_root_id, "root receipt and retained record disagree on root id");
    Ok(())
}
