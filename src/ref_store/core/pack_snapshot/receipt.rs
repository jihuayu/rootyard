//! Sealed immutable A5a pack-snapshot receipt and its lookup/outcome shapes.
//!
//! A receipt is a *record*, not the data: it names the snapshot/pin, the exact
//! historical scope and gate proof, the captured ref/membership/snapshot digests
//! and the retained logical size. It has private fields, no public constructor,
//! no `Serialize`/`Deserialize` and no unchecked factory, so it can only be built
//! by the PostgreSQL adapter from durable rows whose canonical body already
//! agreed with the immutable snapshot header (or, after repository deletion, with
//! the permanent history ledger).
//!
//! `complete_git_read_snapshot()` is `false` here and on every A5a value: this
//! increment captures *registered* pack membership, it does not verify current
//! Blob bytes or native Git closure.
use super::super::pin::SnapshotHeader;
use super::super::snapshot_contract::{MetadataSnapshotScope, expires_at_from_micros};
use super::super::snapshot_receipt::{MetadataPinReceipt, MetadataSnapshotReceipt};
use super::super::snapshot_request::PinReleaseReason;
use super::contract::PACK_MODE_VERIFIED;
use super::sql::StoredHistory;
use crate::ref_store::contract::MetadataMutationAction;
use crate::ref_store::contract::RefStoreError;
use std::time::SystemTime;
use uuid::Uuid;

/// The immutable identity a pack snapshot receipt is rebuilt from.
///
/// It comes from the live snapshot header while the repository exists, or from
/// the permanent history ledger after the header was legitimately cascaded away.
/// Both sources are immutable; every overlapping field of the canonical body is
/// compared before a receipt is returned.
pub(super) struct StoredPackSnapshot {
    pub snapshot_id: Uuid,
    pub scope: MetadataSnapshotScope,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub head_ref: String,
    pub head_oid: Option<String>,
    pub ref_count: i64,
    pub refs_digest: String,
    pub membership_digest: String,
    pub pack_count: i64,
    pub snapshot_digest: String,
    pub logical_bytes: i64,
}

impl StoredPackSnapshot {
    /// From the immutable snapshot header (repository still present).
    pub(super) fn from_header(header: &SnapshotHeader) -> Result<Self, RefStoreError> {
        header.ensure_pack_verified()?;
        Ok(Self {
            snapshot_id: header.snapshot_id,
            scope: header.stored_scope()?,
            gate_revision: header.gate_revision,
            gate_digest: header.gate_digest.clone(),
            head_ref: header.head_ref.clone(),
            head_oid: header.head_oid.clone(),
            ref_count: header.ref_count,
            refs_digest: header.refs_digest.clone(),
            membership_digest: header
                .membership_digest
                .clone()
                .ok_or_else(|| RefStoreError::Database("pack snapshot header has no membership digest".into()))?,
            pack_count: header.pack_count,
            snapshot_digest: header
                .snapshot_digest
                .clone()
                .ok_or_else(|| RefStoreError::Database("pack snapshot header has no snapshot digest".into()))?,
            logical_bytes: header.logical_bytes,
        })
    }

    /// From the permanent history ledger alone (repository deleted).
    ///
    /// The history row was written in the same transaction as the canonical body
    /// it duplicates, and it is immutable/no-delete, so every overlapping field
    /// must agree exactly. `head_ref`/`head_oid` exist only in the canonical body;
    /// they stay anchored because the body is immutable and its `refs_digest`,
    /// gate, counts and digests are all cross-checked against permanent columns.
    pub(super) fn from_history(
        history: &StoredHistory,
        receipt: &MetadataSnapshotReceipt,
    ) -> Result<Self, RefStoreError> {
        let scope = MetadataSnapshotScope::new(
            history.repository_id,
            history.tenant_id,
            history.owner_id,
            receipt.purpose(),
            receipt.object_format(),
            receipt.history_incarnation(),
            receipt.authority_epoch(),
            receipt.group_epoch(),
        )?;
        if receipt.snapshot_id() != history.snapshot_id
            || receipt.pin_id() != history.pin_id
            || receipt.gate_revision() != history.gate_revision
            || receipt.gate_digest_hex() != history.gate_digest.as_str()
            || receipt.refs_digest_hex() != history.refs_digest.as_str()
            || receipt.ref_count() != history.ref_count
            || receipt.logical_bytes() != history.logical_bytes
            || receipt.pack_mode() != Some(PACK_MODE_VERIFIED)
            || receipt.pack_count() != Some(history.pack_count)
            || receipt.membership_digest_hex() != Some(history.membership_digest.as_str())
            || receipt.snapshot_digest_hex() != Some(history.snapshot_digest.as_str())
        {
            return Err(RefStoreError::Database(
                "permanent pack snapshot history disagrees with its canonical receipt body".into(),
            ));
        }
        Ok(Self {
            snapshot_id: history.snapshot_id,
            scope,
            gate_revision: history.gate_revision,
            gate_digest: history.gate_digest.clone(),
            head_ref: receipt.head_ref().to_owned(),
            head_oid: receipt.head_oid_hex().map(str::to_owned),
            ref_count: history.ref_count,
            refs_digest: history.refs_digest.clone(),
            membership_digest: history.membership_digest.clone(),
            pack_count: history.pack_count,
            snapshot_digest: history.snapshot_digest.clone(),
            logical_bytes: history.logical_bytes,
        })
    }
}

/// Immutable receipt of one successful pack snapshot create/renew/release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackSnapshotReceipt {
    request_id: Uuid,
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    scope: MetadataSnapshotScope,
    gate_revision: i64,
    gate_digest: String,
    head_ref: String,
    head_oid: Option<String>,
    ref_count: i64,
    refs_digest: String,
    membership_digest: String,
    pack_count: i64,
    snapshot_digest: String,
    logical_bytes: i64,
    expires_at_unix_micros: i64,
}

impl PackSnapshotReceipt {
    /// Adapter-only construction from a decoded A2 ledger body that was already
    /// proven to agree with its ledger row, its immutable snapshot identity and
    /// its pin identity. Any disagreement here is a database-integrity error.
    pub(super) fn from_stored(
        receipt: &MetadataSnapshotReceipt,
        stored: &StoredPackSnapshot,
    ) -> Result<Self, RefStoreError> {
        if receipt.pack_mode() != Some(PACK_MODE_VERIFIED)
            || receipt.pack_count() != Some(stored.pack_count)
            || receipt.membership_digest_hex() != Some(stored.membership_digest.as_str())
            || receipt.snapshot_digest_hex() != Some(stored.snapshot_digest.as_str())
            || receipt.ref_count() != stored.ref_count
            || receipt.refs_digest_hex() != stored.refs_digest.as_str()
            || receipt.logical_bytes() != stored.logical_bytes
        {
            return Err(RefStoreError::Database(
                "stored pack snapshot receipt does not match its immutable identity".into(),
            ));
        }
        Ok(Self {
            request_id: receipt.request_id(),
            snapshot_id: stored.snapshot_id,
            pin_id: receipt.pin_id(),
            pin_generation: receipt.pin_generation(),
            scope: stored.scope,
            gate_revision: stored.gate_revision,
            gate_digest: stored.gate_digest.clone(),
            head_ref: stored.head_ref.clone(),
            head_oid: stored.head_oid.clone(),
            ref_count: stored.ref_count,
            refs_digest: stored.refs_digest.clone(),
            membership_digest: stored.membership_digest.clone(),
            pack_count: stored.pack_count,
            snapshot_digest: stored.snapshot_digest.clone(),
            logical_bytes: stored.logical_bytes,
            expires_at_unix_micros: receipt.expires_at_unix_micros(),
        })
    }

    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot_id
    }
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
    pub fn pin_generation(&self) -> i64 {
        self.pin_generation
    }
    /// The stored historical scope, including the snapshot producer owner.
    pub fn scope(&self) -> &MetadataSnapshotScope {
        &self.scope
    }
    pub fn repository_id(&self) -> Uuid {
        self.scope.repository_id()
    }
    pub fn tenant_id(&self) -> Uuid {
        self.scope.tenant_id()
    }
    pub fn owner_id(&self) -> Uuid {
        self.scope.owner_id()
    }
    pub fn gate_revision(&self) -> i64 {
        self.gate_revision
    }
    pub fn gate_digest_hex(&self) -> &str {
        &self.gate_digest
    }
    /// Always `pack_verified`: a pack receipt cannot describe metadata mode.
    pub fn pack_mode(&self) -> &'static str {
        PACK_MODE_VERIFIED
    }
    pub fn head_ref(&self) -> &str {
        &self.head_ref
    }
    pub fn head_oid_hex(&self) -> Option<&str> {
        self.head_oid.as_deref()
    }
    pub fn ref_count(&self) -> i64 {
        self.ref_count
    }
    pub fn refs_digest_hex(&self) -> &str {
        &self.refs_digest
    }
    pub fn membership_digest_hex(&self) -> &str {
        &self.membership_digest
    }
    pub fn pack_count(&self) -> i64 {
        self.pack_count
    }
    pub fn snapshot_digest_hex(&self) -> &str {
        &self.snapshot_digest
    }
    pub fn logical_bytes(&self) -> i64 {
        self.logical_bytes
    }
    pub fn expires_at_unix_micros(&self) -> i64 {
        self.expires_at_unix_micros
    }
    pub fn expires_at(&self) -> Result<SystemTime, RefStoreError> {
        expires_at_from_micros(self.expires_at_unix_micros)
    }

    /// A receipt never claims a complete Git read: it is metadata about a
    /// retained snapshot, not the snapshot and not fresh byte proof.
    pub const fn complete_git_read_snapshot(&self) -> bool {
        false
    }

    /// A receipt is not the captured membership data either; only
    /// [`super::PackReadSnapshot`] can make that claim.
    pub const fn complete_registered_pack_membership(&self) -> bool {
        false
    }
}

/// Immutable receipt of one successful **pack-aware pin lifecycle** mutation
/// (renew or release), resolvable from the A2 ledger and from the permanent
/// history ledger after the repository was deleted.
///
/// It is a record of what happened to a lease, never a live authority: it cannot
/// be used to read a snapshot, extended into a new lease, or turned into a pin
/// generation a caller may present. `PackSnapshotLookup::FoundPin` is therefore
/// safe to return from the historical resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackPinReceipt {
    action: MetadataMutationAction,
    request_id: Uuid,
    scope: MetadataSnapshotScope,
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    expires_at_unix_micros: i64,
    released_at_unix_micros: Option<i64>,
    release_reason: Option<PinReleaseReason>,
}

impl PackPinReceipt {
    /// Adapter-only construction from a decoded pin receipt that was already
    /// validated against its ledger row / permanent history row and against the
    /// caller's full historical scope.
    pub(super) fn from_pin_receipt(
        receipt: &MetadataPinReceipt,
        scope: MetadataSnapshotScope,
    ) -> Result<Self, RefStoreError> {
        if receipt.action() != MetadataMutationAction::Renew && receipt.action() != MetadataMutationAction::Release {
            return Err(RefStoreError::Database("stored pin receipt action is not a lifecycle mutation".into()));
        }
        Ok(Self {
            action: receipt.action(),
            request_id: receipt.request_id(),
            scope,
            snapshot_id: receipt.snapshot_id(),
            pin_id: receipt.pin_id(),
            pin_generation: receipt.pin_generation(),
            expires_at_unix_micros: receipt.expires_at_unix_micros(),
            released_at_unix_micros: receipt.released_at_unix_micros(),
            release_reason: receipt.release_reason(),
        })
    }

    pub fn action(&self) -> MetadataMutationAction {
        self.action
    }
    /// The permanent history kind that records this action (`renewed`/`released`).
    pub fn history_kind(&self) -> &'static str {
        match self.action {
            MetadataMutationAction::Renew => super::sql::HISTORY_RENEWED,
            MetadataMutationAction::Release => super::sql::HISTORY_RELEASED,
            MetadataMutationAction::Create => super::sql::HISTORY_CREATED,
        }
    }
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub fn scope(&self) -> &MetadataSnapshotScope {
        &self.scope
    }
    pub fn repository_id(&self) -> Uuid {
        self.scope.repository_id()
    }
    pub fn tenant_id(&self) -> Uuid {
        self.scope.tenant_id()
    }
    pub fn owner_id(&self) -> Uuid {
        self.scope.owner_id()
    }
    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot_id
    }
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
    pub fn pin_generation(&self) -> i64 {
        self.pin_generation
    }
    pub fn expires_at_unix_micros(&self) -> i64 {
        self.expires_at_unix_micros
    }
    pub fn released_at_unix_micros(&self) -> Option<i64> {
        self.released_at_unix_micros
    }
    pub fn release_reason(&self) -> Option<PinReleaseReason> {
        self.release_reason
    }
    pub fn expires_at(&self) -> Result<SystemTime, RefStoreError> {
        expires_at_from_micros(self.expires_at_unix_micros)
    }

    /// A historical pin receipt never claims a Git read snapshot.
    pub const fn complete_git_read_snapshot(&self) -> bool {
        false
    }

    /// It is also never a live lease: the stored generation/expiry above are the
    /// historical values that were acknowledged, not a usable authority.
    pub const fn grants_live_lease(&self) -> bool {
        false
    }
}

/// One successful create result. `replayed` is `true` only when the identical
/// request already had a durable receipt; the receipt is then the *old* one and
/// is not proof that the lease is currently live.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackSnapshotOutcome {
    pub replayed: bool,
    pub receipt: PackSnapshotReceipt,
}

/// Resolution of an unknown pack-snapshot `COMMIT` by its stable request id.
///
/// `Unknown` is not a rejection and not an abort: it means no durable receipt
/// exists under that request id, so the caller must resolve by re-querying the
/// same identity, never by inventing a success or by retrying under a new id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackSnapshotLookup {
    /// The historical pack snapshot *create* receipt (never the snapshot data).
    Found(PackSnapshotReceipt),
    /// The historical pack-aware pin lifecycle (renew/release) receipt.
    FoundPin(PackPinReceipt),
    Unknown,
}
