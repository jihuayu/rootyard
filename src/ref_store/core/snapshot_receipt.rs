//! Immutable metadata snapshot receipts, pin receipts, pages and the shared
//! mutation-ledger lookup result (A2).
//!
//! Receipts are plain immutable values: an exact retry of a create/renew/release
//! request returns the originally stored receipt and ids only, never a fresh
//! page, a revived lease or an extended expiry. The ledger stores one canonical
//! JSON body per successful request, bounded to
//! [`MAX_RECEIPT_BODY_BYTES`](super::snapshot_contract::MAX_RECEIPT_BODY_BYTES).
use super::super::contract::{MetadataMutationAction, MetadataPinPurpose, RefStoreError};
use super::snapshot_contract::{MetadataSnapshotCursor, MetadataSnapshotScope, PackMembershipDescriptor};
use super::snapshot_request::PinReleaseReason;
use super::types::{GitObjectFormat, GitOid, RefName};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

/// One immutable ref row of a snapshot page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataSnapshotRef {
    name: RefName,
    oid: GitOid,
}

impl MetadataSnapshotRef {
    pub(super) fn new(name: RefName, oid: GitOid) -> Self {
        Self { name, oid }
    }
    pub fn name(&self) -> &RefName {
        &self.name
    }
    pub fn oid(&self) -> GitOid {
        self.oid
    }
}

/// One bounded page of immutable snapshot refs. `next` is `None` exactly when
/// the page is the last one; a page never exceeds the request's limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataSnapshotPage {
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    gate_revision: i64,
    ref_count: i64,
    refs: Vec<MetadataSnapshotRef>,
    next: Option<MetadataSnapshotCursor>,
}

impl MetadataSnapshotPage {
    pub(super) fn new(
        snapshot_id: Uuid,
        pin_id: Uuid,
        pin_generation: i64,
        gate_revision: i64,
        ref_count: i64,
        refs: Vec<MetadataSnapshotRef>,
        next: Option<MetadataSnapshotCursor>,
    ) -> Self {
        Self { snapshot_id, pin_id, pin_generation, gate_revision, ref_count, refs, next }
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
    pub fn gate_revision(&self) -> i64 {
        self.gate_revision
    }
    pub fn ref_count(&self) -> i64 {
        self.ref_count
    }
    pub fn refs(&self) -> &[MetadataSnapshotRef] {
        &self.refs
    }
    pub fn next(&self) -> Option<&MetadataSnapshotCursor> {
        self.next.as_ref()
    }
    pub fn complete(&self) -> bool {
        self.next.is_none()
    }
    pub fn packs(&self) -> PackMembershipDescriptor {
        PackMembershipDescriptor::unavailable()
    }
}

/// Immutable creation receipt. Its body is also persisted, so an exact replay
/// returns byte-identical semantic values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataSnapshotReceipt {
    request_id: Uuid,
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    purpose: MetadataPinPurpose,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    gate_revision: i64,
    gate_digest: String,
    head_ref: String,
    head_oid: Option<String>,
    ref_count: i64,
    refs_digest: String,
    logical_bytes: i64,
    expires_at_unix_micros: i64,
}

/// Construction fields for a creation receipt (locked gate/ref rows -> typed
/// receipt).
pub(super) struct SnapshotReceiptParts {
    pub request_id: Uuid,
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub pin_generation: i64,
    pub scope: MetadataSnapshotScope,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub head_ref: String,
    pub head_oid: Option<String>,
    pub ref_count: i64,
    pub refs_digest: String,
    pub logical_bytes: i64,
    pub expires_at_unix_micros: i64,
}

impl MetadataSnapshotReceipt {
    pub(super) fn from_parts(parts: SnapshotReceiptParts) -> Self {
        Self {
            request_id: parts.request_id,
            snapshot_id: parts.snapshot_id,
            pin_id: parts.pin_id,
            pin_generation: parts.pin_generation,
            repository_id: parts.scope.repository_id(),
            tenant_id: parts.scope.tenant_id(),
            owner_id: parts.scope.owner_id(),
            purpose: parts.scope.purpose(),
            object_format: parts.scope.object_format(),
            history_incarnation: parts.scope.history_incarnation(),
            authority_epoch: parts.scope.authority_epoch(),
            group_epoch: parts.scope.group_epoch(),
            gate_revision: parts.gate_revision,
            gate_digest: parts.gate_digest,
            head_ref: parts.head_ref,
            head_oid: parts.head_oid,
            ref_count: parts.ref_count,
            refs_digest: parts.refs_digest,
            logical_bytes: parts.logical_bytes,
            expires_at_unix_micros: parts.expires_at_unix_micros,
        }
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
    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn owner_id(&self) -> Uuid {
        self.owner_id
    }
    pub fn purpose(&self) -> MetadataPinPurpose {
        self.purpose
    }
    pub fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }
    pub fn history_incarnation(&self) -> Uuid {
        self.history_incarnation
    }
    pub fn authority_epoch(&self) -> i64 {
        self.authority_epoch
    }
    pub fn group_epoch(&self) -> i64 {
        self.group_epoch
    }
    pub fn gate_revision(&self) -> i64 {
        self.gate_revision
    }
    pub fn gate_digest_hex(&self) -> &str {
        &self.gate_digest
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
    pub fn logical_bytes(&self) -> i64 {
        self.logical_bytes
    }
    pub fn expires_at_unix_micros(&self) -> i64 {
        self.expires_at_unix_micros
    }
    pub fn expires_at(&self) -> Result<SystemTime, RefStoreError> {
        super::snapshot_contract::expires_at_from_micros(self.expires_at_unix_micros)
    }
    pub fn packs(&self) -> PackMembershipDescriptor {
        PackMembershipDescriptor::unavailable()
    }
    pub fn complete_git_read_snapshot(&self) -> bool {
        false
    }
}

/// Immutable renew/release receipt from the shared mutation ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataPinReceipt {
    action: MetadataMutationAction,
    request_id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    purpose: MetadataPinPurpose,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    expires_at_unix_micros: i64,
    released_at_unix_micros: Option<i64>,
    release_reason: Option<PinReleaseReason>,
}

pub(super) struct PinReceiptParts {
    pub action: MetadataMutationAction,
    pub request_id: Uuid,
    pub scope: MetadataSnapshotScope,
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub pin_generation: i64,
    pub expires_at_unix_micros: i64,
    pub released_at_unix_micros: Option<i64>,
    pub release_reason: Option<PinReleaseReason>,
}

impl MetadataPinReceipt {
    pub(super) fn from_parts(parts: PinReceiptParts) -> Self {
        Self {
            action: parts.action,
            request_id: parts.request_id,
            repository_id: parts.scope.repository_id(),
            tenant_id: parts.scope.tenant_id(),
            owner_id: parts.scope.owner_id(),
            purpose: parts.scope.purpose(),
            object_format: parts.scope.object_format(),
            history_incarnation: parts.scope.history_incarnation(),
            authority_epoch: parts.scope.authority_epoch(),
            group_epoch: parts.scope.group_epoch(),
            snapshot_id: parts.snapshot_id,
            pin_id: parts.pin_id,
            pin_generation: parts.pin_generation,
            expires_at_unix_micros: parts.expires_at_unix_micros,
            released_at_unix_micros: parts.released_at_unix_micros,
            release_reason: parts.release_reason,
        }
    }

    pub fn action(&self) -> MetadataMutationAction {
        self.action
    }
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn owner_id(&self) -> Uuid {
        self.owner_id
    }
    pub fn purpose(&self) -> MetadataPinPurpose {
        self.purpose
    }
    pub fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }
    pub fn history_incarnation(&self) -> Uuid {
        self.history_incarnation
    }
    pub fn authority_epoch(&self) -> i64 {
        self.authority_epoch
    }
    pub fn group_epoch(&self) -> i64 {
        self.group_epoch
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
}

/// A decoded ledger receipt of either kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataReceipt {
    Snapshot(MetadataSnapshotReceipt),
    Pin(MetadataPinReceipt),
}

impl MetadataReceipt {
    pub fn action(&self) -> MetadataMutationAction {
        match self {
            Self::Snapshot(_) => MetadataMutationAction::Create,
            Self::Pin(receipt) => receipt.action(),
        }
    }
    pub fn snapshot_id(&self) -> Uuid {
        match self {
            Self::Snapshot(receipt) => receipt.snapshot_id(),
            Self::Pin(receipt) => receipt.snapshot_id(),
        }
    }
    pub fn pin_id(&self) -> Uuid {
        match self {
            Self::Snapshot(receipt) => receipt.pin_id(),
            Self::Pin(receipt) => receipt.pin_id(),
        }
    }
    pub fn pin_generation(&self) -> i64 {
        match self {
            Self::Snapshot(receipt) => receipt.pin_generation(),
            Self::Pin(receipt) => receipt.pin_generation(),
        }
    }
    pub fn request_id(&self) -> Uuid {
        match self {
            Self::Snapshot(receipt) => receipt.request_id(),
            Self::Pin(receipt) => receipt.request_id(),
        }
    }
    pub fn repository_id(&self) -> Uuid {
        match self {
            Self::Snapshot(receipt) => receipt.repository_id(),
            Self::Pin(receipt) => receipt.repository_id(),
        }
    }
    pub fn tenant_id(&self) -> Uuid {
        match self {
            Self::Snapshot(receipt) => receipt.tenant_id(),
            Self::Pin(receipt) => receipt.tenant_id(),
        }
    }
    pub fn owner_id(&self) -> Uuid {
        match self {
            Self::Snapshot(receipt) => receipt.owner_id(),
            Self::Pin(receipt) => receipt.owner_id(),
        }
    }
    pub fn purpose(&self) -> MetadataPinPurpose {
        match self {
            Self::Snapshot(receipt) => receipt.purpose(),
            Self::Pin(receipt) => receipt.purpose(),
        }
    }
    pub fn object_format(&self) -> GitObjectFormat {
        match self {
            Self::Snapshot(receipt) => receipt.object_format(),
            Self::Pin(receipt) => receipt.object_format(),
        }
    }
    pub fn history_incarnation(&self) -> Uuid {
        match self {
            Self::Snapshot(receipt) => receipt.history_incarnation(),
            Self::Pin(receipt) => receipt.history_incarnation(),
        }
    }
    pub fn authority_epoch(&self) -> i64 {
        match self {
            Self::Snapshot(receipt) => receipt.authority_epoch(),
            Self::Pin(receipt) => receipt.authority_epoch(),
        }
    }
    pub fn group_epoch(&self) -> i64 {
        match self {
            Self::Snapshot(receipt) => receipt.group_epoch(),
            Self::Pin(receipt) => receipt.group_epoch(),
        }
    }

    pub fn as_snapshot(&self) -> Option<&MetadataSnapshotReceipt> {
        match self {
            Self::Snapshot(receipt) => Some(receipt),
            Self::Pin(_) => None,
        }
    }
    pub fn as_pin(&self) -> Option<&MetadataPinReceipt> {
        match self {
            Self::Snapshot(_) => None,
            Self::Pin(receipt) => Some(receipt),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateMetadataSnapshotOutcome {
    /// True when the identical request already had a durable receipt.
    pub replayed: bool,
    pub receipt: MetadataSnapshotReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataPinOutcome {
    /// True when the identical request already had a durable receipt. The
    /// receipt is the old one: it is not proof the lease is currently live.
    pub replayed: bool,
    pub receipt: MetadataPinReceipt,
}

/// Resolution of an unknown metadata COMMIT by its stable request id.
// Receipts have a fixed, bounded inline representation. Keep successful
// internal lookups allocation-free instead of boxing every returned receipt.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataReceiptLookup {
    Found(MetadataReceipt),
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> MetadataSnapshotScope {
        MetadataSnapshotScope::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            MetadataPinPurpose::Backup,
            GitObjectFormat::Sha1,
            Uuid::new_v4(),
            1,
            1,
        )
        .unwrap()
    }

    #[test]
    fn creation_receipt_round_trips_and_never_claims_pack_membership() {
        let scope = scope();
        let receipt = MetadataSnapshotReceipt::from_parts(SnapshotReceiptParts {
            request_id: Uuid::new_v4(),
            snapshot_id: Uuid::new_v4(),
            pin_id: Uuid::new_v4(),
            pin_generation: 1,
            scope,
            gate_revision: 3,
            gate_digest: "a".repeat(64),
            head_ref: "refs/heads/main".into(),
            head_oid: Some("b".repeat(40)),
            ref_count: 1,
            refs_digest: "c".repeat(64),
            logical_bytes: 512,
            expires_at_unix_micros: 1_700_000_000_000_000,
        });
        let body = serde_json::to_string(&receipt).unwrap();
        assert_eq!(serde_json::from_str::<MetadataSnapshotReceipt>(&body).unwrap(), receipt);
        assert!(!receipt.complete_git_read_snapshot());
        assert!(!receipt.packs().complete_git_read_snapshot());
        assert_eq!(receipt.purpose(), MetadataPinPurpose::Backup);
    }

    #[test]
    fn page_is_complete_exactly_without_a_cursor() {
        let page = MetadataSnapshotPage::new(Uuid::new_v4(), Uuid::new_v4(), 1, 2, 0, Vec::new(), None);
        assert!(page.complete());
        assert_eq!(page.refs().len(), 0);
    }
}
