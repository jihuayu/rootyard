//! Durable metadata pin/snapshot state machine and the immutable receipt codec.
//!
//! No IO happens here: the adapter reads one locked snapshot/pin row and this
//! module decides whether a page, renewal or release is admissible. Lease
//! decisions use the *database* clock: the adapter selects
//! `expires_at <= clock_timestamp()` as a boolean, so a client clock can never
//! extend or shorten protection.
//!
//! Lifecycle rules:
//!   * `active -> released` is the only terminal transition and a released pin
//!     never becomes active again, so a pin id cannot be reused.
//!   * Renewal advances `generation` by exactly one; a stale expected generation
//!     is a mismatch, never an implicit retry.
//!   * Expiry denies new pages and renewals only. It never deletes, refunds or
//!     revives anything, and an exact release is still allowed.
use super::super::contract::{MetadataMutationAction, MetadataPinPurpose, RefStoreError};
use super::snapshot_contract::{MAX_RECEIPT_BODY_BYTES, MetadataSnapshotScope};
use super::snapshot_receipt::{MetadataPinReceipt, MetadataReceipt, MetadataSnapshotReceipt};
use super::snapshot_request::PinReleaseReason;
use super::types::GitObjectFormat;
use uuid::Uuid;

/// Stored pin state. There is no `expired` state: expiry is derived from the
/// lease timestamp so an expired pin stays retained and explicitly releasable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PinState {
    Active,
    Released,
}

impl PinState {
    pub(super) fn parse(value: &str) -> Result<Self, RefStoreError> {
        match value {
            "active" => Ok(Self::Active),
            "released" => Ok(Self::Released),
            _ => Err(RefStoreError::Database("stored metadata pin state is not a known state".into())),
        }
    }
}

/// One row of an immutable metadata snapshot header.
///
/// Every field is the retained audit payload as captured; the adapter reads the
/// ones it needs and the rest stay available to later pack/GC increments, so
/// they are intentionally kept here rather than discarded at projection time.
#[allow(dead_code)]
pub(super) struct SnapshotHeader {
    pub snapshot_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: MetadataPinPurpose,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub head_ref: String,
    pub head_oid: Option<String>,
    pub ref_count: i64,
    pub refs_digest: String,
    pub logical_bytes: i64,
}

impl SnapshotHeader {
    /// A stored snapshot row must match the full requested scope. A later refs
    /// revision is fine (rows are immutable); a different
    /// tenant/owner/purpose/format/history/authority/group is not.
    pub(super) fn ensure_scope(&self, scope: &MetadataSnapshotScope) -> Result<(), RefStoreError> {
        if self.repository_id != scope.repository_id() || self.tenant_id != scope.tenant_id() {
            return Err(RefStoreError::MetadataScopeMismatch("snapshot repository/tenant"));
        }
        if self.owner_id != scope.owner_id() {
            return Err(RefStoreError::MetadataScopeMismatch("snapshot owner"));
        }
        if self.purpose != scope.purpose() {
            return Err(RefStoreError::MetadataScopeMismatch("snapshot purpose"));
        }
        if self.object_format != scope.object_format() {
            return Err(RefStoreError::MetadataScopeMismatch("snapshot object format"));
        }
        if self.history_incarnation != scope.history_incarnation() {
            return Err(RefStoreError::MetadataScopeMismatch("snapshot history incarnation"));
        }
        if self.authority_epoch != scope.authority_epoch() {
            return Err(RefStoreError::MetadataScopeMismatch("snapshot authority epoch"));
        }
        if self.group_epoch != scope.group_epoch() {
            return Err(RefStoreError::MetadataScopeMismatch("snapshot group epoch"));
        }
        Ok(())
    }
}

/// Immutable identity columns of one pin. Receipt replay compares these only;
/// generation and expiry are intentionally absent because a historical receipt
/// may legitimately predate a renewal or release.
pub(super) struct PinIdentity {
    pub pin_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub snapshot_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: MetadataPinPurpose,
}

/// One locked durable pin row plus the database-clock expiry observation.
pub(super) struct PinRow {
    pub pin_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub snapshot_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: MetadataPinPurpose,
    pub generation: i64,
    pub state: PinState,
    /// Retained lease/release timestamps, kept for the immutable receipt body
    /// of a later renewal/release (never used to extend a lease by a client
    /// clock).
    #[allow(dead_code)]
    pub expires_at_unix_micros: i64,
    #[allow(dead_code)]
    pub released_at_unix_micros: Option<i64>,
    #[allow(dead_code)]
    pub release_reason: Option<PinReleaseReason>,
    /// Selected as `expires_at <= clock_timestamp()` by the adapter.
    pub expired: bool,
}

impl PinRow {
    /// A pin row must match the requested tenant/owner/purpose and be the pin
    /// of the requested snapshot. It never matches a different pin id.
    pub(super) fn ensure_scope(&self, scope: &MetadataSnapshotScope, snapshot_id: Uuid) -> Result<(), RefStoreError> {
        if self.repository_id != scope.repository_id() || self.tenant_id != scope.tenant_id() {
            return Err(RefStoreError::MetadataScopeMismatch("pin repository/tenant"));
        }
        if self.snapshot_id != snapshot_id {
            return Err(RefStoreError::MetadataScopeMismatch("pin snapshot"));
        }
        if self.owner_id != scope.owner_id() {
            return Err(RefStoreError::MetadataScopeMismatch("pin owner"));
        }
        if self.purpose != scope.purpose() {
            return Err(RefStoreError::MetadataScopeMismatch("pin purpose"));
        }
        Ok(())
    }

    /// A page or renewal requires an active, unexpired pin at the caller's
    /// generation. Pages admitted before a release may still finish because they
    /// hold the pin `FOR SHARE`; this check only orders new requests.
    pub(super) fn ensure_live(&self, expected_generation: i64) -> Result<(), RefStoreError> {
        self.ensure_not_released()?;
        self.ensure_generation(expected_generation)?;
        if self.expired {
            return Err(RefStoreError::MetadataPinExpired { pin_id: self.pin_id, generation: self.generation });
        }
        Ok(())
    }

    /// Renewal also rechecks liveness: an expired lease is never silently
    /// extended by a renew call.
    pub(super) fn ensure_renewable(&self, expected_generation: i64) -> Result<(), RefStoreError> {
        self.ensure_live(expected_generation)
    }

    /// Release is exact: the right generation, the right pin, and released
    /// state is terminal. Expiry and repository transition do not block it, and
    /// it never refunds retained usage.
    pub(super) fn ensure_releasable(&self, expected_generation: i64) -> Result<(), RefStoreError> {
        self.ensure_not_released()?;
        self.ensure_generation(expected_generation)
    }

    /// Typed reason a locked renewal UPDATE affected zero rows. The pin row is
    /// already locked, so a zero-row atomic UPDATE can only mean the database
    /// clock crossed the lease (or the row is no longer renewable).
    pub(super) fn renew_conflict_error(&self, expected_generation: i64) -> RefStoreError {
        if self.state == PinState::Released {
            RefStoreError::MetadataPinReleased { pin_id: self.pin_id, generation: self.generation }
        } else if self.expired {
            RefStoreError::MetadataPinExpired { pin_id: self.pin_id, generation: self.generation }
        } else {
            RefStoreError::MetadataPinGenerationMismatch {
                pin_id: self.pin_id,
                expected: expected_generation,
                actual: self.generation,
            }
        }
    }

    fn ensure_not_released(&self) -> Result<(), RefStoreError> {
        if self.state == PinState::Released {
            return Err(RefStoreError::MetadataPinReleased { pin_id: self.pin_id, generation: self.generation });
        }
        Ok(())
    }

    fn ensure_generation(&self, expected_generation: i64) -> Result<(), RefStoreError> {
        if self.generation != expected_generation {
            return Err(RefStoreError::MetadataPinGenerationMismatch {
                pin_id: self.pin_id,
                expected: expected_generation,
                actual: self.generation,
            });
        }
        Ok(())
    }
}

/// The canonical bounded JSON body stored for one successful mutation.
pub(super) fn encode_receipt(receipt: &MetadataReceipt) -> Result<String, RefStoreError> {
    let body = match receipt {
        MetadataReceipt::Snapshot(receipt) => serde_json::to_string(receipt),
        MetadataReceipt::Pin(receipt) => serde_json::to_string(receipt),
    }
    .map_err(|error| RefStoreError::Database(format!("metadata receipt encoding failed: {error}")))?;
    if body.len() > MAX_RECEIPT_BODY_BYTES {
        return Err(RefStoreError::MetadataSnapshotTooLarge {
            ref_count: body.len(),
            max_refs: MAX_RECEIPT_BODY_BYTES,
        });
    }
    Ok(body)
}

/// Decode a stored body under its recorded action. A body that parses as a
/// different action is corrupt ledger state, never a silent reinterpretation.
pub(super) fn decode_receipt(action: MetadataMutationAction, body: &str) -> Result<MetadataReceipt, RefStoreError> {
    if body.is_empty() || body.len() > MAX_RECEIPT_BODY_BYTES {
        return Err(RefStoreError::Database("stored metadata receipt body is not bounded".into()));
    }
    match action {
        MetadataMutationAction::Create => serde_json::from_str::<MetadataSnapshotReceipt>(body)
            .map(MetadataReceipt::Snapshot)
            .map_err(|error| RefStoreError::Database(format!("stored metadata create receipt is invalid: {error}"))),
        MetadataMutationAction::Renew | MetadataMutationAction::Release => {
            let receipt = serde_json::from_str::<MetadataPinReceipt>(body)
                .map_err(|error| RefStoreError::Database(format!("stored metadata pin receipt is invalid: {error}")))?;
            if receipt.action() != action {
                return Err(RefStoreError::Database(
                    "stored metadata receipt action differs from its ledger action".into(),
                ));
            }
            Ok(MetadataReceipt::Pin(receipt))
        }
    }
}

/// A decoded receipt must describe exactly the requesting scope.
pub(super) fn ensure_receipt_scope(
    receipt: &MetadataReceipt,
    scope: &MetadataSnapshotScope,
) -> Result<(), RefStoreError> {
    let matches = match receipt {
        MetadataReceipt::Snapshot(receipt) => {
            receipt.repository_id() == scope.repository_id()
                && receipt.tenant_id() == scope.tenant_id()
                && receipt.owner_id() == scope.owner_id()
                && receipt.purpose() == scope.purpose()
                && receipt.object_format() == scope.object_format()
                && receipt.history_incarnation() == scope.history_incarnation()
                && receipt.authority_epoch() == scope.authority_epoch()
                && receipt.group_epoch() == scope.group_epoch()
        }
        MetadataReceipt::Pin(receipt) => {
            receipt.repository_id() == scope.repository_id()
                && receipt.tenant_id() == scope.tenant_id()
                && receipt.owner_id() == scope.owner_id()
                && receipt.purpose() == scope.purpose()
                && receipt.object_format() == scope.object_format()
                && receipt.history_incarnation() == scope.history_incarnation()
                && receipt.authority_epoch() == scope.authority_epoch()
                && receipt.group_epoch() == scope.group_epoch()
        }
    };
    if !matches {
        return Err(RefStoreError::MetadataScopeMismatch("stored receipt"));
    }
    Ok(())
}

/// The decoded body must agree with the authoritative immutable ledger key.
#[allow(clippy::too_many_arguments)]
pub(super) fn ensure_receipt_ledger(
    receipt: &MetadataReceipt,
    request_id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    action: MetadataMutationAction,
    pin_id: Uuid,
    snapshot_id: Uuid,
    pin_generation: i64,
) -> Result<(), RefStoreError> {
    if receipt.request_id() != request_id
        || receipt.repository_id() != repository_id
        || receipt.tenant_id() != tenant_id
        || receipt.action() != action
        || receipt.pin_id() != pin_id
        || receipt.snapshot_id() != snapshot_id
        || receipt.pin_generation() != pin_generation
    {
        return Err(RefStoreError::Database(
            "stored metadata receipt body disagrees with its immutable ledger row".into(),
        ));
    }
    Ok(())
}

/// A historical receipt must still match its immutable snapshot header. It is
/// never compared with the current refs revision, which may have moved on.
pub(super) fn ensure_receipt_snapshot(receipt: &MetadataReceipt, header: &SnapshotHeader) -> Result<(), RefStoreError> {
    if receipt.snapshot_id() != header.snapshot_id
        || receipt.repository_id() != header.repository_id
        || receipt.tenant_id() != header.tenant_id
        || receipt.owner_id() != header.owner_id
        || receipt.purpose() != header.purpose
        || receipt.object_format() != header.object_format
        || receipt.history_incarnation() != header.history_incarnation
        || receipt.authority_epoch() != header.authority_epoch
        || receipt.group_epoch() != header.group_epoch
    {
        return Err(RefStoreError::MetadataScopeMismatch("stored receipt snapshot"));
    }
    // A creation receipt also captures the exact refs/HEAD summary. Every one
    // of those immutable fields must still agree with the stored header; a
    // tampered body must never replay as a valid old receipt. Pack membership
    // is fixed `unavailable` by both the contract and the migration CHECK, so
    // there is no varying pack field to compare.
    if let MetadataReceipt::Snapshot(snapshot) = receipt
        && (snapshot.gate_revision() != header.gate_revision
            || snapshot.gate_digest_hex() != header.gate_digest.as_str()
            || snapshot.head_ref() != header.head_ref.as_str()
            || snapshot.head_oid_hex() != header.head_oid.as_deref()
            || snapshot.ref_count() != header.ref_count
            || snapshot.refs_digest_hex() != header.refs_digest.as_str()
            || snapshot.logical_bytes() != header.logical_bytes)
    {
        return Err(RefStoreError::MetadataScopeMismatch("stored receipt snapshot summary"));
    }
    Ok(())
}

/// A historical receipt must still match the immutable identity of its pin. It
/// must not compare the receipt generation to the live pin generation.
pub(super) fn ensure_receipt_pin_identity(receipt: &MetadataReceipt, pin: &PinIdentity) -> Result<(), RefStoreError> {
    if receipt.pin_id() != pin.pin_id
        || receipt.snapshot_id() != pin.snapshot_id
        || receipt.repository_id() != pin.repository_id
        || receipt.tenant_id() != pin.tenant_id
        || receipt.owner_id() != pin.owner_id
        || receipt.purpose() != pin.purpose
    {
        return Err(RefStoreError::MetadataScopeMismatch("stored receipt pin"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::snapshot_receipt::SnapshotReceiptParts;
    use super::*;

    fn scope() -> MetadataSnapshotScope {
        MetadataSnapshotScope::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            MetadataPinPurpose::Maintenance,
            GitObjectFormat::Sha256,
            Uuid::new_v4(),
            2,
            3,
        )
        .unwrap()
    }

    fn pin(scope: &MetadataSnapshotScope, state: PinState, generation: i64, expired: bool) -> PinRow {
        PinRow {
            pin_id: Uuid::new_v4(),
            repository_id: scope.repository_id(),
            tenant_id: scope.tenant_id(),
            snapshot_id: Uuid::new_v4(),
            owner_id: scope.owner_id(),
            purpose: scope.purpose(),
            generation,
            state,
            expires_at_unix_micros: 1,
            released_at_unix_micros: None,
            release_reason: None,
            expired,
        }
    }

    #[test]
    fn released_pin_is_terminal() {
        let scope = scope();
        let row = pin(&scope, PinState::Released, 2, false);
        assert!(matches!(row.ensure_live(2), Err(RefStoreError::MetadataPinReleased { .. })));
        assert!(matches!(row.ensure_renewable(2), Err(RefStoreError::MetadataPinReleased { .. })));
        assert!(matches!(row.ensure_releasable(2), Err(RefStoreError::MetadataPinReleased { .. })));
        assert!(row.ensure_scope(&scope, row.snapshot_id).is_ok());
    }

    #[test]
    fn expiry_denies_pages_and_renewals_but_allows_exact_release() {
        let scope = scope();
        let row = pin(&scope, PinState::Active, 4, true);
        assert!(matches!(row.ensure_live(4), Err(RefStoreError::MetadataPinExpired { .. })));
        assert!(matches!(row.ensure_renewable(4), Err(RefStoreError::MetadataPinExpired { .. })));
        assert!(row.ensure_releasable(4).is_ok());
        assert!(matches!(row.ensure_releasable(3), Err(RefStoreError::MetadataPinGenerationMismatch { .. })));
    }

    #[test]
    fn receipt_codec_is_action_typed_and_bounded() {
        let scope = scope();
        let snapshot = MetadataSnapshotReceipt::from_parts(SnapshotReceiptParts {
            request_id: Uuid::new_v4(),
            snapshot_id: Uuid::new_v4(),
            pin_id: Uuid::new_v4(),
            pin_generation: 1,
            scope,
            gate_revision: 1,
            gate_digest: "a".repeat(64),
            head_ref: "refs/heads/main".into(),
            head_oid: None,
            ref_count: 0,
            refs_digest: "b".repeat(64),
            logical_bytes: 1,
            expires_at_unix_micros: 1,
        });
        let body = encode_receipt(&MetadataReceipt::Snapshot(snapshot)).unwrap();
        assert!(matches!(decode_receipt(MetadataMutationAction::Create, &body).unwrap(), MetadataReceipt::Snapshot(_)));
        assert!(decode_receipt(MetadataMutationAction::Renew, &body).is_err());
        assert!(decode_receipt(MetadataMutationAction::Create, &"x".repeat(MAX_RECEIPT_BODY_BYTES + 1)).is_err());
    }
}
