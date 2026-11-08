//! Bounds, canonical digests, accounting and error mapping for the A5a
//! complete registered-pack-membership snapshot.
//!
//! No IO happens here. Everything is either a fixed named bound, a canonical
//! SHA-256 digest over full semantic identity, or a conservative retained-byte
//! computation that is charged *before* the first persistent write.
//!
//! Two counter families are deliberately independent and both are charged in the
//! same transaction:
//!
//! * the migration-140 A2 repo/tenant counters, which bound the A2-lifetime rows
//!   (snapshot header, snapshot refs, pin, receipt ledger) and cascade away with
//!   the repository/tenant;
//! * the migration-143 permanent pack-snapshot repo/tenant counters, which have
//!   no business foreign key at all and bound the retained *permanent* state
//!   (snapshot header, refs, pack bindings, pins, history rows, receipts and
//!   logical bytes) after repository/user deletion.
//!
//! Charging the same row in both families is intentional: each family bounds its
//! own lifetime, and neither can refund the other.
use super::super::pack_commit::{
    MembershipDigest, PackCommitError, PackCommitRejectCode, PackMembershipEntry, RegisteredPack,
};
use super::super::snapshot_contract::MetadataSnapshotScope;
use super::super::snapshot_contract::{MAX_RECEIPT_BODY_BYTES, MAX_SNAPSHOT_PACKS, MAX_SNAPSHOT_REFS};
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use uuid::Uuid;

/// The only pack mode a pack-aware snapshot may capture or read.
pub const PACK_MODE_VERIFIED: &str = "pack_verified";
/// Canonical domain of the stored per-snapshot digest.
pub const SNAPSHOT_DIGEST_DOMAIN: &str = "core-pack-snapshot-v1";
/// Canonical domain of the canonical create-request digest.
pub const CREATE_REQUEST_DIGEST_DOMAIN: &str = "core-pack-snapshot-create-v1";
/// Canonical domain of the sealed read-result digest.
pub const READ_RESULT_DIGEST_DOMAIN: &str = "core-pack-read-snapshot-v1";

/// Retained per-repository permanent admission bounds.
///
/// `snapshots` and `refs` mirror the conservative A2 bounds because every pack
/// snapshot is exactly one A2 header plus one captured ref row set. `bindings` is
/// the fixed 16-packs-per-snapshot product, `pins` is one per snapshot, and
/// `history`/`receipts` reuse the A2 receipt bound because every successful
/// mutation writes exactly one receipt and one permanent history row.
pub const REPO_MAX_PACK_SNAPSHOTS: i64 = 64;
pub const REPO_MAX_PACK_REFS: i64 = 16_384;
pub const REPO_MAX_PACK_BINDINGS: i64 = 1_024;
pub const REPO_MAX_PACK_PINS: i64 = 64;
pub const REPO_MAX_PACK_HISTORY: i64 = 2_048;
pub const REPO_MAX_PACK_RECEIPTS: i64 = 2_048;
pub const REPO_MAX_PACK_LOGICAL_BYTES: i64 = 16 * 1024 * 1024;

/// Fixed bounded tenant factor: every tenant bound is exactly 4x its repository
/// bound, so a tenant can never hold more than four full repositories' worth of
/// permanent pack-snapshot history.
pub const TENANT_PACK_FACTOR: i64 = 4;
pub const TENANT_MAX_PACK_SNAPSHOTS: i64 = REPO_MAX_PACK_SNAPSHOTS * TENANT_PACK_FACTOR;
pub const TENANT_MAX_PACK_REFS: i64 = REPO_MAX_PACK_REFS * TENANT_PACK_FACTOR;
pub const TENANT_MAX_PACK_BINDINGS: i64 = REPO_MAX_PACK_BINDINGS * TENANT_PACK_FACTOR;
pub const TENANT_MAX_PACK_PINS: i64 = REPO_MAX_PACK_PINS * TENANT_PACK_FACTOR;
pub const TENANT_MAX_PACK_HISTORY: i64 = REPO_MAX_PACK_HISTORY * TENANT_PACK_FACTOR;
pub const TENANT_MAX_PACK_RECEIPTS: i64 = REPO_MAX_PACK_RECEIPTS * TENANT_PACK_FACTOR;
pub const TENANT_MAX_PACK_LOGICAL_BYTES: i64 = REPO_MAX_PACK_LOGICAL_BYTES * TENANT_PACK_FACTOR;

/// Conservative retained bytes of ONE `ref_store_core_snapshot_packs` row.
///
/// It is computed from the actual column widths instead of an arbitrary
/// estimate: four UUID columns (4x16), one 64-hex digest (64), one bigint (8),
/// plus 64 bytes of row header/tuple/padding allowance. The bound is therefore
/// never smaller than the physically retained binding.
pub const PACK_BINDING_OVERHEAD_BYTES: i64 = 4 * 16 + 64 + 8 + 64;

/// Conservative retained bytes of ONE permanent history row *excluding* its
/// canonical body: history_id/request_id/repository/tenant/owner/snapshot/pin
/// UUIDs (7x16), gate revision (8), five 64-hex digests (5x64) including the
/// persisted canonical request digest, bounded kind/pack_mode text (24),
/// pack_count (4), created_at (8) and a 96-byte tuple allowance.
pub const PACK_HISTORY_OVERHEAD_BYTES: i64 = 7 * 16 + 8 + 5 * 64 + 24 + 4 + 8 + 96;

/// The permanent history body is the same canonical bounded body the A2 receipt
/// ledger stores, so it can never be larger than the A2 receipt bound.
pub const MAX_PACK_HISTORY_BODY_BYTES: usize = MAX_RECEIPT_BODY_BYTES;

/// Conservative retained bytes of one captured pack binding set.
pub(crate) fn pack_binding_logical_bytes(pack_count: usize) -> i64 {
    PACK_BINDING_OVERHEAD_BYTES.saturating_mul(i64::try_from(pack_count).unwrap_or(i64::MAX))
}

/// Conservative retained bytes of one permanent history row plus its body.
pub(crate) fn history_logical_bytes(body_bytes: usize) -> i64 {
    PACK_HISTORY_OVERHEAD_BYTES.saturating_add(i64::try_from(body_bytes).unwrap_or(i64::MAX))
}

/// Typed, sorted, unique membership entries of one captured pack set.
///
/// Every pack must carry its `joined_revision`; a pack without one is not an
/// active membership and is refused rather than silently treated as new.
pub(super) fn membership_entries(packs: &[RegisteredPack]) -> Result<Vec<PackMembershipEntry>, RefStoreError> {
    if packs.is_empty() || packs.len() > MAX_SNAPSHOT_PACKS {
        return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count: packs.len(), max_refs: MAX_SNAPSHOT_PACKS });
    }
    let mut sorted = packs.to_vec();
    sorted.sort_by_key(RegisteredPack::pack_id);
    let mut entries = Vec::with_capacity(sorted.len());
    for pack in &sorted {
        entries.push(PackMembershipEntry::from_pack(pack).map_err(map_pack_error)?);
    }
    Ok(entries)
}

/// Canonical membership digest of a full captured pack set.
pub(super) fn membership_digest(packs: &[RegisteredPack]) -> Result<MembershipDigest, RefStoreError> {
    Ok(MembershipDigest::of(&membership_entries(packs)?))
}

/// Canonical digest of one captured pack-aware snapshot.
///
/// It binds the full trusted scope, the immutable snapshot id, the exact gate
/// revision *and* digest, HEAD, the ref count and A2-domain refs digest, the
/// membership digest and the pack count. It deliberately does not bind the pin
/// generation or lease: those are lease state, not captured data, and are bound
/// by the sealed read-result digest instead.
#[allow(clippy::too_many_arguments)]
pub(super) fn snapshot_digest(
    scope: &MetadataSnapshotScope,
    snapshot_id: Uuid,
    gate_revision: i64,
    gate_digest: &str,
    head_ref: &str,
    head_oid: Option<&str>,
    ref_count: i64,
    refs_digest: &str,
    membership_digest: &str,
    pack_count: i64,
) -> RequestDigest {
    let oid_presence: &[u8] = if head_oid.is_some() { b"head-oid-present" } else { b"head-oid-absent" };
    RequestDigest::of(
        SNAPSHOT_DIGEST_DOMAIN,
        &[
            scope.repository_id().as_bytes(),
            scope.tenant_id().as_bytes(),
            scope.owner_id().as_bytes(),
            scope.purpose().as_str().as_bytes(),
            scope.object_format().as_str().as_bytes(),
            scope.history_incarnation().as_bytes(),
            &scope.authority_epoch().to_be_bytes(),
            &scope.group_epoch().to_be_bytes(),
            snapshot_id.as_bytes(),
            &gate_revision.to_be_bytes(),
            gate_digest.as_bytes(),
            PACK_MODE_VERIFIED.as_bytes(),
            head_ref.as_bytes(),
            oid_presence,
            head_oid.unwrap_or("").as_bytes(),
            &ref_count.to_be_bytes(),
            refs_digest.as_bytes(),
            membership_digest.as_bytes(),
            &pack_count.to_be_bytes(),
        ],
    )
}

/// Map an A4 refusal into the shared ref-store vocabulary.
///
/// A stored-registration inconsistency is a database-integrity error, never
/// `Found`; a realm/epoch disagreement is a scope mismatch; a mode refusal is
/// `Unsupported`. No variant here carries bytes, a locator or Git text.
pub(super) fn map_pack_error(error: PackCommitError) -> RefStoreError {
    fn capacity(actual: i64, bound: i64) -> RefStoreError {
        RefStoreError::MetadataSnapshotTooLarge {
            ref_count: usize::try_from(actual.max(0)).unwrap_or(MAX_SNAPSHOT_REFS + 1),
            max_refs: usize::try_from(bound.max(0)).unwrap_or(0),
        }
    }
    match error {
        PackCommitError::RefStore(error) => error,
        PackCommitError::Invalid(reason) => {
            RefStoreError::Database(format!("A4 registered pack data is invalid: {reason}"))
        }
        PackCommitError::Capacity { bound, actual, .. } => capacity(actual, bound),
        PackCommitError::ProofUnavailable(_) => {
            RefStoreError::Unsupported("A4 closure proof is not part of a pack snapshot read")
        }
        PackCommitError::CommitUnknown { repository_id, operation_id } => {
            RefStoreError::CommitUnknown { repository_id, operation_id: Some(operation_id) }
        }
        PackCommitError::Rejected(rejection) => match rejection.code {
            PackCommitRejectCode::CaptureOverflow => capacity(MAX_SNAPSHOT_PACKS as i64 + 1, MAX_SNAPSHOT_PACKS as i64),
            PackCommitRejectCode::ModeMismatch => {
                RefStoreError::Unsupported("registered pack membership requires a pack_verified gate")
            }
            PackCommitRejectCode::TenantMismatch
            | PackCommitRejectCode::ObjectFormatMismatch
            | PackCommitRejectCode::HistoryIncarnationMismatch
            | PackCommitRejectCode::AuthorityEpochMismatch
            | PackCommitRejectCode::GroupEpochMismatch => {
                RefStoreError::MetadataScopeMismatch("A4 registered pack realm")
            }
            other => RefStoreError::Database(format!(
                "A4 registered pack ledger refused this snapshot ({}): {}",
                other.as_str(),
                rejection.detail
            )),
        },
    }
}
