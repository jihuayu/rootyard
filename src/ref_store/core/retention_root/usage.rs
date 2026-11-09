//! Fixed retained admission bounds and the per-mutation charge for roots.
//!
//! Roots are non-expiring and survive a whole-repository delete, so admission is a **retained** ceiling over
//! every root row a repository/tenant has ever written. Counters only grow: there is no refund on release,
//! source-pin expiry, error or unknown outcome, and no automatic pruning. `RootQuotaExceeded` is backpressure,
//! never a reason to release or delete a root.
//!
//! Every counter is charged *before* the first persistent write, inside the same short transaction that locks
//! the tenant usage row and then the repository usage row (the frozen cross-feature order), and the charge is
//! computed from the **actual** canonical column values the mutation is about to write. A per-row constant is
//! never used where a stored field is variable-width: a captured ref name may be 1024 bytes and its object id
//! 64, a complete pack binding carries two full locators, and the capture header carries many tell-tale digests
//! and identity text. Residual uncertainty is covered by a fixed, generous per-row overhead that is larger than
//! any tuple header/alignment cost. An exact receipt replay returns before any lock/charge, so it is never
//! double charged and nothing is ever refunded.
use super::candidate::RootCandidate;
use super::scope::RootsScope;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::{CapturedRef, PackArtifactRole, RegisteredArtifact, RegisteredPack};

/// Retained per-repository ceilings.
pub const REPO_MAX_ROOTS: i64 = 64;
pub const REPO_MAX_ROOT_OID_REFS: i64 = 4_096;
pub const REPO_MAX_PACK_BINDINGS: i64 = 1_024;
pub const REPO_MAX_RECEIPTS: i64 = 2_048;
pub const REPO_MAX_LOGICAL_BYTES: i64 = 32 * 1024 * 1024;

/// Fixed bounded tenant factor: every tenant ceiling is exactly 4x its repository ceiling.
pub const TENANT_FACTOR: i64 = 4;
pub const TENANT_MAX_ROOTS: i64 = REPO_MAX_ROOTS * TENANT_FACTOR;
pub const TENANT_MAX_ROOT_OID_REFS: i64 = REPO_MAX_ROOT_OID_REFS * TENANT_FACTOR;
pub const TENANT_MAX_PACK_BINDINGS: i64 = REPO_MAX_PACK_BINDINGS * TENANT_FACTOR;
pub const TENANT_MAX_RECEIPTS: i64 = REPO_MAX_RECEIPTS * TENANT_FACTOR;
pub const TENANT_MAX_LOGICAL_BYTES: i64 = REPO_MAX_LOGICAL_BYTES * TENANT_FACTOR;

/// Hard selector bound: exact root object ids per root.
pub const MAX_ROOT_OIDS: usize = 256;
/// Hard receipt body bound (canonical JSON, no raw payload).
pub const MAX_RECEIPT_BODY_BYTES: usize = 65_536;

// -----------------------------------------------------------------------------------------------------------
// Stored-width vocabulary for the actual-byte charge.
//
// Every charged byte is either (a) the actual length of a value this mutation writes (`ref_name`, `oid`,
// namespace/provider/backend identity, header text) or (b) a fixed stored width of a bounded column
// (`UUID` 16, `BIGINT` 8, `INT` 4, `TIMESTAMPTZ` 8, `^[0-9a-f]{64}$` digest 64, bounded enum text <= 64), plus
// one per-row overhead that is larger than any PostgreSQL tuple header/alignment/xmin-xmax/ctid cost.
// -----------------------------------------------------------------------------------------------------------

/// Conservative per-row heap overhead (tuple header, null bitmap, item pointer, alignment, `xmin`/`xmax`/`ctid`).
const ROW_OVERHEAD_BYTES: i64 = 128;
/// Stored width of one `UUID` column (binary 16 bytes; the `::text` form is never stored).
const UUID_BYTES: i64 = 16;
/// Stored width of one `BIGINT` column.
const BIGINT_BYTES: i64 = 8;
/// Stored width of one `INT` column.
const INT_BYTES: i64 = 4;
/// Stored width of one `TIMESTAMPTZ` column.
const TIMESTAMPTZ_BYTES: i64 = 8;
/// Upper bound of one bounded enum/purpose/action/state text column.
const ENUM_TEXT_BYTES: i64 = 64;
/// Stored width of one canonical lowercase sha256 hex digest column.
const DIGEST_BYTES: i64 = 64;
/// Upper bound of one stored root tombstone `reason` (`1..=256`).
const REASON_MAX_BYTES: i64 = 256;

fn text_bytes(value: &str) -> i64 {
    i64::try_from(value.len()).unwrap_or(i64::MAX)
}

fn total(parts: impl IntoIterator<Item = i64>) -> i64 {
    parts.into_iter().fold(0i64, |sum, part| sum.saturating_add(part))
}

fn sum_by<T>(items: &[T], weigh: impl Fn(&T) -> i64) -> i64 {
    items.iter().fold(0i64, |sum, item| sum.saturating_add(weigh(item)))
}

/// Actual bytes of one stored artifact identity: three UUIDs, both lengths, its generation, slot, hold id, and
/// the complete `namespace`/`sha256`/`provider`/`backend_identity`/`verified_sha256` text it carries.
fn artifact_bytes(artifact: &RegisteredArtifact) -> i64 {
    let locator = artifact.locator();
    total([
        ROW_OVERHEAD_BYTES,
        UUID_BYTES * 3,
        BIGINT_BYTES * 3,
        INT_BYTES,
        text_bytes(locator.namespace()),
        text_bytes(locator.sha256().as_str()),
        text_bytes(artifact.provider()),
        text_bytes(artifact.backend_identity()),
        text_bytes(artifact.verified_sha256().as_str()),
    ])
}

/// Complete bytes of one `ref_store_core_root_packs` binding row (pack + both artifacts, fully self-contained).
fn pack_row_bytes(pack: &RegisteredPack) -> i64 {
    total([
        UUID_BYTES * 3,
        DIGEST_BYTES,
        BIGINT_BYTES,
        artifact_bytes(pack.artifact(PackArtifactRole::Pack)),
        artifact_bytes(pack.artifact(PackArtifactRole::Idx)),
    ])
}

/// Actual bytes of one `ref_store_core_root_refs` row: the captured ref name (may be 1024 bytes) and its oid.
fn ref_row_bytes(reference: &CapturedRef) -> i64 {
    total([
        ROW_OVERHEAD_BYTES,
        UUID_BYTES * 2,
        BIGINT_BYTES,
        text_bytes(reference.name()),
        text_bytes(reference.oid_hex()),
    ])
}

/// Actual bytes of one `ref_store_core_root_oids` row: the selector oid (40 or 64 bytes) plus ordinal.
fn oid_row_bytes(oid: &str) -> i64 {
    total([ROW_OVERHEAD_BYTES, UUID_BYTES * 2, BIGINT_BYTES, INT_BYTES, text_bytes(oid)])
}

/// Actual bytes of one `ref_store_core_root_heads` row.
fn head_row_bytes(scope: &RootsScope, register_digest: &str) -> i64 {
    total([
        ROW_OVERHEAD_BYTES,
        UUID_BYTES * 4,
        BIGINT_BYTES,
        TIMESTAMPTZ_BYTES * 2,
        ENUM_TEXT_BYTES * 2,
        DIGEST_BYTES,
        text_bytes(register_digest),
        text_bytes(scope.purpose().as_str()),
    ])
}

/// Actual bytes of one `ref_store_core_root_tombstones` row.
fn tombstone_row_bytes(scope: &RootsScope, reason: &str) -> i64 {
    let reason_bytes = text_bytes(reason).min(REASON_MAX_BYTES);
    total([
        ROW_OVERHEAD_BYTES,
        UUID_BYTES * 5,
        BIGINT_BYTES,
        TIMESTAMPTZ_BYTES,
        ENUM_TEXT_BYTES,
        DIGEST_BYTES * 3,
        text_bytes(scope.purpose().as_str()),
        reason_bytes,
    ])
}

/// Actual bytes of one immutable `ref_store_core_roots` capture header row.
fn capture_row_bytes(candidate: &RootCandidate) -> i64 {
    total([
        ROW_OVERHEAD_BYTES,
        UUID_BYTES * 9,
        BIGINT_BYTES * 6,
        INT_BYTES * 3,
        TIMESTAMPTZ_BYTES,
        ENUM_TEXT_BYTES * 2,
        text_bytes(candidate.scope().purpose().as_str()),
        text_bytes(candidate.scope().object_format().as_str()),
        DIGEST_BYTES * 9,
        text_bytes(candidate.head_ref.as_str()),
        text_bytes(candidate.head_oid.as_deref().unwrap_or("")),
    ])
}

/// Actual bytes of one `ref_store_core_root_receipts` row excluding the JSON body (counted separately).
fn receipt_row_bytes(scope: &RootsScope, body_bytes: usize, action: &str) -> i64 {
    let body = i64::try_from(body_bytes).unwrap_or(i64::MAX);
    total([
        ROW_OVERHEAD_BYTES,
        UUID_BYTES * 5,
        BIGINT_BYTES,
        TIMESTAMPTZ_BYTES,
        ENUM_TEXT_BYTES * 2,
        DIGEST_BYTES * 2,
        text_bytes(scope.purpose().as_str()),
        i64::try_from(action.len()).unwrap_or(i64::MAX),
        body,
    ])
}

/// Bounded admission resource named by a quota refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootQuotaResource {
    Roots,
    RootOidRefs,
    PackBindings,
    Receipts,
    LogicalBytes,
}

impl RootQuotaResource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Roots => "roots",
            Self::RootOidRefs => "root_oid_refs",
            Self::PackBindings => "pack_bindings",
            Self::Receipts => "receipts",
            Self::LogicalBytes => "logical_bytes",
        }
    }
}

/// One candidate charge: exactly the rows this mutation is about to insert.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RootCharge {
    pub roots: i64,
    pub root_oid_refs: i64,
    pub pack_bindings: i64,
    pub receipts: i64,
    pub logical_bytes: i64,
}

impl RootCharge {
    /// Charge for one successful `register`: head + capture header + every captured ref row + every selector
    /// OID row + every pack binding + one receipt, each measured from the actual values being written.
    pub fn register(candidate: &RootCandidate, receipt_body_bytes: usize) -> Self {
        let scope = candidate.scope();
        let oid_count = i64::try_from(candidate.root_oids().len()).unwrap_or(i64::MAX);
        let refs = sum_by(candidate.captured_refs(), ref_row_bytes);
        let oids = sum_by(candidate.root_oids(), |oid| oid_row_bytes(oid));
        let packs = sum_by(candidate.packs(), pack_row_bytes);
        let bytes = total([
            head_row_bytes(scope, &candidate.register_digest().as_hex()),
            capture_row_bytes(candidate),
            refs,
            oids,
            packs,
            receipt_row_bytes(scope, receipt_body_bytes, "register"),
        ]);
        Self {
            roots: 1,
            root_oid_refs: candidate.ref_count().saturating_add(oid_count),
            pack_bindings: candidate.pack_count(),
            receipts: 1,
            logical_bytes: bytes,
        }
    }

    /// Charge for one `release`: a durable tombstone (may be release-before-register), possibly a released
    /// head row, and one bounded receipt. Captures and pack bindings are never released or refunded.
    ///
    /// A release-before-register inserts a terminal head row, so it consumes one root slot exactly like a
    /// register: otherwise released-at-generation-2 root ids could bypass `REPO_MAX_ROOTS`.
    pub fn release(
        scope: &RootsScope,
        expected_register_digest: &RequestDigest,
        reason: &str,
        receipt_body_bytes: usize,
        head_inserted: bool,
        tombstone_inserted: bool,
    ) -> Self {
        let mut bytes = receipt_row_bytes(scope, receipt_body_bytes, "release");
        if head_inserted {
            bytes = bytes.saturating_add(head_row_bytes(scope, &expected_register_digest.as_hex()));
        }
        if tombstone_inserted {
            bytes = bytes.saturating_add(tombstone_row_bytes(scope, reason));
        }
        Self {
            roots: if head_inserted { 1 } else { 0 },
            root_oid_refs: 0,
            pack_bindings: 0,
            receipts: 1,
            logical_bytes: bytes,
        }
    }

    /// Repository/tenant ceiling pair for one resource.
    pub fn bounds(resource: RootQuotaResource) -> (i64, i64) {
        match resource {
            RootQuotaResource::Roots => (REPO_MAX_ROOTS, TENANT_MAX_ROOTS),
            RootQuotaResource::RootOidRefs => (REPO_MAX_ROOT_OID_REFS, TENANT_MAX_ROOT_OID_REFS),
            RootQuotaResource::PackBindings => (REPO_MAX_PACK_BINDINGS, TENANT_MAX_PACK_BINDINGS),
            RootQuotaResource::Receipts => (REPO_MAX_RECEIPTS, TENANT_MAX_RECEIPTS),
            RootQuotaResource::LogicalBytes => (REPO_MAX_LOGICAL_BYTES, TENANT_MAX_LOGICAL_BYTES),
        }
    }
}
