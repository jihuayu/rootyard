//! Fixed bounds, canonical digests and admission math for the bounded TRANSIENT
//! serving read pin (migration 146).
//!
//! This module performs no IO and holds no state. Everything here is either a
//! named bound, a canonical SHA-256 digest over the complete captured identity,
//! or the conservative retained-byte computation that is charged *before* the
//! first row of a fresh serving read is written.
//!
//! # Two disjoint pin families
//!
//! The durable A5a/A5b family (`ref_store_core_snapshots`/`ref_store_core_pins`
//! plus the permanent history/receipt ledger, migrations 140/143) is retained,
//! immutable and bounded at 64 snapshots/pins per repository. It is untouched by
//! this module and keeps its exact contract.
//!
//! The serving read family defined here is **transient**: a row protects one
//! bounded read for at most [`MAX_SERVING_READ_LEASE_SECONDS`], it is deleted on
//! release and reclaimed after expiry, and its counters are recomputed from the
//! actual rows. Nothing in this family can refund, mutate or delete a durable
//! snapshot/pin/receipt/history/root row, and no durable counter is touched.
//!
//! # Why a serving read is bounded
//!
//! * `active_count` and `logical_bytes` are capped per repository (64 leases,
//!   8 MiB) and per tenant (256 leases, 32 MiB);
//! * the per-read work is capped by the existing snapshot bounds: at most 4096
//!   refs and 1..=16 complete registered packs (two artifacts each);
//! * expiry is bounded by the lease (max 300 seconds), and expired/released rows
//!   are deleted, so an unacknowledged `COMMIT` can leak rows only until that
//!   lease elapses and only within the row/byte caps.
use super::super::pack_commit::RegisteredPack;
use super::super::snapshot_contract::{MAX_SNAPSHOT_PACKS, MAX_SNAPSHOT_REFS, MetadataSnapshotScope};
use crate::ref_store::contract::{MetadataQuotaResource, MetadataQuotaScope, RefStoreError, RequestDigest};
use uuid::Uuid;

/// Hard maximum lease of one transient serving read pin (five minutes).
///
/// A serving read is a request-scoped view: the materializer performs all
/// Blob/native work inside this window. The bound is deliberately much shorter
/// than the one-hour durable metadata pin (`MAX_PIN_LEASE_SECONDS`) because
/// these rows are created on every GET.
pub const MAX_SERVING_READ_LEASE_SECONDS: i64 = 300;
/// Hard minimum lease; zero/negative leases are refused before any SQL.
pub const MIN_SERVING_READ_LEASE_SECONDS: i64 = 1;

/// Bounded active transient leases per repository.
pub const REPO_MAX_ACTIVE_SERVING_READS: i64 = 64;
/// Bounded active transient leases per tenant (four full repositories).
pub const TENANT_MAX_ACTIVE_SERVING_READS: i64 = REPO_MAX_ACTIVE_SERVING_READS * 4;
/// Bounded total retained transient row bytes per repository (8 MiB).
pub const REPO_MAX_SERVING_READ_LOGICAL_BYTES: i64 = 8 * 1024 * 1024;
/// Bounded total retained transient row bytes per tenant (32 MiB).
pub const TENANT_MAX_SERVING_READ_LOGICAL_BYTES: i64 = REPO_MAX_SERVING_READ_LOGICAL_BYTES * 4;

/// Hard bound on how many expired/released rows one capture may reclaim.
///
/// Reclaim runs under the tenant + repository usage locks and is therefore
/// serialized, bounded work: a large backlog is drained in bounded batches by
/// later captures instead of one unbounded `DELETE`.
pub const MAX_EXPIRED_SERVING_READ_RECLAIM: i64 = 64;

/// Canonical domain of the digest stored on one transient serving read row.
///
/// It binds the complete captured identity plus the transient pin identity and
/// the live Blob backend digest, so a serving read digest can never be confused
/// with a durable A5a snapshot digest value.
pub const SERVING_CAPTURE_DIGEST_DOMAIN: &str = "core-serving-read-capture-v1";
/// Canonical domain of a checked *empty* repository capture (no pin, no packs).
pub const SERVING_EMPTY_CAPTURE_DIGEST_DOMAIN: &str = "core-serving-read-empty-v1";

/// Conservative retained bytes of one transient serving read header row
/// (four UUIDs, the scope realm, the backend digest, gate proof, HEAD, the
/// refs/membership/snapshot digests, counters and a tuple allowance).
pub const SERVING_READ_HEADER_BYTES: i64 = 768;
/// Conservative retained bytes of one captured ref row besides its name/oid.
pub const SERVING_READ_REF_OVERHEAD_BYTES: i64 = 96;
/// Conservative retained bytes of one captured pack descriptor row besides its
/// artifact-set digest (three UUIDs, a digest, the joined revision, padding).
pub const SERVING_READ_PACK_OVERHEAD_BYTES: i64 = 192;
/// Conservative retained bytes of one captured artifact row (five UUIDs, role,
/// slot, locator fields, provider, backend identity and both verified digests).
pub const SERVING_READ_ARTIFACT_OVERHEAD_BYTES: i64 = 640;

/// One locked transient usage observation (repository or tenant scope).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ServingReadUsage {
    /// Leases that are still live (`expires_at > clock_timestamp()`).
    pub active: i64,
    /// Conservative retained bytes of every row in the scope, including rows
    /// that expired but were not reclaimed yet (never under-counted).
    pub logical_bytes: i64,
}

impl ServingReadUsage {
    pub(crate) fn new(active: i64, logical_bytes: i64) -> Self {
        Self { active: active.max(0), logical_bytes: logical_bytes.max(0) }
    }
}

/// Validate one caller-requested lease and return it as the stored `bigint`.
pub(crate) fn validate_lease(lease_seconds: u32) -> Result<i64, RefStoreError> {
    let lease = i64::from(lease_seconds);
    if !(MIN_SERVING_READ_LEASE_SECONDS..=MAX_SERVING_READ_LEASE_SECONDS).contains(&lease) {
        return Err(RefStoreError::InvalidIdentity(format!(
            "serving read lease must be {MIN_SERVING_READ_LEASE_SECONDS}..={MAX_SERVING_READ_LEASE_SECONDS} seconds"
        )));
    }
    Ok(lease)
}

/// Conservative retained bytes of one captured serving read.
///
/// It never under-counts the physical rows: the header, every captured ref row
/// (actual name/oid bytes plus a fixed overhead), every pack descriptor and both
/// artifact rows of every pack.
pub(crate) fn serving_read_logical_bytes(
    head_ref: &str,
    head_oid: Option<&str>,
    refs: &[(String, String)],
    packs: &[RegisteredPack],
) -> i64 {
    let refs_bytes = refs
        .iter()
        .map(|(name, oid)| name.len() as i64 + oid.len() as i64 + SERVING_READ_REF_OVERHEAD_BYTES)
        .sum::<i64>();
    let packs_bytes = packs
        .iter()
        .map(|pack| {
            SERVING_READ_PACK_OVERHEAD_BYTES + pack.artifacts().len() as i64 * SERVING_READ_ARTIFACT_OVERHEAD_BYTES
        })
        .sum::<i64>();
    SERVING_READ_HEADER_BYTES
        .saturating_add(head_ref.len() as i64)
        .saturating_add(head_oid.map_or(0, |oid| oid.len() as i64))
        .saturating_add(refs_bytes)
        .saturating_add(packs_bytes)
}

/// Per-read structural bounds. The snapshot contract already bounds refs and
/// packs; this is the serving-read projection of the same fixed limits.
pub(crate) fn check_read_shape(ref_count: usize, pack_count: usize) -> Result<(), RefStoreError> {
    if ref_count > MAX_SNAPSHOT_REFS {
        return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count, max_refs: MAX_SNAPSHOT_REFS });
    }
    if pack_count == 0 || pack_count > MAX_SNAPSHOT_PACKS {
        return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count: pack_count, max_refs: MAX_SNAPSHOT_PACKS });
    }
    Ok(())
}

/// Explicit admission backpressure against the locked transient counters.
///
/// `new_bytes` is the conservative retained size of the read that is about to be
/// inserted. Nothing is evicted, refunded or reset to make room; a caller that
/// is over a bound gets a typed `MetadataQuotaExceeded` and no row is written.
pub(crate) fn check_admission(
    repository: ServingReadUsage,
    tenant: ServingReadUsage,
    new_bytes: i64,
) -> Result<(), RefStoreError> {
    let refuse = |scope: MetadataQuotaScope, resource: MetadataQuotaResource| {
        Err(RefStoreError::MetadataQuotaExceeded { scope, resource })
    };
    if repository.active.saturating_add(1) > REPO_MAX_ACTIVE_SERVING_READS {
        return refuse(MetadataQuotaScope::Repository, MetadataQuotaResource::Snapshots);
    }
    if repository.logical_bytes.saturating_add(new_bytes) > REPO_MAX_SERVING_READ_LOGICAL_BYTES {
        return refuse(MetadataQuotaScope::Repository, MetadataQuotaResource::LogicalBytes);
    }
    if tenant.active.saturating_add(1) > TENANT_MAX_ACTIVE_SERVING_READS {
        return refuse(MetadataQuotaScope::Tenant, MetadataQuotaResource::Snapshots);
    }
    if tenant.logical_bytes.saturating_add(new_bytes) > TENANT_MAX_SERVING_READ_LOGICAL_BYTES {
        return refuse(MetadataQuotaScope::Tenant, MetadataQuotaResource::LogicalBytes);
    }
    Ok(())
}

/// Canonical digest of one complete transient serving read capture.
///
/// It binds the trusted scope, both minted identities, the exact captured gate
/// revision *and* digest, HEAD, the ref count/A5a-domain refs digest, the A5a
/// membership digest and pack count, and the digest of the Blob backend the
/// capturing engine had open. The pin generation is captured too, so a
/// re-created row can never present the same digest.
#[allow(clippy::too_many_arguments)]
pub(crate) fn serving_capture_digest(
    scope: &MetadataSnapshotScope,
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    backend_identity_hex: &str,
    gate_revision: i64,
    gate_digest_hex: &str,
    head_ref: &str,
    head_oid: Option<&str>,
    ref_count: i64,
    refs_digest_hex: &str,
    pack_count: i64,
    membership_digest_hex: &str,
) -> RequestDigest {
    let oid_presence: &[u8] = if head_oid.is_some() { b"head-oid-present" } else { b"head-oid-absent" };
    RequestDigest::of(
        SERVING_CAPTURE_DIGEST_DOMAIN,
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
            pin_id.as_bytes(),
            &pin_generation.to_be_bytes(),
            backend_identity_hex.as_bytes(),
            &gate_revision.to_be_bytes(),
            gate_digest_hex.as_bytes(),
            head_ref.as_bytes(),
            oid_presence,
            head_oid.unwrap_or("").as_bytes(),
            &ref_count.to_be_bytes(),
            refs_digest_hex.as_bytes(),
            &pack_count.to_be_bytes(),
            membership_digest_hex.as_bytes(),
        ],
    )
}

/// Canonical digest of one checked *empty* repository capture.
///
/// An empty repository has no packs, so it has no byte protection to pin. Its
/// capture digest still binds the full scope, the captured gate proof, HEAD and
/// the live Blob backend digest under a dedicated domain, so an empty view can
/// never be confused with a registered-pack capture (or with a durable A5a
/// snapshot digest).
pub(crate) fn serving_empty_capture_digest(
    scope: &MetadataSnapshotScope,
    backend_identity_hex: &str,
    gate_revision: i64,
    gate_digest_hex: &str,
    head_ref: &str,
) -> RequestDigest {
    RequestDigest::of(
        SERVING_EMPTY_CAPTURE_DIGEST_DOMAIN,
        &[
            scope.repository_id().as_bytes(),
            scope.tenant_id().as_bytes(),
            scope.owner_id().as_bytes(),
            scope.purpose().as_str().as_bytes(),
            scope.object_format().as_str().as_bytes(),
            scope.history_incarnation().as_bytes(),
            &scope.authority_epoch().to_be_bytes(),
            &scope.group_epoch().to_be_bytes(),
            backend_identity_hex.as_bytes(),
            &gate_revision.to_be_bytes(),
            gate_digest_hex.as_bytes(),
            head_ref.as_bytes(),
            b"no-refs",
            b"no-packs",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::MetadataPinPurpose;
    use crate::ref_store::core::GitObjectFormat;

    fn scope() -> MetadataSnapshotScope {
        MetadataSnapshotScope::new(
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            MetadataPinPurpose::Verification,
            GitObjectFormat::Sha1,
            Uuid::from_bytes([3; 16]),
            1,
            1,
        )
        .unwrap()
    }

    #[test]
    fn leases_are_strictly_bounded() {
        assert!(validate_lease(0).is_err());
        assert!(validate_lease(1).is_ok());
        assert!(validate_lease(MAX_SERVING_READ_LEASE_SECONDS as u32).is_ok());
        assert!(validate_lease(MAX_SERVING_READ_LEASE_SECONDS as u32 + 1).is_err());
    }

    #[test]
    fn active_and_byte_bounds_refuse_without_eviction() {
        let ok_repo = ServingReadUsage::new(REPO_MAX_ACTIVE_SERVING_READS - 1, 0);
        let ok_tenant = ServingReadUsage::new(TENANT_MAX_ACTIVE_SERVING_READS - 1, 0);
        assert!(check_admission(ok_repo, ok_tenant, 1024).is_ok());
        let full_repo = ServingReadUsage::new(REPO_MAX_ACTIVE_SERVING_READS, 0);
        assert_eq!(
            check_admission(full_repo, ok_tenant, 1024),
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Repository,
                resource: MetadataQuotaResource::Snapshots,
            })
        );
        let full_tenant = ServingReadUsage::new(TENANT_MAX_ACTIVE_SERVING_READS, 0);
        assert_eq!(
            check_admission(ok_repo, full_tenant, 1024),
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Tenant,
                resource: MetadataQuotaResource::Snapshots,
            })
        );
        let wide = ServingReadUsage::new(0, REPO_MAX_SERVING_READ_LOGICAL_BYTES);
        assert_eq!(
            check_admission(wide, ServingReadUsage::default(), 1),
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Repository,
                resource: MetadataQuotaResource::LogicalBytes,
            })
        );
        let wide_tenant = ServingReadUsage::new(0, TENANT_MAX_SERVING_READ_LOGICAL_BYTES);
        assert_eq!(
            check_admission(ServingReadUsage::default(), wide_tenant, 1),
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Tenant,
                resource: MetadataQuotaResource::LogicalBytes,
            })
        );
    }

    #[test]
    fn read_shape_refuses_an_empty_or_oversize_pack_set() {
        assert!(check_read_shape(0, 1).is_ok());
        assert!(check_read_shape(MAX_SNAPSHOT_REFS, MAX_SNAPSHOT_PACKS).is_ok());
        assert!(check_read_shape(0, 0).is_err());
        assert!(check_read_shape(0, MAX_SNAPSHOT_PACKS + 1).is_err());
        assert!(check_read_shape(MAX_SNAPSHOT_REFS + 1, 1).is_err());
    }

    #[test]
    fn digests_bind_pin_backend_and_domain() {
        let scope = scope();
        let one = serving_capture_digest(
            &scope,
            Uuid::from_bytes([4; 16]),
            Uuid::from_bytes([5; 16]),
            1,
            &"a".repeat(64),
            3,
            &"b".repeat(64),
            "refs/heads/main",
            None,
            0,
            &"c".repeat(64),
            1,
            &"d".repeat(64),
        );
        let same = serving_capture_digest(
            &scope,
            Uuid::from_bytes([4; 16]),
            Uuid::from_bytes([5; 16]),
            1,
            &"a".repeat(64),
            3,
            &"b".repeat(64),
            "refs/heads/main",
            None,
            0,
            &"c".repeat(64),
            1,
            &"d".repeat(64),
        );
        assert_eq!(one, same);
        // A different pin identity, generation, backend or gate revision changes
        // the captured digest.
        assert_ne!(
            one,
            serving_capture_digest(
                &scope,
                Uuid::from_bytes([4; 16]),
                Uuid::from_bytes([6; 16]),
                1,
                &"a".repeat(64),
                3,
                &"b".repeat(64),
                "refs/heads/main",
                None,
                0,
                &"c".repeat(64),
                1,
                &"d".repeat(64),
            )
        );
        assert_ne!(
            one,
            serving_capture_digest(
                &scope,
                Uuid::from_bytes([4; 16]),
                Uuid::from_bytes([5; 16]),
                2,
                &"a".repeat(64),
                3,
                &"b".repeat(64),
                "refs/heads/main",
                None,
                0,
                &"c".repeat(64),
                1,
                &"d".repeat(64),
            )
        );
        assert_ne!(
            one,
            serving_capture_digest(
                &scope,
                Uuid::from_bytes([4; 16]),
                Uuid::from_bytes([5; 16]),
                1,
                &"e".repeat(64),
                3,
                &"b".repeat(64),
                "refs/heads/main",
                None,
                0,
                &"c".repeat(64),
                1,
                &"d".repeat(64),
            )
        );
        let empty = serving_empty_capture_digest(&scope, &"a".repeat(64), 1, &"b".repeat(64), "refs/heads/main");
        assert_ne!(empty.as_hex(), one.as_hex());
        let empty_same = serving_empty_capture_digest(&scope, &"a".repeat(64), 1, &"b".repeat(64), "refs/heads/main");
        assert_eq!(empty, empty_same);
    }

    #[test]
    fn logical_bytes_cover_header_refs_and_full_pack_identity() {
        let refs = vec![("refs/heads/main".to_string(), "a".repeat(40))];
        let empty = serving_read_logical_bytes("refs/heads/main", None, &[], &[]);
        let with_ref = serving_read_logical_bytes("refs/heads/main", None, &refs, &[]);
        assert!(with_ref > empty);
        assert!(empty >= SERVING_READ_HEADER_BYTES);
    }
}
