//! Crate-private re-derivation of one transient serving read capture for the
//! fail-closed source-ledger validator (#169).
//!
//! This is the same algorithm [`super::serving_read::revalidate_serving_capture`]
//! runs (its T2 recheck), with two deliberate differences:
//!
//! * it never locks: the caller already reads on its own exported `REPEATABLE
//!   READ` snapshot, so the checks take no gate/pin lock and never compare the
//!   stored lease with a later database clock;
//! * it never performs Blob or native Git IO and never materializes: it only
//!   re-derives the membership and capture values from rows read on that same
//!   snapshot.
//!
//! The canonical domains are not re-implemented here: [`super::contract`] owns
//! `membership_digest` and [`super::serving_read_sql::check_capture_digest`] owns
//! the capture digest, the refs digest/count, the HEAD agreement and the
//! logical-byte accounting. The header's `owner_id`/`purpose` are stored
//! serving-read requester identity, not authority: the capture digest binds
//! them exactly as the header carries them, while the realm and backend
//! identity are judged against the actual repository/binding by the caller.

use super::super::GitObjectFormat;
use super::super::pack_commit::{MembershipDigest, PackMembershipEntry, RegisteredPack};
use super::super::snapshot_contract::{MAX_SNAPSHOT_REFS, MetadataSnapshotScope};
use super::contract as pack_contract;
use super::serving_read_sql::{self, ServingReadRow};
use crate::ref_store::MetadataPinPurpose;
use crate::ref_store::contract::RefStoreError;
#[cfg(test)]
use crate::ref_store::contract::RequestDigest;
use uuid::Uuid;

/// The complete captured registered pack membership: the canonical
/// `pack_count` and `membership_digest` the capture wrote for these packs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ServingMembership {
    /// The number of descriptors the digest was derived from.
    pub(crate) pack_count: i64,
    pub(crate) membership_digest: String,
}

/// Re-derive the canonical membership digest of `packs` with the core A5
/// algorithm and their exact count.
pub(crate) fn check_membership(packs: &[RegisteredPack]) -> Result<ServingMembership, RefStoreError> {
    let membership_digest = pack_contract::membership_digest(packs)?.as_hex();
    let pack_count = i64::try_from(packs.len()).unwrap_or(i64::MAX);
    Ok(ServingMembership { pack_count, membership_digest })
}

/// The stored descriptors alone, judged with the same canonical membership
/// digest the capture writes. `pack_count` is the stored pack row count, so the
/// count half of the diagnostic stays exact even if a descriptor is unbuildable.
pub(crate) fn descriptor_membership(
    descriptors: impl IntoIterator<Item = (uuid::Uuid, uuid::Uuid, String, i64)>,
) -> ServingMembership {
    let descriptors = descriptors.into_iter().collect::<Vec<_>>();
    let entries = descriptors
        .iter()
        .filter_map(|(pack_id, registration_id, digest, joined)| {
            descriptor_entry(*pack_id, *registration_id, digest, *joined).ok()
        })
        .collect::<Vec<_>>();
    ServingMembership {
        pack_count: i64::try_from(descriptors.len()).unwrap_or(i64::MAX),
        membership_digest: MembershipDigest::of(&entries).as_hex(),
    }
}

/// The core A5 membership identity of one stored descriptor row, exactly as
/// [`super::serving_read_sql::read_packs`] builds it (the stored artifact-set
/// digest parsed into the issuer type, the stored joined revision).
pub(crate) fn descriptor_entry(
    pack_id: Uuid,
    registration_id: Uuid,
    artifact_set_digest: &str,
    joined_revision: i64,
) -> Result<PackMembershipEntry, RefStoreError> {
    let digest = artifact_set_digest
        .parse()
        .map_err(|_| RefStoreError::Database("stored serving read artifact-set digest is not sha256 hex".into()))?;
    PackMembershipEntry::new(
        pack_id,
        registration_id,
        super::super::pack_commit::ArtifactSetDigest::from_digest(digest),
        joined_revision,
    )
    .map_err(|_| RefStoreError::Database("stored serving read membership entry is invalid".into()))
}

/// The exact scope columns of one stored serving read header, decoded with the
/// issuer's own parsers. A header column outside the stored vocabulary is a
/// refusal, never a substituted default.
pub(crate) fn scope_of(row: &ServingReadRow) -> Result<MetadataSnapshotScope, RefStoreError> {
    let format = GitObjectFormat::parse(&row.object_format)?;
    let purpose = MetadataPinPurpose::parse(&row.purpose)?;
    MetadataSnapshotScope::new(
        row.repository_id,
        row.tenant_id,
        row.owner_id,
        purpose,
        format,
        row.history_incarnation,
        row.authority_epoch,
        row.group_epoch,
    )
}

/// The core's own `serving_capture_digest` over one header's stored identity.
///
/// Every field is taken from the stored row exactly as the capture wrote it,
/// under the one canonical domain; no second digest shape is introduced.
#[cfg(test)]
pub(crate) struct ServingCaptureDigest;

#[cfg(test)]
impl ServingCaptureDigest {
    pub(crate) fn of(row: &ServingReadRow) -> Result<String, RefStoreError> {
        let scope = scope_of(row)?;
        Ok(super::serving_read_request::serving_capture_digest(
            &scope,
            row.snapshot_id,
            row.pin_id,
            row.generation,
            &row.backend_identity,
            row.gate_revision,
            &row.gate_digest,
            &row.head_ref,
            row.head_oid.as_deref(),
            row.ref_count,
            &row.refs_digest,
            row.pack_count,
            &row.membership_digest,
        )
        .as_hex())
    }
}

/// The A5a-domain refs digest the serving capture stores for captured refs.
#[cfg(test)]
pub(crate) fn captured_refs_digest(refs: &[(String, String)]) -> RequestDigest {
    super::super::snapshot_contract::refs_digest(refs)
}

/// The logical bytes the serving capture charges for these exact refs and packs.
#[cfg(test)]
pub(crate) fn captured_logical_bytes(
    head_ref: &str,
    head_oid: Option<&str>,
    refs: &[(String, String)],
    packs: &[RegisteredPack],
) -> i64 {
    super::serving_read_request::serving_read_logical_bytes(head_ref, head_oid, refs, packs)
}

/// The orphan diagnostic for a header whose descriptors/artifacts could not be
/// rebuilt into a registered pack set: the count/digest/HEAD half only.
pub(crate) fn check_refs_and_membership(
    row: &ServingReadRow,
    refs: &[(String, String)],
    membership: &ServingMembership,
) -> Result<(), RefStoreError> {
    if refs.len() > MAX_SNAPSHOT_REFS {
        return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count: refs.len(), max_refs: MAX_SNAPSHOT_REFS });
    }
    let head_oid = refs.iter().find(|(name, _)| name == &row.head_ref).map(|(_, oid)| oid.clone());
    if head_oid != row.head_oid {
        return Err(RefStoreError::Database("stored serving read HEAD disagrees with its captured ref rows".into()));
    }
    if membership.pack_count != row.pack_count {
        return Err(RefStoreError::Database(
            "stored serving read pack count disagrees with its captured descriptors".into(),
        ));
    }
    if membership.membership_digest != row.membership_digest {
        return Err(RefStoreError::Database(
            "stored serving read membership digest disagrees with its captured packs".into(),
        ));
    }
    Ok(())
}

/// Re-prove one stored header against its complete captured rows exactly like
/// the serving-read T2 recheck: HEAD, refs digest/count, pack count, canonical
/// membership, capture digest and logical-byte accounting.
///
/// `packs` must have been rebuilt from the header's own descriptors (as
/// [`serving_read_sql::read_packs`] does, re-deriving every artifact-set digest)
/// and `membership` must be [`check_membership`] of that same set.
pub(crate) fn check_canonical_serving(
    row: &ServingReadRow,
    refs: &[(String, String)],
    packs: &[RegisteredPack],
    membership: &ServingMembership,
) -> Result<(), RefStoreError> {
    check_refs_and_membership(row, refs, membership)?;
    serving_read_sql::check_capture_digest(row, &scope_of(row)?, refs, packs, &membership.membership_digest)
}
