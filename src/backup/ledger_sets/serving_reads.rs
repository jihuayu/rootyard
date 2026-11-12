//! Transient serving read capture headers of the source ledger (#169).
//!
//! `DECLARED_SETS` already enumerates every `serving_read_packs` descriptor, so
//! each descriptor is judged by [`super::check_declared`] like any other declared
//! set. What that cannot see is the *header* those descriptors hang from: its
//! pack count, membership digest, realm, backend identity and capture digest.
//! This module decodes the headers and the rows they own (never through an inner
//! join, so a header without packs and a pack without a header both survive) and
//! keeps their violations in [`SourceSets::serving_reads`].
//!
//! The canonical values are not recomputed here. Every header is re-proven by
//! [`crate::ref_store::core::pack_snapshot`]'s crate-private serving-read
//! re-derivation (`check_membership`, `check_refs_and_membership`,
//! `check_canonical_serving`): the same A5 membership algorithm, the same
//! `serving_capture_digest` domain and the same refs/HEAD/logical-byte checks the
//! serving-read T2 recheck uses. Only the cross-row agreement a T2 does not need
//! (actual repository/gate realm, serving binding/backend identity, publication
//! realm) is decided in [`ServingReads::cross_violations`].
//!
//! Identities: the header `tenant_id` is the repository/gate tenant; the header
//! `owner_id` is the serving-read requester, a distinct identity that is neither
//! the A3 pack producer nor the tenant, so only the capture digest binds it.
use super::{DeclaredPair, Realm, key_of};
use crate::backup::ledger_canonical::canonical;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::pack_commit::PackCommitError;
use crate::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, RegisteredArtifact, RegisteredPack,
};
use crate::ref_store::core::pack_snapshot::{
    self as pack_snapshot, ServingReadRow, check_canonical_serving, check_membership, check_refs_and_membership,
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// The actual lane of a repository that carries a serving read header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::backup) struct ServingReadLane {
    /// `repositories.storage_backend`.
    pub storage_backend: Option<String>,
    /// `repositories.owner_id`: the actual repository tenant.
    pub repository_owner: Option<Uuid>,
    /// The serving binding `(owner_id, object_format, history_incarnation,
    /// authority_epoch, group_epoch, backend_identity, state)`.
    pub binding: Option<(Uuid, String, Uuid, i64, i64, String, String)>,
    /// The core gate `(tenant_id, object_format, history_incarnation,
    /// authority_epoch, group_epoch)`.
    pub gate: Option<(Uuid, String, Uuid, i64, i64)>,
}

/// One `ref_store_core_serving_read_packs` descriptor row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::backup) struct ServingReadDescriptor {
    pub pack_id: Uuid,
    pub registration_id: Uuid,
    pub artifact_set_digest: String,
    pub joined_revision: i64,
}

/// One `ref_store_core_serving_read_artifacts` row as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::backup) struct ServingReadArtifact {
    pub pack_id: Uuid,
    pub role: String,
    pub slot: i32,
    pub hold_id: Uuid,
    pub locator_tenant_id: Uuid,
    pub locator_authority_id: Uuid,
    pub locator_authority_generation: i64,
    pub locator_attempt_id: Uuid,
    pub locator_namespace: String,
    pub locator_sha256: String,
    pub locator_length: i64,
    pub provider: String,
    pub backend_identity: String,
    pub verified_sha256: String,
    pub verified_length: i64,
}

/// One stored header with the rows it owns and the lane of its repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::backup) struct ServingReadHeader {
    pub row: ServingReadRow,
    pub lane: ServingReadLane,
    pub refs: Vec<(String, String)>,
    pub packs: Vec<ServingReadDescriptor>,
    pub artifacts: Vec<ServingReadArtifact>,
}

/// Everything decoded from the serving read tables on the validator's one
/// snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::backup) struct ServingReadScan {
    pub headers: Vec<ServingReadHeader>,
    /// The bare `(repository_id, pin_id)` of every serving read that owns a row.
    pub found: Vec<(Uuid, Uuid)>,
    pub lanes: Vec<(Uuid, ServingReadLane)>,
    /// Orphans the SQL decode already named (a descriptor with no header).
    pub violations: Vec<String>,
    /// The captured refs of every pin that owns a header.
    pub refs: BTreeMap<Uuid, Vec<(String, String)>>,
    /// The stored pack descriptors of every pin that owns a header.
    pub packs: BTreeMap<Uuid, Vec<ServingReadDescriptor>>,
    /// The stored artifacts of every pin that owns a header.
    pub artifacts: BTreeMap<Uuid, Vec<ServingReadArtifact>>,
}

/// The decoded serving reads of the source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::backup) struct ServingReads {
    pub headers: Vec<ServingReadHeader>,
    /// Bare headers found from an orphaned child row.
    pub found: Vec<(Uuid, Uuid)>,
    /// Every decoded lane (including repositories with no header).
    pub lanes: BTreeMap<Uuid, ServingReadLane>,
    /// Deterministic violations.
    pub violations: Vec<String>,
}

/// A parsed lowercase sha256 of a stored digest column.
fn digest(value: &str) -> Result<RequestDigest, RefStoreError> {
    value.parse().map_err(|_| RefStoreError::Database("stored serving read digest is not sha256 hex".into()))
}

/// The binding state column is the stored lifecycle text; it is compared with
/// the one ready literal the serving authority admits (`serving_scope`).
const READY: &str = "ready";

/// Stable `repository_id:pin_id` tag of one header.
fn at(row: &ServingReadRow) -> String {
    format!("{}:{}", row.repository_id, row.pin_id)
}

impl ServingReads {
    /// Assemble the decoded headers and receipts of the header-side read.
    pub(in crate::backup) fn from_scan(scan: ServingReadScan) -> Self {
        let ServingReadScan { headers, found, lanes, violations, refs, packs, artifacts } = scan;
        let mut violations = violations;
        let mut headers = headers;
        let lanes: BTreeMap<Uuid, ServingReadLane> = lanes.into_iter().collect();
        for header in &mut headers {
            let pin = header.row.pin_id;
            // A repository with no decoded lane still gets the default lane, so
            // the missing binding/gate fails closed in the realm/backend checks.
            header.lane = lanes.get(&header.row.repository_id).cloned().unwrap_or_default();
            header.refs = refs.get(&pin).cloned().unwrap_or_default();
            header.packs = packs.get(&pin).cloned().unwrap_or_default();
            header.artifacts = artifacts.get(&pin).cloned().unwrap_or_default();
            // A header that owns no pack descriptor is a capture the core can
            // never have written; refused explicitly, never through a join.
            if header.packs.is_empty() {
                violations.push(format!("serving_read_pack_missing:{}:{}", header.row.repository_id, pin));
            }
        }
        let seen = headers.iter().map(|header| header.row.pin_id).collect::<BTreeSet<_>>();
        for pin in refs.keys().chain(artifacts.keys()).filter(|pin| !seen.contains(pin)) {
            violations.push(format!("serving_read_orphan:{pin}"));
        }
        headers.sort_by_key(|header| (header.row.repository_id, header.row.pin_id));
        let mut reads = Self { headers, found, lanes, violations };
        reads.found.sort();
        reads.reconcile();
        reads.violations.extend(reads.header_violations());
        reads
    }

    /// Resolve the bare headers found from orphaned rows: a pin that names a
    /// header is not an orphan, and every bare (repository, pin) pair that this
    /// decode never saw is refused instead of disappearing from the set.
    fn reconcile(&mut self) {
        let seen =
            self.headers.iter().map(|header| (header.row.repository_id, header.row.pin_id)).collect::<BTreeSet<_>>();
        let missing = self.found.iter().copied().filter(|key| !seen.contains(key)).collect::<BTreeSet<_>>();
        for (repository_id, pin_id) in missing {
            self.violations.push(format!("serving_read_orphan:{repository_id}:{pin_id}"));
        }
    }

    /// Every violation each header has on its own rows and its lane.
    pub(in crate::backup) fn header_violations(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for header in &self.headers {
            lines.extend(header_violations(header));
        }
        lines.sort();
        lines.dedup();
        lines
    }

    /// Every stored descriptor of every header, keyed like [`super::key_of`].
    pub(in crate::backup) fn declared_keys(&self) -> BTreeSet<(Uuid, Uuid, Uuid)> {
        self.headers
            .iter()
            .flat_map(|header| {
                header
                    .packs
                    .iter()
                    .map(move |descriptor| (header.row.repository_id, descriptor.pack_id, descriptor.registration_id))
            })
            .collect()
    }

    /// Cross-row agreement with the already validated A4 declarations and the
    /// lane of every repository that carries a serving read row.
    pub(in crate::backup) fn cross_violations(&self, declared: &[DeclaredPair]) -> Vec<String> {
        let sets = declared.iter().map(|pair| (key_of(pair), pair)).collect::<BTreeMap<_, _>>();
        let mut lines = Vec::new();
        for (repository_id, lane) in &self.lanes {
            if !lane_agrees(lane) {
                lines.push(format!("serving_read_realm_mismatch:{repository_id}"));
            }
        }
        for header in &self.headers {
            let row = &header.row;
            let realm = realm_of_row(row);
            let at = at(row);
            // The header realm must be every declared publication realm of the
            // descriptors it carries (the actual repository/gate realm is checked
            // with the header's own lane).
            for descriptor in &header.packs {
                let key = (row.repository_id, descriptor.pack_id, descriptor.registration_id);
                if sets.get(&key).is_some_and(|pair| canonical(pair).is_ok_and(|(_, stored)| stored.realm != realm)) {
                    lines.push(format!("serving_read_realm_mismatch:{at}"));
                }
            }
            let Some(backend) = header.lane.binding.as_ref().map(|binding| binding.5.as_str()) else {
                lines.push(format!("serving_read_backend_mismatch:{at}"));
                continue;
            };
            for artifact in &header.artifacts {
                if artifact.backend_identity != backend {
                    lines.push(format!("serving_read_backend_mismatch:{at}"));
                }
            }
        }
        lines
    }

    /// Every descriptor of every header must still state its declaration, and a
    /// descriptor whose registration is not declared at all is refused on its own
    /// pin. A re-pointed, detached or unresolvable declaration is a violation,
    /// never an orphan of the declaration that silently disappears.
    pub(in crate::backup) fn descriptor_violations(&self, declared: &[DeclaredPair]) -> Vec<String> {
        let sets = declared.iter().map(|pair| (key_of(pair), pair)).collect::<BTreeMap<_, _>>();
        let mut lines = Vec::new();
        for header in &self.headers {
            for descriptor in &header.packs {
                let at = at(&header.row);
                let key = (header.row.repository_id, descriptor.pack_id, descriptor.registration_id);
                match sets.get(&key) {
                    Some(pair) if !descriptor_agrees(pair, descriptor) || !identity_agrees(pair, descriptor) => {
                        lines.push(format!("serving_read_pack_mismatch:{at}:{}", descriptor.pack_id));
                    }
                    Some(_) => {}
                    None => lines.push(format!("serving_read_unregistered_pack:{at}:{}", descriptor.pack_id)),
                }
            }
        }
        lines
    }
}

/// The serving binding and core gate of one repository must agree with each
/// other and with the repository owner and format.
pub(in crate::backup) fn lane_agrees(lane: &ServingReadLane) -> bool {
    let (Some(binding), Some(gate)) = (&lane.binding, &lane.gate) else { return false };
    binding.6 == READY
        && lane.storage_backend.as_deref() == Some("pg_refstore")
        && lane.repository_owner == Some(binding.0)
        && (binding.0, &binding.1, binding.2, binding.3, binding.4) == (gate.0, &gate.1, gate.2, gate.3, gate.4)
}

/// The exact header realm.
fn realm_of_row(row: &ServingReadRow) -> Realm {
    Realm {
        tenant_id: row.tenant_id,
        history_incarnation: row.history_incarnation,
        authority_epoch: row.authority_epoch,
        group_epoch: row.group_epoch,
        object_format: row.object_format.clone(),
    }
}

/// The stored descriptor must be the canonical A4 set of its registration:
/// the canonical pack rebuilt from the already validated A4 rows, its stored
/// artifact-set digest and its joined revision (`gate_revision + 1`).
fn descriptor_agrees(pair: &DeclaredPair, descriptor: &ServingReadDescriptor) -> bool {
    matches!(
        canonical(pair),
        Ok((pack, stored))
            if pack.pack_id() == descriptor.pack_id
                && pack.registration_id() == descriptor.registration_id
                && descriptor.artifact_set_digest == stored.digest.as_hex()
                && descriptor.joined_revision == stored.joined_revision
    )
}

/// Whether the A4 rows still state this descriptor's identity: the publication
/// row, its artifact-set digest and the joined revision every declaring row
/// recorded. Identity only: no canonical rebuild, so a header whose artifacts
/// are damaged cannot hide a descriptor whose pack was re-pointed or detached.
fn identity_agrees(pair: &DeclaredPair, descriptor: &ServingReadDescriptor) -> bool {
    pair.artifacts.iter().all(|artifact| artifact.pack_id == descriptor.pack_id)
        && matches!(
            &pair.publication,
            Some(publication)
                if publication.pack_id == descriptor.pack_id
                    && publication.repository_id == pair.repository_id
                    && publication.digest == descriptor.artifact_set_digest
                    && publication.gate_revision.saturating_add(1) == descriptor.joined_revision
                    && pair.declared_sets.iter().all(|(_, digest, joined)| {
                        *digest == descriptor.artifact_set_digest && *joined == descriptor.joined_revision
                    })
        )
}

/// Every violation of one header on its own rows and its lane.
pub(in crate::backup) fn header_violations(header: &ServingReadHeader) -> Vec<String> {
    let row = &header.row;
    let at = at(row);
    let mut lines = Vec::new();
    if !lane_agrees(&header.lane) {
        lines.push(format!("serving_read_realm_mismatch:{at}"));
    }
    match header.lane.binding.as_ref() {
        Some(binding) if binding.5 == row.backend_identity => {}
        _ => lines.push(format!("serving_read_backend_mismatch:{at}")),
    }
    if header.packs.is_empty() {
        lines.push(format!("serving_read_pack_missing:{at}"));
        return lines;
    }
    match registered(header) {
        Ok(packs) => match check_membership(&packs) {
            Ok(membership) => {
                if let Err(error) = check_canonical_serving(row, &header.refs, &packs, &membership) {
                    lines.push(format!("serving_read_capture_mismatch:{at}:{}", reason(&error)));
                }
            }
            Err(error) => lines.push(format!("serving_read_capture_mismatch:{at}:{}", reason(&error))),
        },
        Err(error) => {
            lines.push(format!("serving_read_artifact_mismatch:{at}:{}", reason(&error)));
            let descriptors = header
                .packs
                .iter()
                .map(|d| (d.pack_id, d.registration_id, d.artifact_set_digest.clone(), d.joined_revision));
            let membership = pack_snapshot::descriptor_membership(descriptors);
            if let Err(error) = check_refs_and_membership(row, &header.refs, &membership) {
                lines.push(format!("serving_read_membership_mismatch:{at}:{}", reason(&error)));
            }
        }
    }
    lines
}

/// Rebuild the complete registered pack set from one header's own descriptors
/// and artifacts, exactly like `serving_read_sql::read_packs`: every
/// artifact-set digest is re-derived from the stored physical identity.
fn registered(header: &ServingReadHeader) -> Result<Vec<RegisteredPack>, RefStoreError> {
    let mut packs = Vec::with_capacity(header.packs.len());
    for descriptor in &header.packs {
        let parsed = digest(&descriptor.artifact_set_digest)?;
        let artifacts = header
            .artifacts
            .iter()
            .filter(|artifact| artifact.pack_id == descriptor.pack_id)
            .map(registered_artifact)
            .collect::<Result<Vec<_>, _>>()?;
        packs.push(
            RegisteredPack::new(
                descriptor.pack_id,
                descriptor.registration_id,
                ArtifactSetDigest::from_digest(parsed),
                artifacts,
                Some(descriptor.joined_revision),
            )
            .map_err(pack_refusal)?,
        );
    }
    Ok(packs)
}

/// One stored artifact row as the issuer's `RegisteredArtifact`.
fn registered_artifact(artifact: &ServingReadArtifact) -> Result<RegisteredArtifact, RefStoreError> {
    let sha = ContentDigest::parse(artifact.locator_sha256.clone()).map_err(pack_refusal)?;
    let length = u64::try_from(artifact.locator_length)
        .map_err(|_| RefStoreError::Database("stored serving read locator length is negative".into()))?;
    let verified = ContentDigest::parse(artifact.verified_sha256.clone()).map_err(pack_refusal)?;
    let verified_length = u64::try_from(artifact.verified_length)
        .map_err(|_| RefStoreError::Database("stored verified length is negative".into()))?;
    RegisteredArtifact::new(
        PackArtifactRole::parse(&artifact.role)
            .map_err(|_| RefStoreError::Database("stored serving read artifact role is invalid".into()))?,
        artifact.slot,
        artifact.hold_id,
        ArtifactLocator::new(
            artifact.locator_tenant_id,
            artifact.locator_authority_id,
            artifact.locator_authority_generation,
            artifact.locator_attempt_id,
            artifact.locator_namespace.clone(),
            sha,
            length,
        )
        .map_err(pack_refusal)?,
        artifact.provider.clone(),
        artifact.backend_identity.clone(),
        verified,
        verified_length,
    )
    .map_err(pack_refusal)
}

/// A stored passage the A4 issuer refuses is an invalid stored row, never a
/// silently accepted default.
fn pack_refusal(error: PackCommitError) -> RefStoreError {
    RefStoreError::Database(format!("stored serving read pack data is invalid: {error}"))
}

/// A stable, database-text-free form of a core refusal reason.
fn reason(error: &RefStoreError) -> String {
    error.to_string().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}
