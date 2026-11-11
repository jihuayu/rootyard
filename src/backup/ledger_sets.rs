//! Pure (database-free) source-ledger set logic for the paired archive.
//!
//! [`super::ledger_validation`] only reads raw rows; every decision is made here
//! so a corrupted source is refused identically in production and in unit
//! tests. A registration "should be archived" when a `pg_refstore` repository
//! still declares it:
//!
//! * `membership`: the live pack set of the core gate;
//! * `snapshot_packs`: an A5 snapshot pack set;
//! * `root_packs`: a retained root, active **or released**;
//! * `serving_read_packs`: a transient serving read lease.
//!
//! For each declared registration the validator requires the A4 publication,
//! exactly one legal `pack`(slot 0)/`idx`(slot 1) pair bound to that publication's
//! own acquire/consume request, to its durable hold and to its consume receipt,
//! and a recomputed artifact-set digest. Snapshot and retained-root descriptors
//! are then compared item by item with the same canonical A4 set (the semantics
//! of `RegisteredPack::new` over the retained rows), so a retained *subset*, a
//! retained *superset* or a different locator is a refusal instead of a silently
//! smaller archive. A root head always owns exactly one capture; only a
//! release-before-register head matching its tombstone may have none.
//!
//! `owner_id` of a snapshot or root is its producer/requester, never the
//! repository tenant: only the realm fields (`tenant_id`,
//! `history_incarnation`, epochs and object format) bind a declared set to the
//! registration. A producer owner distinct from the repository tenant is valid.
//!
//! The two identities inside one A4 registration are never conflated (see
//! `declared_owner_scope`: the publication binding and each artifact row's
//! request/hold/receipt scope; the typed consume ACK body is judged by
//! [`super::ledger::ack_scope_differs`]):
//!
//! * the **producer** (`owner_id` of the publication) is the A3 artifact-hold
//!   requester: it equals the acquire request's owner, both durable holds'
//!   owners and both consume receipts' owners (typed ACK body included). It may
//!   differ from the repository tenant, and is never required to equal a root
//!   head/capture/tombstone requester;
//! * the **tenant** (`tenant_id` of the publication, locator, holds, storage
//!   tenants and receipts) is the actual repository tenant (`repositories`
//!   owner, the core gate tenant).
use self::declared_owner_scope::declared_binding;
use self::root_lifetime::check_heads;
use self::serving_reads::ServingReads;
use super::ledger_canonical::{canonical, declared_agrees, retained_pair};
use crate::ref_store::core::pack_commit::{MembershipDigest, PackMembershipEntry, packs_digest, refs_digest};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

mod model;
pub(super) use self::model::*;

/// `pack_membership_state` of a complete, pack-verified A5 snapshot.
pub(super) const PACK_VERIFIED: &str = "pack_verified";

impl SourceSets {
    /// Every violation line, sorted and de-duplicated.
    pub(super) fn violations(&self) -> Vec<String> {
        let mut lines = check_declared(&self.declared);
        lines.extend(check_declared_missing(
            &self.snapshots,
            &self.roots,
            &self.serving_reads.declared_keys(),
            &self.registrations(),
        ));
        lines.extend(check_snapshots(&self.snapshots, &self.declared));
        lines.extend(check_roots(&self.roots, &self.declared));
        lines.extend(check_heads(&self.heads, &self.tombstones, &self.roots, &self.declared));
        lines.extend(self.serving_reads.violations.iter().cloned());
        lines.extend(self.serving_reads.cross_violations(&self.declared));
        lines.extend(self.serving_reads.descriptor_violations(&self.declared));
        lines.sort();
        lines.dedup();
        lines
    }

    /// Sorted, unique `(repository_id, pack_id, registration_id)` registrations
    /// that should be archived.
    pub(super) fn registrations(&self) -> BTreeSet<(Uuid, Uuid, Uuid)> {
        self.declared.iter().map(key_of).collect()
    }

    /// Canonical artifact rows of the declared registrations only, tagged with
    /// their stored publication digest and declaring set kinds. A declared
    /// registration without complete artifact rows contributes nothing, so a
    /// missing pair is never papered over by an unrelated registration.
    pub(super) fn select<A: DeclaredArtifact>(&self, artifacts: Vec<A>) -> Vec<A> {
        let declared = self.registrations();
        if declared.is_empty() {
            return artifacts;
        }
        let mut tags = BTreeMap::new();
        for pair in &self.declared {
            let mut sources = pair.declared_by.clone();
            sources.sort();
            sources.dedup();
            tags.insert(pair.registration_id, (pair.publication.as_ref().map(|p| p.digest.clone()), sources));
        }
        artifacts
            .into_iter()
            .filter(|artifact| declared.contains(&artifact.identity()))
            .map(|mut artifact| {
                if let Some((digest, sources)) = tags.get(&artifact.registration()).cloned() {
                    artifact.retain(digest, sources);
                }
                artifact
            })
            .collect()
    }
}

/// The shape of one canonical artifact row that the archive selection tags:
/// its registration and the stored publication digest / declaring set kinds.
/// Implemented by the archive row in `super::ledger`, so this module stays free
/// of the archive's serialisation.
pub(super) trait DeclaredArtifact {
    fn registration(&self) -> Uuid;
    fn identity(&self) -> (Uuid, Uuid, Uuid);
    fn retain(&mut self, digest: Option<String>, sources: Vec<String>);
}

/// Sortable identity of one declared registration.
pub(super) fn key_of(pair: &DeclaredPair) -> (Uuid, Uuid, Uuid) {
    (pair.repository_id, pair.pack_id, pair.registration_id)
}

/// Registration ids of declared snapshot/root packs that have no declared A4
/// set at all, ascending. These rows are invisible to a read restricted to
/// [`SourceSets::declared`], so they are looked up by id instead of dropped.
pub(super) fn undeclared(
    declared: &[DeclaredPair],
    snapshots: &[SnapshotSet],
    roots: &[RootCapture],
    serving_reads: &ServingReads,
) -> Vec<Uuid> {
    let known = declared.iter().map(|pair| pair.registration_id).collect::<BTreeSet<_>>();
    let mut missing = snapshots
        .iter()
        .flat_map(|snapshot| snapshot.packs.iter().map(|(_, registration_id, _, _)| *registration_id))
        .chain(roots.iter().flat_map(|root| root.packs.iter().map(|pack| pack.registration_id)))
        // Every stored serving read descriptor names its registration without a
        // join, so a descriptor whose declaration is invisible is still refused.
        .chain(serving_reads.declared_keys().iter().map(|(_, _, registration_id)| *registration_id))
        .filter(|registration_id| !known.contains(registration_id))
        .collect::<BTreeSet<_>>();
    std::mem::take(&mut missing).into_iter().collect()
}

/// Stable `repository_id:pack_id:registration_id` tag of one declared pair.
fn tag(pair: &DeclaredPair) -> String {
    format!("{}:{}:{}", pair.repository_id, pair.pack_id, pair.registration_id)
}

/// Owner/publication scope lines of one declared registration, produced by the
/// `declared_owner_scope` child and only visible inside `backup`. The child
/// implementation stays `pub(super)` to `ledger_sets`.
pub(super) fn declared_violations(pair: &DeclaredPair) -> Vec<String> {
    declared_owner_scope::declared_violations(pair)
}

/// Legal slot/role pair: exactly slot 0 for the `.pack` and slot 1 for the `.idx`.
pub(super) fn legal(role: &str, slot: i32) -> bool {
    (role == "pack" && slot == 0) || (role == "idx" && slot == 1)
}

/// Per-registration violations: publication, exact legal pair, issuer binding,
/// durable hold, consume receipt and declared digest / joined revision.
pub(super) fn check_declared(declared: &[DeclaredPair]) -> Vec<String> {
    let mut lines = Vec::new();
    for pair in declared {
        let key = tag(pair);
        let Some(publication) = &pair.publication else {
            lines.push(format!("unregistered_publication:{}:{key}", pair.declared_by.join(",")));
            continue;
        };
        // The pair must be the canonical A4 set: `canonical` rebuilds it with
        // `RegisteredPack::new`, which recomputes `ArtifactSetDigest::of` over the
        // rows and refuses a stored publication digest that disagrees. Without
        // this check a pair declared only by membership, and never restated by a
        // snapshot or root, could carry a `declared_sets` digest equal to a wrong
        // publication digest and never be refused.
        if canonical(pair).is_err() {
            lines.push(format!("canonical_pair_mismatch:{key}"));
        }
        // The publication tenant is the actual repository tenant / gate tenant,
        // and its owner is the A3 pack producer. Neither identity is the other.
        if !declared_binding(pair) {
            lines.push(format!("publication_binding_mismatch:{key}"));
        }
        // Pre-computed by the decoder, so the exact row that is selected for
        // the archive can be judged without the SQL decoder in the unit tests.
        lines.extend(pair.scope.iter().cloned());
        match pair.artifacts.len() {
            0 => lines.push(format!("missing_artifacts:{key}")),
            1 => lines.push(format!("incomplete_pair:{key}")),
            n if n > 2 => lines.push(format!("extra_artifacts:{key}")),
            _ => {
                let mut roles = pair.artifacts.iter().map(|a| (a.role.as_str(), a.slot)).collect::<Vec<_>>();
                roles.sort_unstable();
                if roles != [("idx", 1), ("pack", 0)] || !pair.artifacts.iter().all(|a| legal(&a.role, a.slot)) {
                    lines.push(format!("illegal_roles:{key}"));
                }
            }
        }
        for (source, digest, joined) in &pair.declared_sets {
            if digest != &publication.digest {
                lines.push(format!("declared_set_digest_mismatch:{source}:{key}"));
            }
            if *joined != publication.gate_revision.saturating_add(1) {
                lines.push(format!("declared_joined_revision_mismatch:{source}:{key}"));
            }
        }
        for artifact in &pair.artifacts {
            let at = format!("{key}:{}:{}", artifact.role, artifact.slot);
            if artifact.acquire_request_id != publication.acquire_request_id
                || artifact.consume_request_id != publication.consume_request_id
                || !artifact.issuer_operation
            {
                lines.push(format!("foreign_hold_binding:{at}"));
            }
            if !hold_matches(pair.repository_id, artifact) {
                lines.push(format!("hold_mismatch:{at}"));
            }
            if !artifact.receipt {
                lines.push(format!("missing_receipt:{at}"));
            }
        }
    }
    lines
}

/// The durable hold row must equal the artifact row on every physical
/// coordinate. `hold.tenant_id` is the durable hold's own column, compared with
/// the artifact row's locator tenant and with `storage_tenant_id`.
fn hold_matches(repository_id: Uuid, artifact: &PairArtifact) -> bool {
    artifact.hold.as_ref().is_some_and(|hold| {
        hold.request_id == artifact.acquire_request_id
            && hold.slot == artifact.slot
            && hold.repository_id == repository_id
            && hold.tenant_id == artifact.tenant_id
            && hold.storage_tenant_id == artifact.tenant_id
            && hold.provider == artifact.provider
            && hold.backend_identity == artifact.backend_identity
            && hold.sha256 == artifact.sha256
            && hold.length == artifact.length
            && hold.authority_id == artifact.authority_id
            && hold.generation == artifact.generation
            && hold.attempt_id == artifact.attempt_id
            && hold.namespace == artifact.namespace
    })
}

/// A snapshot, root or serving read pack row whose registration is not declared
/// in A4 at all. Serving read headers are passed through their own descriptor
/// keys, so an orphaned descriptor is still an `unregistered_publication`.
pub(super) fn check_declared_missing(
    snapshots: &[SnapshotSet],
    roots: &[RootCapture],
    serving_reads: &BTreeSet<(Uuid, Uuid, Uuid)>,
    declared: &BTreeSet<(Uuid, Uuid, Uuid)>,
) -> Vec<String> {
    let mut lines = Vec::new();
    let missing = |lines: &mut Vec<String>, source: &str, repo: Uuid, pack: Uuid, registration: Uuid| {
        if !declared.contains(&(repo, pack, registration)) {
            lines.push(format!("unregistered_publication:{source}:{repo}:{pack}:{registration}"));
        }
    };
    for snapshot in snapshots {
        for (pack_id, registration_id, _, _) in &snapshot.packs {
            missing(&mut lines, "snapshot_packs", snapshot.repository_id, *pack_id, *registration_id);
        }
    }
    for root in roots {
        for pack in &root.packs {
            missing(&mut lines, "root_packs", root.repository_id, pack.pack_id, pack.registration_id);
        }
    }
    for (repository_id, pack_id, registration_id) in serving_reads {
        missing(&mut lines, "serving_read_packs", *repository_id, *pack_id, *registration_id);
    }
    lines
}

/// Every pack-verified A5 snapshot must still describe the canonical A4 sets of
/// its registrations; its membership digest is recomputed from the rows.
pub(super) fn check_snapshots(snapshots: &[SnapshotSet], declared: &[DeclaredPair]) -> Vec<String> {
    let sets: BTreeMap<Uuid, &DeclaredPair> = declared.iter().map(|pair| (pair.registration_id, pair)).collect();
    let mut lines = Vec::new();
    for snapshot in snapshots {
        let at = format!("{}:{}", snapshot.repository_id, snapshot.snapshot_id);
        let mut members = Vec::new();
        for (pack_id, registration_id, digest, joined_revision) in &snapshot.packs {
            let Some(pair) = sets.get(registration_id) else { continue };
            let checked = canonical(pair).and_then(|(pack, canonical)| {
                if *pack_id != pack.pack_id() {
                    return Err("the declared pack id differs from its registration");
                }
                declared_agrees(&canonical, &snapshot.realm, digest, *joined_revision)?;
                PackMembershipEntry::new(*pack_id, *registration_id, canonical.digest, *joined_revision)
                    .map_err(|_| "invalid membership entry")
            });
            match checked {
                Ok(entry) => members.push(entry),
                Err(reason) => lines.push(format!("snapshot_set_mismatch:{at}:{reason}")),
            }
        }
        let count = i32::try_from(snapshot.packs.len()).unwrap_or(i32::MAX);
        if snapshot.pack_mode != PACK_VERIFIED
            || snapshot.pack_count != count
            || members.is_empty()
            || members.len() != snapshot.packs.len()
            || MembershipDigest::of(&members).as_hex() != snapshot.membership_digest
        {
            lines.push(format!("snapshot_membership_mismatch:{at}"));
        }
    }
    lines
}

/// Every retained root (active or released) must still retain the canonical A4
/// set of its registrations, its complete refs and its exact selector.
///
/// The selector, native binding and register digests are not re-implemented
/// here: `proof` is the verdict of the core's own capture validator, so a
/// tampered selector order/format, a whole-snapshot selector that is not the
/// captured refs plus HEAD, or a binding digest outside the core domain is
/// already refused there.
pub(super) fn check_roots(roots: &[RootCapture], declared: &[DeclaredPair]) -> Vec<String> {
    let sets: BTreeMap<Uuid, &DeclaredPair> = declared.iter().map(|pair| (pair.registration_id, pair)).collect();
    let mut lines = Vec::new();
    for root in roots {
        let at = format!("{}:{}", root.repository_id, root.root_id);
        let mut rebuilt = Vec::new();
        for pack in &root.packs {
            let Some(pair) = sets.get(&pack.registration_id) else { continue };
            match retained_pair(root, pack, pair) {
                Ok(pack) => rebuilt.push(pack),
                Err(reason) => lines.push(format!("root_set_mismatch:{at}:{reason}")),
            }
        }
        let Some(proof) = &root.proof else {
            lines.push(format!("root_capture_invalid:{at}"));
            continue;
        };
        // A root prepares its native set from the source snapshot refs plus the
        // resolved selector OIDs, so only the captured refs are used to
        // recompute the stored `refs_digest`.
        let refs = super::ledger::captured_refs(&root.realm.object_format, root.refs.clone());
        let count = |value: usize| i32::try_from(value).unwrap_or(i32::MAX);
        let refs_ok = match &refs {
            Some(refs) => count(refs.len()) == root.ref_count && refs_digest(refs).as_hex() == root.refs_digest,
            None => false,
        };
        if !refs_ok {
            lines.push(format!("root_refs_mismatch:{at}"));
        }
        if !verified_selector(root, proof) {
            lines.push(format!("root_selector_mismatch:{at}"));
        }
        rebuilt.sort_by_key(|pack| pack.pack_id());
        if rebuilt.is_empty()
            || count(rebuilt.len()) != root.pack_count
            || packs_digest(&rebuilt).as_hex() != root.pack_set_digest
        {
            lines.push(format!("root_pack_set_mismatch:{at}"));
        }
    }
    lines
}

/// The stored capture columns must be exactly the ones the core re-derived.
fn verified_selector(root: &RootCapture, proof: &RootProof) -> bool {
    let mut stored = root.oids.clone();
    stored.sort_by_key(|(ordinal, _)| *ordinal);
    let ordinals = stored.iter().enumerate().all(|(index, (ordinal, _))| usize::try_from(*ordinal) == Ok(index));
    ordinals
        && stored.iter().map(|(_, oid)| oid.clone()).eq(proof.oids.iter().cloned())
        && root.tenant_id == proof.tenant_id
        && root.owner_id == proof.owner_id
        && root.purpose == proof.purpose
        && root.business_intent_digest == proof.business_intent_digest
        && root.register_digest == proof.register_digest
        && root.selector_kind == proof.selector_kind
        && root.head_ref == proof.head_ref
        && root.head_oid == proof.head_oid
        && root.refs_digest == proof.refs_digest
        && root.pack_set_digest == proof.pack_set_digest
        && root.native_binding_digest == proof.native_binding_digest
}

/// The restored side must carry exactly the registrations the archive declares.
pub(super) fn require_archive_registrations<A: DeclaredArtifact>(archived: &[A], restored: &[A]) -> anyhow::Result<()> {
    let set = |artifacts: &[A]| artifacts.iter().map(|a| a.identity()).collect::<BTreeSet<_>>();
    let (archived, restored) = (set(archived), set(restored));
    anyhow::ensure!(
        archived == restored,
        "the restored source declares {} registrations but the archive carries {}",
        restored.len(),
        archived.len()
    );
    Ok(())
}

mod declared_owner_scope;
#[cfg(test)]
pub(in crate::backup) mod ledger_sets_tests;
mod root_lifetime;
#[cfg(test)]
mod serving_read_tests;
pub(super) mod serving_reads;

// Owner/tenant/repository/pack scopes of one registration: see
// `owner_scope_tests`. A sibling file, hence the explicit `#[path]`.
#[cfg(test)]
mod owner_scope_tests;
