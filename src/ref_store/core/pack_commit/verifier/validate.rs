//! Pure pre-IO validation of one plan/closure-context pair.
//!
//! Nothing here touches Blob storage, Git or the filesystem: the complete public
//! field set of the plan and the captured closure context must agree before a
//! single byte is fetched. The checks are deliberately redundant with the
//! capture path, because a proof binds values it recomputes itself:
//!
//! * the context must bind this exact parent digest, revision, gate digest, pack
//!   mode and old membership digest;
//! * the old active membership set must be exactly the planned one, with the
//!   complete artifact-set digest and joined revision of every pack;
//! * the new registered set must be exactly the planned pack/registration ids
//!   with the planned content digest and length of both artifacts;
//! * every artifact must carry the complete physical identity of *this* tenant,
//!   role `pack` on slot 0 / role `idx` on slot 1, and read-back values equal to
//!   its own locator;
//! * pack identities are unique across old and new, and the frozen pair, byte,
//!   object-free and result-ref bounds hold;
//! * the resulting ref map is recomputed from the plan and the captured old refs
//!   and must equal the context's.
use super::refs::{self, RefMap};
use super::refuse;
use crate::ref_store::core::pack_commit::artifact::{ArtifactSetDigest, RegisteredArtifact, RegisteredPack};
use crate::ref_store::core::pack_commit::closure::PackClosureContext;
use crate::ref_store::core::pack_commit::context::{MembershipDigest, PackMembershipEntry};
use crate::ref_store::core::pack_commit::contract::{
    ARTIFACTS_PER_PACK, MAX_ACTIVE_MEMBERSHIPS, MAX_BATCH_NEW_PACKS, MAX_CAPTURE_REFS, PackArtifactRole,
    VERIFIER_MAX_PAIRS, VERIFIER_MAX_RESULT_REFS, VERIFIER_MAX_TOTAL_BYTES,
};
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::types::{GitObjectFormat, RefName, RefUpdate};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// A validated closure ready for verified reads.
pub(super) struct Checked<'a> {
    pub(super) format: GitObjectFormat,
    pub(super) old: &'a [RegisteredPack],
    pub(super) new: &'a [RegisteredPack],
    pub(super) resulting: RefMap,
    pub(super) head: RefName,
    pub(super) head_oid: Option<String>,
    pub(super) pairs: usize,
    pub(super) bytes: u64,
}

/// Validate the complete context against the complete plan. No IO.
pub(super) fn check<'a>(
    plan: &'a PackCommitPlan,
    context: &'a PackClosureContext,
) -> Result<Checked<'a>, PackCommitError> {
    if *context.parent_digest() != *plan.parent_digest() {
        return Err(refuse("closure context binds another parent operation digest"));
    }
    if *context.gate_digest() != *plan.expected().gate_digest() {
        return Err(refuse("closure context binds another gate digest"));
    }
    if context.expected_revision() != plan.expected().revision() {
        return Err(refuse("closure context was captured at another revision"));
    }
    if context.mode() != plan.expected().mode() {
        return Err(refuse("closure context was captured in another pack mode"));
    }
    if context.old_membership_digest() != plan.old_membership_digest() {
        return Err(refuse("closure context binds another old membership digest"));
    }
    let (old, new) = (context.old_packs(), context.new_packs());
    if old.len() as i64 > MAX_ACTIVE_MEMBERSHIPS || new.len() > MAX_BATCH_NEW_PACKS {
        return Err(refuse("closure pack set exceeds a fixed registered bound"));
    }
    let pairs = old.len().saturating_add(new.len());
    if pairs > VERIFIER_MAX_PAIRS {
        return Err(refuse("closure exceeds the verifier pack-pair bound"));
    }
    unique_packs(old, new)?;
    check_membership(plan, old)?;
    check_registrations(plan, new)?;
    let mut bytes = 0u64;
    for pack in old.iter().chain(new.iter()) {
        bytes =
            bytes.checked_add(pack_bytes(pack, plan)?).ok_or_else(|| refuse("closure artifact bytes overflowed"))?;
    }
    if bytes > VERIFIER_MAX_TOTAL_BYTES {
        return Err(refuse("closure exceeds the verifier total artifact-byte bound"));
    }
    if context.old_refs().len() as i64 > MAX_CAPTURE_REFS {
        return Err(refuse("captured old ref set exceeds the verifier bound"));
    }
    // Atomic path: the complete plan batch. Accepted-subset path: exactly the
    // selected accepted updates, each one an identical original plan update. A
    // rejected ref is never part of the resulting map or of the proof.
    let updates: &[RefUpdate] = match context.accepted() {
        Some(accepted) => {
            ensure_accepted_subset(plan, accepted)?;
            accepted
        }
        None => plan.refs(),
    };
    let resulting = refs::resulting_refs_for(plan, context.old_refs(), updates)?;
    if context_map(context, plan.object_format())? != resulting {
        return Err(refuse("closure context resulting refs are not the exact planned result"));
    }
    if resulting.len() > VERIFIER_MAX_RESULT_REFS {
        return Err(refuse("closure exceeds the verifier result-ref bound"));
    }
    let (head, head_oid) = refs::head_state_with(plan, updates, context.head_ref(), &resulting)?;
    if *context.resulting_head() != head {
        return Err(refuse("closure context resulting HEAD is not the exact planned HEAD"));
    }
    Ok(Checked { format: plan.object_format(), old, new, resulting, head, head_oid, pairs, bytes })
}

/// Every accepted update must be one identical original plan update, named once.
fn ensure_accepted_subset(plan: &PackCommitPlan, accepted: &[RefUpdate]) -> Result<(), PackCommitError> {
    let mut names = BTreeSet::new();
    for update in accepted {
        if !plan.refs().iter().any(|planned| planned == update) {
            return Err(refuse("accepted subset contains an update that is not in the original plan"));
        }
        if !names.insert(update.name().as_str()) {
            return Err(refuse("accepted subset repeats a ref name"));
        }
    }
    Ok(())
}

/// Defensive role lookup: the verifier never trusts the artifact *order* inside a
/// registered pack, only each artifact's own declared role and slot.
pub(super) fn artifact_of(
    pack: &RegisteredPack,
    role: PackArtifactRole,
) -> Result<&RegisteredArtifact, PackCommitError> {
    if pack.artifacts().len() != ARTIFACTS_PER_PACK {
        return Err(refuse("registered pack does not carry exactly two artifacts"));
    }
    let mut found: Option<&RegisteredArtifact> = None;
    for artifact in pack.artifacts() {
        if artifact.role() == role {
            if found.is_some() {
                return Err(refuse("registered pack repeats an artifact role"));
            }
            found = Some(artifact);
        }
    }
    let artifact = found.ok_or_else(|| refuse("registered pack is missing an artifact role"))?;
    let slot = match role {
        PackArtifactRole::Pack => 0,
        PackArtifactRole::Idx => 1,
    };
    if artifact.slot() != slot {
        return Err(refuse("registered artifact uses the wrong pair slot"));
    }
    Ok(artifact)
}

fn pack_bytes(pack: &RegisteredPack, plan: &PackCommitPlan) -> Result<u64, PackCommitError> {
    if ArtifactSetDigest::of(pack.artifacts()) != pack.artifact_set_digest() {
        return Err(refuse("stored artifact-set digest does not cover its artifacts"));
    }
    let mut bytes = 0u64;
    for role in [PackArtifactRole::Pack, PackArtifactRole::Idx] {
        let artifact = artifact_of(pack, role)?;
        let locator = artifact.locator();
        if locator.tenant_id() != plan.tenant_id() {
            return Err(refuse("registered artifact belongs to another tenant"));
        }
        if artifact.provider().is_empty() || artifact.backend_identity().is_empty() {
            return Err(refuse("registered artifact has no provider identity"));
        }
        if artifact.verified_sha256() != locator.sha256() || artifact.verified_length() != locator.length() {
            return Err(refuse("registered read-back does not match its locator"));
        }
        locator.blob_locator().map_err(|_| refuse("registered locator cannot be reconstructed"))?;
        bytes = bytes
            .checked_add(artifact.verified_length())
            .ok_or_else(|| refuse("registered artifact bytes overflowed"))?;
    }
    Ok(bytes)
}

fn unique_packs(old: &[RegisteredPack], new: &[RegisteredPack]) -> Result<(), PackCommitError> {
    let mut packs = BTreeSet::new();
    let mut registrations = BTreeSet::new();
    for pack in old.iter().chain(new.iter()) {
        if !packs.insert(pack.pack_id()) || !registrations.insert(pack.registration_id()) {
            return Err(refuse("closure pack set repeats a pack or registration identity"));
        }
    }
    Ok(())
}

fn check_membership(plan: &PackCommitPlan, old: &[RegisteredPack]) -> Result<(), PackCommitError> {
    let mut planned = plan
        .old_memberships()
        .iter()
        .map(|entry| {
            (entry.pack_id(), entry.registration_id(), *entry.artifact_set_digest().digest(), entry.joined_revision())
        })
        .collect::<Vec<_>>();
    // `RequestDigest` is deliberately not `Ord`; order by the semantic key only.
    planned.sort_by_key(|row| (row.0, row.1, row.3));
    let mut observed = Vec::with_capacity(old.len());
    let mut entries = Vec::with_capacity(old.len());
    for pack in old {
        let joined = pack.joined_revision().ok_or_else(|| refuse("active pack membership has no joined revision"))?;
        observed.push((pack.pack_id(), pack.registration_id(), *pack.artifact_set_digest().digest(), joined));
        entries.push(
            PackMembershipEntry::from_pack(pack).map_err(|_| refuse("active pack membership identity is invalid"))?,
        );
    }
    observed.sort_by_key(|row| (row.0, row.1, row.3));
    if observed != planned {
        return Err(refuse("closure old memberships are not the planned memberships"));
    }
    if MembershipDigest::of(&entries) != plan.old_membership_digest() {
        return Err(refuse("closure old membership digest does not cover its memberships"));
    }
    Ok(())
}

fn check_registrations(plan: &PackCommitPlan, new: &[RegisteredPack]) -> Result<(), PackCommitError> {
    let mut planned: BTreeMap<Uuid, _> = BTreeMap::new();
    for pack in plan.packs() {
        if planned.insert(pack.pack_id(), pack).is_some() {
            return Err(refuse("plan repeats a pack identity"));
        }
    }
    if planned.len() != new.len() {
        return Err(refuse("closure context does not register exactly the planned packs"));
    }
    for pack in new {
        let expected = planned
            .get(&pack.pack_id())
            .ok_or_else(|| refuse("closure context registers a pack the plan does not name"))?;
        if pack.registration_id() != expected.registration_id() {
            return Err(refuse("closure context binds another registration identity"));
        }
        for role in [PackArtifactRole::Pack, PackArtifactRole::Idx] {
            let artifact = artifact_of(pack, role)?;
            let planned_artifact = expected.artifact(role);
            if artifact.locator().sha256() != planned_artifact.content()
                || artifact.verified_sha256() != planned_artifact.content()
                || artifact.locator().length() != planned_artifact.length()
                || artifact.verified_length() != planned_artifact.length()
            {
                return Err(refuse("registered artifact content is not the planned content"));
            }
        }
    }
    Ok(())
}

fn context_map(context: &PackClosureContext, format: GitObjectFormat) -> Result<RefMap, PackCommitError> {
    let mut map = RefMap::new();
    for reference in context.resulting_refs() {
        refs::validate_ref(reference.name(), reference.oid_hex(), format)?;
        if map.insert(reference.name().to_owned(), reference.oid_hex().to_owned()).is_some() {
            return Err(refuse("closure context resulting refs repeat a name"));
        }
    }
    Ok(map)
}
