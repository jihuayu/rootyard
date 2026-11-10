//! Pure helpers and bounded workspace accounting for the publication-facts engine.
//!
//! These functions contain no native child and no PostgreSQL client; they are the
//! deterministic digest/identity/accounting pieces extracted from the engine so
//! every source file stays small. The owned blocking workspace scan keeps a lease
//! clone so a cancelled or timed-out join never releases capacity early.
use super::lease::VerificationLease;
use super::refuse;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::artifact::{ArtifactSetDigest, RegisteredPack};
use crate::ref_store::core::pack_commit::context::{CapturedRef, MembershipDigest, PackMembershipEntry, refs_digest};
use crate::ref_store::core::pack_commit::contract::{PackArtifactRole, VERIFIER_VIEW_MAX_LOGICAL_BYTES};
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::pack_commit::facts::{RefFacts, VerifiedPackIdentity};
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::types::GitObjectFormat;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

pub(super) fn membership_rows(
    packs: &[RegisteredPack],
) -> Result<BTreeMap<Uuid, (Uuid, ArtifactSetDigest, i64)>, PackCommitError> {
    let mut rows = BTreeMap::new();
    for pack in packs {
        let entry = PackMembershipEntry::from_pack(pack)?;
        rows.insert(entry.pack_id(), (entry.registration_id(), entry.artifact_set_digest(), entry.joined_revision()));
    }
    Ok(rows)
}

pub(super) fn pair_bytes(pack: &RegisteredPack) -> Result<u64, PackCommitError> {
    pack.artifact(PackArtifactRole::Pack)
        .verified_length()
        .checked_add(pack.artifact(PackArtifactRole::Idx).verified_length())
        .ok_or_else(|| refuse("publication artifact bytes overflowed"))
}

pub(super) fn old_ref_map(
    refs: &[CapturedRef],
    format: GitObjectFormat,
) -> Result<BTreeMap<String, String>, PackCommitError> {
    let mut map = BTreeMap::new();
    for reference in refs {
        super::refs::validate_ref(reference.name(), reference.oid_hex(), format)?;
        if map.insert(reference.name().to_owned(), reference.oid_hex().to_owned()).is_some() {
            return Err(refuse("captured old ref set repeats a name"));
        }
    }
    Ok(map)
}

pub(super) fn facts_digest(
    plan: &PackCommitPlan,
    realm: &RequestDigest,
    old_refs: &[CapturedRef],
    old_membership: MembershipDigest,
    old_packs_digest: RequestDigest,
    new_packs_digest: RequestDigest,
    packs: &[VerifiedPackIdentity],
    refs: &[RefFacts],
) -> RequestDigest {
    let mut fields: Vec<Vec<u8>> = vec![
        plan.identity().repository_id().as_bytes().to_vec(),
        plan.identity().issuer_id().as_bytes().to_vec(),
        plan.identity().lane().as_str().as_bytes().to_vec(),
        plan.identity().sequence().to_be_bytes().to_vec(),
        plan.identity().operation_id().as_bytes().to_vec(),
        plan.parent_digest().as_bytes().to_vec(),
        plan.commit_mode().as_str().as_bytes().to_vec(),
        realm.as_bytes().to_vec(),
        refs_digest(old_refs).as_bytes().to_vec(),
        old_membership.digest().as_bytes().to_vec(),
        old_packs_digest.as_bytes().to_vec(),
        new_packs_digest.as_bytes().to_vec(),
    ];
    fields.push((packs.len() as u64).to_be_bytes().to_vec());
    for pack in packs {
        fields.push(pack.digest().as_bytes().to_vec());
    }
    fields.push((refs.len() as u64).to_be_bytes().to_vec());
    for facts in refs {
        fields.push(facts.digest().as_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-publication-facts-v1", &parts)
}

pub(super) async fn check_workspace(lease: &Arc<VerificationLease>, deadline: Instant) -> Result<(), PackCommitError> {
    if workspace_bytes(lease, deadline).await? > VERIFIER_VIEW_MAX_LOGICAL_BYTES {
        return Err(refuse("publication facts workspace exceeds its aggregate bound"));
    }
    Ok(())
}

pub(super) async fn preflight_workspace(
    lease: &Arc<VerificationLease>,
    additional: u64,
    deadline: Instant,
) -> Result<(), PackCommitError> {
    let projected = workspace_bytes(lease, deadline)
        .await?
        .checked_add(additional)
        .ok_or_else(|| refuse("publication workspace projection overflowed"))?;
    if projected > VERIFIER_VIEW_MAX_LOGICAL_BYTES {
        return Err(refuse("publication facts would exceed their aggregate workspace bound"));
    }
    Ok(())
}

/// Recursive workspace scan on one owned blocking task holding a lease clone, so
/// a timed-out or cancelled join can never release the workspace, the view budget
/// or the native permit while syscalls may still run.
pub(super) async fn workspace_bytes(lease: &Arc<VerificationLease>, deadline: Instant) -> Result<u64, PackCommitError> {
    if deadline <= Instant::now() {
        return Err(refuse("publication workspace scan has no remaining deadline"));
    }
    let lease = Arc::clone(lease);
    let task = tokio::task::spawn_blocking(move || {
        let lease = lease;
        lease.retained_bytes()
    });
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(refuse("publication workspace scan task failed")),
        Err(_) => Err(refuse("publication workspace scan is retained until it exits")),
    }
}
