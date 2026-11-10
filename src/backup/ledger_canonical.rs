//! Canonical A4 registration rebuilds shared by the snapshot and root checks.
//!
//! The artifact locator is rebuilt with the issuer's own types
//! (`ArtifactLocator::new`/`RegisteredArtifact::new`/`RegisteredPack::new`), so
//! a stored digest alone is never trusted; `packs_digest` then binds the joined
//! membership revision (`publication.gate_revision + 1`).
use super::ledger_sets::{DeclaredPair, Realm, RetainedPack, RootCapture};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, PackArtifactRole, RegisteredArtifact, RegisteredPack,
};

/// Realm and stored digest of one canonical registration.
pub(super) struct Canonical {
    pub(super) digest: ArtifactSetDigest,
    pub(super) joined_revision: i64,
    pub(super) realm: Realm,
}

/// Rebuild one canonical registration from its A4 rows like the issuer does.
pub(super) fn canonical(pair: &DeclaredPair) -> Result<(RegisteredPack, Canonical), &'static str> {
    let publication = pair.publication.as_ref().ok_or("unpublished")?;
    let artifacts = pair
        .artifacts
        .iter()
        .map(|artifact| {
            let sha = content_digest(&artifact.sha256).map_err(|_| "invalid artifact digest")?;
            let role = PackArtifactRole::parse(&artifact.role).map_err(|_| "invalid artifact role")?;
            let locator = ArtifactLocator::new(
                artifact.tenant_id,
                artifact.authority_id,
                artifact.generation,
                artifact.attempt_id,
                artifact.namespace.clone(),
                sha.clone(),
                artifact.length,
            )
            .map_err(|_| "invalid artifact locator")?;
            RegisteredArtifact::new(
                role,
                artifact.slot,
                artifact.hold_id,
                locator,
                artifact.provider.clone(),
                artifact.backend_identity.clone(),
                sha,
                artifact.length,
            )
            .map_err(|_| "invalid artifact identity")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let digest: RequestDigest = publication.digest.parse().map_err(|_| "invalid stored digest")?;
    let stored = ArtifactSetDigest::from_digest(digest);
    let joined_revision = publication.gate_revision.saturating_add(1);
    // The active membership of a registration joins at `publication.gate_revision
    // + 1`, and `packs_digest` binds that revision, so the canonical pair carries
    // it exactly (the artifact-set digest itself does not depend on it).
    let pack = RegisteredPack::new(pair.pack_id, pair.registration_id, stored, artifacts, Some(joined_revision))
        .map_err(|_| "invalid canonical pair")?;
    let realm = Realm {
        tenant_id: publication.tenant_id,
        history_incarnation: publication.history_incarnation,
        authority_epoch: publication.authority_epoch,
        group_epoch: publication.group_epoch,
        object_format: publication.object_format.clone(),
    };
    Ok((pack, Canonical { digest: stored, joined_revision, realm }))
}

/// A stored lowercase SHA-256 as the issuer's content digest.
pub(super) fn content_digest(sha256: &str) -> Result<crate::ref_store::core::pack_commit::ContentDigest, ()> {
    crate::ref_store::core::pack_commit::ContentDigest::parse(sha256.to_owned()).map_err(|_| ())
}

/// The declared row must agree with the canonical registration on realm, digest
/// and joined revision.
pub(super) fn declared_agrees(
    canonical: &Canonical,
    realm: &Realm,
    digest: &str,
    joined_revision: i64,
) -> Result<(), &'static str> {
    if canonical.realm != *realm {
        return Err("the declared realm differs from the publication");
    }
    if digest != canonical.digest.as_hex() {
        return Err("the declared artifact-set digest differs from the canonical set");
    }
    if joined_revision != canonical.joined_revision {
        return Err("the declared joined revision differs from the publication");
    }
    Ok(())
}

/// Rebuild one retained pair from the root's own rows and require it to equal
/// the canonical A4 registration (realm, digest, joined revision, every locator
/// and the verified read-back of both artifacts).
pub(super) fn retained_pair(
    root: &RootCapture,
    pack: &RetainedPack,
    pair: &DeclaredPair,
) -> Result<RegisteredPack, &'static str> {
    let (canonical, stored) = canonical(pair)?;
    declared_agrees(&stored, &root.realm, &pack.artifact_set_digest, pack.joined_revision)?;
    if pack.pack_id != canonical.pack_id() || pack.registration_id != canonical.registration_id() {
        return Err("the retained pack id differs from its registration");
    }
    // A root pack row carries its `.pack` in the pack column group (slot 0) and
    // its `.idx` in the idx column group (slot 1); the stored slots must name
    // exactly those groups.
    if pack.pack.slot != 0 || pack.idx.slot != 1 {
        return Err("the retained pair slots are not pack/idx 0/1");
    }
    for retained in [&pack.pack, &pack.idx] {
        let role = retained_role(retained.slot)?;
        let expected = canonical.artifact(role);
        let length = u64::try_from(retained.length).map_err(|_| "the retained length is not positive")?;
        let verified = u64::try_from(retained.verified_length).map_err(|_| "the retained length is not positive")?;
        let same = retained.slot == expected.slot()
            && retained.hold_id == expected.hold_id()
            && retained.tenant_id == expected.locator().tenant_id()
            && retained.authority_id == expected.locator().authority_id()
            && retained.generation == expected.locator().authority_generation()
            && retained.attempt_id == expected.locator().attempt_id()
            && retained.namespace == expected.locator().namespace()
            && retained.sha256 == expected.locator().sha256().as_str()
            && length == expected.locator().length()
            && retained.provider == expected.provider()
            && retained.backend_identity == expected.backend_identity()
            && retained.verified_sha256 == expected.verified_sha256().as_str()
            && verified == expected.verified_length();
        if !same {
            return Err("the retained locator differs from the canonical registration");
        }
    }
    Ok(canonical)
}

/// The role a retained slot names: 0 is `.pack`, 1 is `.idx`. A root pack row
/// carries the two slots in two column groups, so a group's slot selects the
/// role of that group's artifact.
fn retained_role(slot: i32) -> Result<PackArtifactRole, &'static str> {
    match slot {
        0 => Ok(PackArtifactRole::Pack),
        1 => Ok(PackArtifactRole::Idx),
        _ => Err("the retained slot is not 0/1"),
    }
}
