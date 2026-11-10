//! Packs, snapshot and marker identity of one *existing* API-provisioned
//! repository.
//!
//! Issue #169 needs the real HTTP `pg_refstore` repository (`ref_store::serving`
//! provision), not the offline `Db::business` gitfs/provisioning pair that the
//! shared `pack::verify_new` creates. This module therefore starts from a
//! repository and tenant the serving path already returned and only reuses the
//! unchanged shared helpers: `pack::{closure, prove, commit, release_pin}` and
//! the raw `pg_refstore` gate read. Its three "different owner" helpers are the
//! unchanged production calls with an explicit producer owner instead of the
//! tenant:
//!
//! * `pack_plan::{draft, publish, register}` -- A3 acquire / protected upload /
//!   A4 register, so the durable holds and the publication carry the real
//!   request owner (storage tenant/RAM prefix stay derived from the same store);
//! * `producer_snapshot` -- the A5 pack snapshot created by that owner, which is
//!   the owner the root `prepare` proves the pin against;
//! * `registration_badges` -- the stored `artifact_set_digest` read back from
//!   the real publication row and re-derived from the typed A4 registration.
//!
//! Nothing here writes SQL for positive state, creates a fake repository or
//! fabricates a digest.
use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::core::pack_commit::{PackCommitPlan, PackPendingToken, RegisteredPack};
use rootyard::ref_store::core::{
    CreatePackSnapshotRequest, MetadataPinOutcome, MetadataSnapshotScope, PackReadSnapshot, PackSnapshotExpectation,
};
use rootyard::ref_store::{CoreGateVersion, MetadataPinPurpose};
use std::path::Path;
use uuid::Uuid;

use super::db::Db;
use super::git::{GitRepo, PairFiles};
use super::pack::{self, Verified};
use super::pack_plan;
use super::roots;

/// The pre-existing API repository the format22 packs are registered on.
pub struct Existing {
    pub tenant: Uuid,
    pub repo: Uuid,
    pub gate: CoreGateVersion,
}

/// A5 pack snapshot whose owner (the pin/snapshot scope owner) is `owner`.
pub struct ProducerSnapshot {
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub scope: MetadataSnapshotScope,
    pub read: PackReadSnapshot,
}

/// Existing repository + Git corpus; no repository row is created here.
pub async fn open(db: &Db, repo: Uuid, tenant: Uuid, git: &Path) -> Result<(Existing, GitRepo)> {
    let gate = super::db::gate_version(&db.pool, repo, tenant).await?;
    let fixture = GitRepo::new(git.to_path_buf(), gate.object_format()).await?;
    Ok((Existing { tenant, repo, gate }, fixture))
}

/// `verify_new`'s verified-commit tail for the *first* pack on an existing
/// repository (main absent -> `refs/heads/main`), with an explicit producer
/// owner. The shared `closure`/`prove`/`commit` calls are used unchanged.
pub async fn finish_pair(
    db: &Db,
    store: &BlobStore,
    git: &Path,
    draft: &pack_plan::Draft,
    files: &PairFiles,
) -> Result<Vec<RegisteredPack>> {
    let pack_id = draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    let publication = pack_plan::publish(db, store, &draft.plan, files).await?;
    pack_plan::register(db, &draft.plan, pack_id, &publication).await?;
    let context = pack::closure(db, &draft.plan).await?;
    ensure!(context.new_packs().len() == 1 && context.old_packs().is_empty(), "first closure is not one new pack");
    let proof = pack::prove(store, git, &draft.plan, &context).await?;
    let receipt = pack::commit(db, &draft.plan, &draft.token, &proof).await?;
    ensure!(receipt.is_committed() && !receipt.replayed, "fresh verified commit did not commit");
    let gate = super::db::gate_version(&db.pool, draft.plan.repository_id(), draft.plan.tenant_id()).await?;
    ensure!(gate.revision() == receipt.terminal.revision, "gate after commit differs");
    Ok(context.new_packs().to_vec())
}

/// `verify_advance`'s verified-commit tail (one more pack advancing `main`),
/// with an explicit producer owner.
pub async fn advance_pair(
    db: &Db,
    store: &BlobStore,
    git: &Path,
    draft: &pack_plan::Draft,
    files: &PairFiles,
) -> Result<Vec<RegisteredPack>> {
    let pack_id = draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    let publication = pack_plan::publish(db, store, &draft.plan, files).await?;
    pack_plan::register(db, &draft.plan, pack_id, &publication).await?;
    let context = pack::closure(db, &draft.plan).await?;
    ensure!(context.new_packs().len() == 1, "advance closure is not one new pack");
    let proof = pack::prove(store, git, &draft.plan, &context).await?;
    let receipt = pack::commit(db, &draft.plan, &draft.token, &proof).await?;
    ensure!(receipt.is_committed() && !receipt.replayed, "advance verified commit did not commit");
    let gate = super::db::gate_version(&db.pool, draft.plan.repository_id(), draft.plan.tenant_id()).await?;
    ensure!(gate.revision() == receipt.terminal.revision, "advanced gate revision differs");
    Ok(context.new_packs().to_vec())
}

/// The shared `snapshot_scope` with `owner_id` = the producer that will prepare
/// the root, so `PgPackSnapshot.create` seals a snapshot whose scope owner is
/// that producer (the root `prepare` compares the pin realm owner-for-owner).
pub fn producer_snapshot_scope(
    repo: Uuid,
    tenant: Uuid,
    producer: Uuid,
    gate: &CoreGateVersion,
) -> Result<MetadataSnapshotScope> {
    Ok(MetadataSnapshotScope::new(
        repo,
        tenant,
        producer,
        MetadataPinPurpose::Verification,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?)
}

/// `pack::create_snapshot` with the snapshot owner set to `producer`.
pub async fn producer_snapshot(db: &Db, verified: &Verified, producer: Uuid, lease: i64) -> Result<ProducerSnapshot> {
    let scope = producer_snapshot_scope(verified.repo, verified.tenant, producer, &verified.gate)?;
    let request_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let pin_id = Uuid::new_v4();
    let expected = PackSnapshotExpectation::new(verified.gate.revision(), *verified.gate.digest())?;
    let request = CreatePackSnapshotRequest::new(scope, request_id, pin_id, snapshot_id, lease, expected)?;
    let outcome = pack::a5_create(&db.pool, &request).await?;
    ensure!(!outcome.replayed, "fresh pack snapshot replayed");
    let stored_owner = db
        .pool
        .get()
        .await?
        .query_one("SELECT owner_id FROM ref_store_core_snapshots WHERE snapshot_id=$1", &[&snapshot_id])
        .await?
        .get::<_, Uuid>(0);
    ensure!(stored_owner == producer, "the stored A5 snapshot owner is not the producer");
    let read = pack::a5_read(&db.pool, verified.repo, verified.tenant, snapshot_id, pin_id, 1).await?;
    ensure!(read.pack_mode() == "pack_verified", "source snapshot is not pack_verified");
    ensure!(read.pack_count() > 0, "source snapshot has no registered pack membership");
    Ok(ProducerSnapshot { snapshot_id, pin_id, scope, read })
}

/// Rebuild the `retention_roots_support::pack::SourceSnapshot` view of the
/// producer's snapshot (its `scope` is the authoritative read).
pub fn as_source(snapshot: &ProducerSnapshot) -> pack::SourceSnapshot {
    pack::SourceSnapshot {
        scope: snapshot.scope,
        request_id: Uuid::new_v4(),
        snapshot_id: snapshot.snapshot_id,
        pin_id: snapshot.pin_id,
        read: snapshot.read.clone(),
    }
}

/// Release the A5 pin through the shared `release_pin` with its own scope.
pub async fn release_snapshot_pin(db: &Db, snapshot: &ProducerSnapshot) -> Result<MetadataPinOutcome> {
    pack::release_pin(&db.pool, snapshot.scope, snapshot.pin_id)
        .await
        .map_err(|error| anyhow!("A5 source pin release failed: {error}"))
}

/// One registration as the archive stores it: publication digest (the real
/// column) and the typed set digest recomputed from that same registration.
pub struct RegistrationBadge {
    pub registration_id: Uuid,
    pub pack_id: Uuid,
    pub artifact_set_digest: String,
    pub pack_sha256: String,
    pub idx_sha256: String,
}

/// Read every fixture registration back through the production typed record
/// (`capture_context` -> `RegisteredPack`) and require its stored
/// `artifact_set_digest` to equal `RegisteredPack::artifact_set_digest()`.
pub async fn registration_badges(
    db: &Db,
    plan: &PackCommitPlan,
    packs: &[RegisteredPack],
) -> Result<Vec<RegistrationBadge>> {
    let context = pack::closure(db, plan).await?;
    let typed = context.old_packs().iter().chain(context.new_packs()).collect::<Vec<_>>();
    let mut out = Vec::with_capacity(packs.len());
    for pack in packs {
        let stored = typed
            .iter()
            .find(|candidate| candidate.pack_id() == pack.pack_id())
            .ok_or_else(|| anyhow!("the registration is not in the captured A4 set"))?;
        ensure!(stored.registration_id() == pack.registration_id(), "registration identity differs");
        ensure!(
            stored.artifact_set_digest() == pack.artifact_set_digest(),
            "typed A4 set digest differs from the committed registration"
        );
        let row = db
            .pool
            .get()
            .await?
            .query_one(
                "SELECT artifact_set_digest FROM ref_store_core_pack_publications WHERE registration_id=$1",
                &[&pack.registration_id()],
            )
            .await?;
        let stored_column: String = row.get(0);
        ensure!(
            stored_column == pack.artifact_set_digest().as_hex(),
            "the stored publication digest differs from the typed registration"
        );
        let digest = |role: rootyard::ref_store::core::pack_commit::PackArtifactRole| {
            pack.artifact(role).verified_sha256().as_str().to_owned()
        };
        out.push(RegistrationBadge {
            registration_id: pack.registration_id(),
            pack_id: pack.pack_id(),
            artifact_set_digest: stored_column,
            pack_sha256: digest(rootyard::ref_store::core::pack_commit::PackArtifactRole::Pack),
            idx_sha256: digest(rootyard::ref_store::core::pack_commit::PackArtifactRole::Idx),
        });
    }
    Ok(out)
}

/// Pin a draft so its lifetime is explicit: the token is consumed exactly once.
pub fn single(draft: pack_plan::Draft) -> (PackCommitPlan, PackPendingToken) {
    (draft.plan, draft.token)
}

/// Shared root scope for the producer (root owner) of one repository.
pub fn root_scope(
    existing: &Existing,
    producer: Uuid,
) -> Result<rootyard::ref_store::core::retention_root::RootsScope> {
    roots::producer_scope(existing.repo, existing.tenant, producer, &existing.gate)
}
