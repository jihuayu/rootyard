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
//! * `registration_badges` -- the current typed A4 active membership, captured
//!   read-only at the verified gate (`PgPackCommit::capture_baseline`, never a
//!   stale pre-commit plan closure), and the stored `artifact_set_digest` read
//!   back from the real publication row.
//!
//! An HTTP-provisioned `pg_refstore` repository carries the irreversible
//! migration-144 decision-required fence from the moment it is ready (serving
//! enables it before readiness, including the first push). The production
//! serving pipeline therefore commits received packs through the decision-gated
//! facade, not the legacy A4 path. `decided_pair` reproduces that tail with the
//! real `PgAuthorizedCommit::{prepare,select,verify,commit}` calls after the
//! same `pack_plan::publish`/`register`; the producer token is the operation
//! issuer, exactly as the serving request owner is.
//!
//! Nothing here writes SQL for positive state, creates a fake repository,
//! disables a fence or fabricates a digest.
use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::core::pack_commit::{
    AuthorizedCommitMode, PackArtifactRole, PackCommitPlan, PackPendingToken, PgAuthorizedCommit, PgPackCommit,
    PrepareOutcome, RegisteredArtifact, RegisteredPack,
};
use rootyard::ref_store::core::{
    CreatePackSnapshotRequest, MetadataPinOutcome, MetadataSnapshotScope, PackReadSnapshot, PackSnapshotExpectation,
};
use rootyard::ref_store::{CoreGateVersion, MetadataPinPurpose};
use std::path::Path;
use uuid::Uuid;

use super::db::{Db, deadline};
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

/// Diagnostic form of one fixture-owned pack step: a fixed stage label, the
/// seed loop sequence when there is one, and the gate revision the plan expects.
///
/// It never replaces the typed error: the `{error:#}` chain (and every
/// `PackCommitError` source) is kept verbatim. Labels and the plan's expected
/// revision are plain integers/literals, so nothing sensitive is added.
#[derive(Clone, Copy)]
struct Stage {
    name: &'static str,
    sequence: Option<i64>,
    revision: i64,
}

impl Stage {
    fn of(name: &'static str, sequence: Option<i64>, plan: &PackCommitPlan) -> Self {
        Self { name, sequence, revision: plan.expected().revision() }
    }

    fn tag(&self, error: impl std::fmt::Display) -> anyhow::Error {
        match self.sequence {
            Some(sequence) => {
                anyhow!("sequence {sequence} stage={} expected_revision={}: {error:#}", self.name, self.revision)
            }
            None => anyhow!("stage={} expected_revision={}: {error:#}", self.name, self.revision),
        }
    }
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

/// `finish_pair`/`advance_pair`'s upload tail through the decision-gated
/// pipeline production serving uses on a fenced repository: A3 acquire +
/// protected upload + A4 register (same shared `publish`/`register`), then
/// `prepare` -> `select` -> `verify` -> `commit` on the same original plan.
///
/// The plan's closure context (`pack::closure` -> `capture_context`) is
/// captured **before** `prepare`, at the planned gate revision: `prepare` seals
/// it at `expected_revision`, and `select` then installs the decision in the
/// same transaction as the gate advance, so a context requested afterwards can
/// only be reached with `expected_v1`. The registrations it reads are the durable
/// A4 rows of this plan (same ids, digests, locators); nothing is synthesized.
///
/// `sequence` is the seed's pack-loop position, used only to tag the untagged
/// `publish`/`register`/`closure` rejections.
pub async fn decided_pair(
    db: &Db,
    store: &BlobStore,
    git: &Path,
    draft: &pack_plan::Draft,
    files: &PairFiles,
    actor: &rootyard::db::Identity,
    sequence: i64,
) -> Result<Vec<RegisteredPack>> {
    let mode = match draft.plan.commit_mode().as_str() {
        "accepted_subset" => AuthorizedCommitMode::AcceptedSubset,
        "atomic" => AuthorizedCommitMode::Atomic,
        other => return Err(anyhow!("unknown planned commit mode {other}")),
    };
    ensure!(draft.plan.identity().issuer_id() == actor.id, "the producer token is not the operation issuer");
    let pack_id = draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    // Diagnostic only: `publish` and `register` (A4 `register_publication`)
    // return untagged bare `PackCommitError`s, so name those stages with the
    // plan's expected revision too. `closure` (via `capture_context`) is named
    // for the same reason, keeping apart each untagged sibling callsite.
    let stage = Stage::of("publish", Some(sequence), &draft.plan);
    let publication = pack_plan::publish(db, store, &draft.plan, files).await.map_err(|error| stage.tag(error))?;
    let stage = Stage::of("register", Some(sequence), &draft.plan);
    pack_plan::register(db, &draft.plan, pack_id, &publication).await.map_err(|error| stage.tag(error))?;
    let stage = Stage::of("closure", Some(sequence), &draft.plan);
    let context = pack::closure(db, &draft.plan).await.map_err(|error| stage.tag(error))?;
    ensure!(
        context.new_packs().len() == 1 && context.old_packs().len() == draft.plan.old_memberships().len(),
        "the planned closure is not one new pack on the planned membership"
    );
    ensure!(
        context.new_packs()[0].registration_id() == draft.plan.packs()[0].registration_id(),
        "the captured closure is not this plan's registration"
    );
    let authorized = PgAuthorizedCommit::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("authorized pipeline rejected the Blob/Git configuration: {error:?}"))?;
    let prepared = match authorized.prepare(&db.pool, draft.plan.clone(), deadline()).await {
        Ok(PrepareOutcome::Prepared(publication)) => publication,
        Ok(PrepareOutcome::Replayed(_)) => return Err(anyhow!("authorized prepare replayed a fresh operation")),
        Err(error) => return Err(anyhow!("authorized prepare refused ({}): {error:?}", error.code())),
    };
    let selection = authorized
        .select(&db.pool, *prepared, actor, mode, deadline())
        .await
        .map_err(|error| anyhow!("authorized select refused ({}): {error:?}", error.code()))?;
    // Diagnostic only: counts and the all-rejected flag on the failing path.
    // `AuthorizedSelection` keeps its sealed decision private, so per-ref
    // verdicts (name + shared reason + bounded detail) are not reachable here and
    // no free-form string from any other source may stand in for them.
    let selection_state = || {
        format!(
            "accepted={} planned={} all_rejected={}",
            selection.accepted_refs(),
            selection.planned_refs(),
            selection.is_all_rejected()
        )
    };
    ensure!(
        selection.accepted_refs() == draft.plan.refs().len() && !selection.is_all_rejected(),
        "the decision did not accept every planned ref: {}",
        selection_state()
    );
    let verified = authorized
        .verify(selection, deadline())
        .await
        .map_err(|error| anyhow!("authorized verify refused ({}): {error:?}", error.code()))?;
    let receipt = authorized
        .commit(&db.pool, &verified, deadline())
        .await
        .map_err(|error| anyhow!("authorized commit refused ({}): {error:?}", error.code()))?;
    ensure!(receipt.is_committed() && !receipt.replayed, "decided verified commit did not commit");
    let gate = super::db::gate_version(&db.pool, draft.plan.repository_id(), draft.plan.tenant_id()).await?;
    ensure!(gate.revision() == receipt.terminal.revision, "gate after the decided commit differs");
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
    // Diagnostic only: name the A5 stages with the verified gate the snapshot
    // expectation is built from; the typed error is kept unchanged.
    let stage = Stage { name: "a5_create", sequence: None, revision: verified.gate.revision() };
    let outcome = pack::a5_create(&db.pool, &request).await.map_err(|error| stage.tag(error))?;
    ensure!(!outcome.replayed, "fresh pack snapshot replayed");
    let stored_owner = db
        .pool
        .get()
        .await?
        .query_one("SELECT owner_id FROM ref_store_core_snapshots WHERE snapshot_id=$1", &[&snapshot_id])
        .await?
        .get::<_, Uuid>(0);
    ensure!(stored_owner == producer, "the stored A5 snapshot owner is not the producer");
    let stage = Stage { name: "a5_read", sequence: None, revision: verified.gate.revision() };
    let read = pack::a5_read(&db.pool, verified.repo, verified.tenant, snapshot_id, pin_id, 1)
        .await
        .map_err(|error| stage.tag(error))?;
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
pub async fn release_snapshot_pin(
    db: &Db,
    snapshot: &ProducerSnapshot,
    gate: &CoreGateVersion,
) -> Result<MetadataPinOutcome> {
    let stage = Stage { name: "release_pin", sequence: None, revision: gate.revision() };
    pack::release_pin(&db.pool, snapshot.scope, snapshot.pin_id).await.map_err(|error| stage.tag(error))
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

/// Require one artifact of a captured membership to be the exact stored
/// artifact of the committed registration: role, slot, hold, locator identity
/// (storage tenant, authority, generation, attempt, namespace, content digest,
/// length), provider, backend identity and verified content.
fn same_artifact(stored: &RegisteredArtifact, committed: &RegisteredArtifact) -> bool {
    stored.role() == committed.role()
        && stored.slot() == committed.slot()
        && stored.hold_id() == committed.hold_id()
        && stored.locator() == committed.locator()
        && stored.locator().tenant_id() == committed.locator().tenant_id()
        && stored.provider() == committed.provider()
        && stored.backend_identity() == committed.backend_identity()
        && stored.verified_sha256().as_str() == committed.verified_sha256().as_str()
        && stored.verified_length() == committed.verified_length()
}

/// Read every fixture registration back from the *current* production typed A4
/// active membership and require its stored `artifact_set_digest` to equal
/// `RegisteredPack::artifact_set_digest()`.
///
/// This is a fresh read-only `PgPackCommit::capture_baseline` at the verified
/// gate, not the closure of the last plan: after a successful decided commit
/// that plan's expected revision is its pre-commit one, so its closure is
/// correctly fenced off by `check_gate` (`RevisionMismatch`). The baseline's
/// `old_packs()` is the same production complete active-membership reader a
/// commit uses, including each stored producer's full ACK/artifact/A3
/// validation; the stored publisher owner is resolved independently and is
/// never compared with the tenant.
pub async fn registration_badges(
    db: &Db,
    repository_id: Uuid,
    tenant_id: Uuid,
    gate: &CoreGateVersion,
    packs: &[RegisteredPack],
) -> Result<Vec<RegistrationBadge>> {
    let stage =
        |error: anyhow::Error| anyhow!("stage=registration_badges expected_revision={}: {error:#}", gate.revision());
    let mut client = db.pool.get().await.map_err(|error| stage(error.into()))?;
    let baseline = PgPackCommit::new()
        .capture_baseline(&mut client, repository_id, tenant_id, deadline())
        .await
        .map_err(|error| stage(anyhow!("capture_baseline refused: {error:?}")))?;
    // The capture is a complete snapshot; the pooled client is not needed by
    // the per-registration publication read-back below, so return it first.
    drop(client);
    ensure!(
        baseline.gate().revision() == gate.revision() && baseline.gate().digest() == gate.digest(),
        "the captured baseline gate is not the verified gate"
    );
    let typed = baseline.old_packs();
    ensure!(
        typed.len() == packs.len(),
        "the active A4 membership holds {} packs, expected {}",
        typed.len(),
        packs.len()
    );
    let mut out = Vec::with_capacity(packs.len());
    for pack in packs {
        let stored = typed
            .iter()
            .find(|candidate| candidate.pack_id() == pack.pack_id())
            .ok_or_else(|| anyhow!("the registration is not in the current A4 membership"))?;
        ensure!(stored.registration_id() == pack.registration_id(), "registration identity differs");
        ensure!(
            stored.artifact_set_digest() == pack.artifact_set_digest(),
            "typed A4 set digest differs from the committed registration"
        );
        ensure!(
            same_artifact(stored.artifact(PackArtifactRole::Pack), pack.artifact(PackArtifactRole::Pack))
                && same_artifact(stored.artifact(PackArtifactRole::Idx), pack.artifact(PackArtifactRole::Idx)),
            "the captured A4 artifacts differ from the committed pack/idx artifacts"
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
        let digest = |role: PackArtifactRole| stored.artifact(role).verified_sha256().as_str().to_owned();
        out.push(RegistrationBadge {
            registration_id: stored.registration_id(),
            pack_id: stored.pack_id(),
            artifact_set_digest: stored_column,
            pack_sha256: digest(PackArtifactRole::Pack),
            idx_sha256: digest(PackArtifactRole::Idx),
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
