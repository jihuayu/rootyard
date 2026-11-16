//! Packs, snapshot and marker identity of one *existing* API-provisioned
//! repository.
//!
//! Issue #169 needs the real HTTP `pg_refstore` repository (`ref_store::serving`
//! provision), not the offline `Db::business` gitfs/provisioning pair that the
//! shared `pack::verify_new` creates. This module therefore starts from a
//! repository and tenant the serving path already returned and reuses the
//! unchanged production pack helpers plus the explicit actor-owned snapshot
//! facade:
//!
//! * `pack_plan::{draft, publish, register}` -- A3 acquire / protected upload /
//!   A4 register, so the durable holds and the publication carry the real
//!   request owner (storage tenant/RAM prefix stay derived from the same store);
//! * `producer_snapshot` -- `PgServingSnapshotMetadata::create_actor_owned` and
//!   `read_actor_owned`, which persist the producer as the A5 owner while the
//!   repository tenant, gate realm, backend and Admin/ContentsWrite checks stay
//!   production-derived;
//! * `release_snapshot_pin` -- the actor-owned snapshot release facade;
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
use rootyard::db::Identity;
use rootyard::ref_store::core::pack_commit::{
    AuthorizedCommitMode, PackArtifactRole, PackCommitPlan, PgAuthorizedCommit, PgPackCommit, PrepareOutcome,
    RegisteredArtifact, RegisteredPack,
};
use rootyard::ref_store::core::{MetadataPinOutcome, PackReadSnapshot};
use rootyard::ref_store::serving::{
    PgServingSnapshotMetadata, ServingSnapshotCreate, ServingSnapshotRead, ServingSnapshotRelease,
};
use rootyard::ref_store::{CoreGateVersion, PinReleaseReason};
use std::path::Path;
use uuid::Uuid;

use super::db::{Db, deadline};
use super::git::{GitRepo, PairFiles};
use super::pack::{self, Verified};
use super::pack_plan;

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

/// Actor-owned A5 pack snapshot receipt/read pair for the format22 source.
pub struct ProducerSnapshot {
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub read: PackReadSnapshot,
}

/// Existing repository + Git corpus; no repository row is created here.
pub async fn open(db: &Db, repo: Uuid, tenant: Uuid, git: &Path) -> Result<(Existing, GitRepo)> {
    let gate = super::db::gate_version(&db.pool, repo, tenant).await?;
    let fixture = GitRepo::new(git.to_path_buf(), gate.object_format()).await?;
    Ok((Existing { tenant, repo, gate }, fixture))
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

/// Capture one durable serving A5 snapshot through the explicit actor-owned
/// facade. The facade derives the durable owner from the authenticated
/// producer; repository tenant, gate realm, storage backend and request
/// identities stay production-derived. No owner-id field or direct SQL exists.
pub async fn producer_snapshot(
    db: &Db,
    store: &BlobStore,
    verified: &Verified,
    producer: &Identity,
    owner: &str,
    name: &str,
    lease: i64,
) -> Result<ProducerSnapshot> {
    let stage = Stage { name: "a5_create", sequence: None, revision: verified.gate.revision() };
    let created = PgServingSnapshotMetadata
        .create_actor_owned(
            &db.pool,
            producer,
            ServingSnapshotCreate {
                owner: owner.to_owned(),
                name: name.to_owned(),
                idempotency_key: "format22-producer-a5".into(),
                lease_seconds: lease,
            },
            store.backend_identity(),
            deadline(),
        )
        .await
        .map_err(|error| stage.tag(error))?;
    ensure!(!created.replayed, "fresh actor-owned pack snapshot replayed");
    ensure!(
        created.receipt.scope().tenant_id() == verified.tenant
            && created.receipt.scope().owner_id() == producer.id,
        "actor-owned A5 receipt scope owner/tenant differs"
    );
    let snapshot_id = created.receipt.snapshot_id();
    let pin_id = created.receipt.pin_id();
    let stage = Stage { name: "a5_read", sequence: None, revision: verified.gate.revision() };
    let read = PgServingSnapshotMetadata
        .read_actor_owned(
            &db.pool,
            producer,
            ServingSnapshotRead {
                owner: owner.to_owned(),
                name: name.to_owned(),
                snapshot_id,
            },
            store.backend_identity(),
            deadline(),
        )
        .await
        .map_err(|error| stage.tag(error))?;
    ensure!(
        read.scope().tenant_id() == verified.tenant
            && read.scope().owner_id() == producer.id
            && read.snapshot_id() == snapshot_id
            && read.pin_id() == pin_id,
        "actor-owned A5 read scope/identity differs"
    );
    ensure!(read.pack_mode() == "pack_verified", "source snapshot is not pack_verified");
    ensure!(read.pack_count() > 0, "source snapshot has no registered pack membership");
    Ok(ProducerSnapshot { snapshot_id, pin_id, read })
}

/// Release the actor-owned A5 pin through the production facade. This is the
/// source-pin lifecycle, independent of the retained root/snapshot descriptors
/// that continue to declare every registration after release.
pub async fn release_snapshot_pin(
    db: &Db,
    store: &BlobStore,
    producer: &Identity,
    owner: &str,
    name: &str,
    snapshot: &ProducerSnapshot,
    gate: &CoreGateVersion,
) -> Result<MetadataPinOutcome> {
    let stage = Stage { name: "release_pin", sequence: None, revision: gate.revision() };
    PgServingSnapshotMetadata
        .release_actor_owned(
            &db.pool,
            producer,
            ServingSnapshotRelease {
                owner: owner.to_owned(),
                name: name.to_owned(),
                snapshot_id: snapshot.snapshot_id,
                idempotency_key: "format22-producer-a5-release".into(),
                expected_generation: snapshot.read.pin_generation(),
                reason: PinReleaseReason::ClientDone,
            },
            store.backend_identity(),
            deadline(),
        )
        .await
        .map_err(|error| stage.tag(error))
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
