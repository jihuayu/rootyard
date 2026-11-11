//! Verified pack registration and one transient serving-read capture.
use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::Pool;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db::Identity;
use rootyard::ref_store::core::MetadataSnapshotScope;
use rootyard::ref_store::core::pack_commit::{PackCommitPlan, RegisteredPack};
use rootyard::ref_store::core::pack_snapshot::PgServingReads;
use rootyard::ref_store::{CoreGateVersion, MetadataPinPurpose, PgRefStoreCore, VersionCheck};
use uuid::Uuid;

use super::super::db::{Db, deadline};
use super::super::git::GitRepo;
use super::super::{pack, pack_plan, repo};
use super::{PACKS, SERVING_READ_LEASE_SECONDS, SHA1};

pub(super) async fn current_gate(pool: &Pool, repo: Uuid, tenant: Uuid) -> Result<CoreGateVersion> {
    let mut client = pool.get().await?;
    match PgRefStoreCore.check_version(&mut client, repo, tenant, None, deadline()).await? {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => Ok(version),
        VersionCheck::Unknown => Err(anyhow!("core gate is missing")),
    }
}

/// Register `PACKS` verified packs as `producer` on the provisioned repository.
pub(super) async fn packs(
    db: &Db,
    store: &BlobStore,
    target: &repo::Existing,
    git: &std::path::Path,
    fixture: &GitRepo,
    producer: &Identity,
) -> Result<(Vec<RegisteredPack>, PackCommitPlan, String)> {
    let mut gate = target.gate.clone();
    let first = fixture.build_commit("file.txt", b"root fixture\n", "format22 main").await?;
    fixture.update_ref("refs/heads/main", &first).await?;
    let mut head = first;
    let mut registrations: Vec<RegisteredPack> = Vec::new();
    let mut last_plan = None;
    for sequence in 1..=PACKS {
        let refs = if sequence == 1 {
            vec![pack::main_update(SHA1, None, &head)?]
        } else {
            let next = fixture
                .build_commit("advance.txt", format!("pack {sequence}\n").as_bytes(), "format22 advance")
                .await?;
            fixture.update_ref("refs/heads/main", &next).await?;
            let refs = vec![pack::main_update(SHA1, Some(&head), &next)?];
            head = next;
            refs
        };
        // Pack after the fixture ref reaches this sequence's target, so the
        // registered pack contains the commit the plan names.
        let files = fixture.pack_all(&format!("format22-{sequence}")).await?;
        // Diagnostic only: the sequence, a fixed stage label and the gate
        // revisions (no ids, refs or request contents) precede the unchanged
        // typed error, so a bare rejection names the stage it escaped from.
        let expected_revision = gate.revision();
        let input = pack_plan::DraftInput { repo: target.repo, tenant: target.tenant, owner: producer.id, sequence };
        let draft = pack_plan::draft(db, input, &gate, refs, std::slice::from_ref(&files)).await.map_err(|error| {
            anyhow!("sequence {sequence} stage=draft expected_revision={expected_revision}: {error:#}")
        })?;
        // The provisioned repository is already under the irreversible
        // decision-required fence, so its packs commit through the same
        // decision-gated pipeline the serving first push uses.
        let new = repo::decided_pair(db, store, git, &draft, &files, producer, sequence).await.map_err(|error| {
            anyhow!("sequence {sequence} stage=decided_pair expected_revision={expected_revision}: {error:#}")
        })?;
        registrations.extend(new);
        gate = current_gate(&db.pool, target.repo, target.tenant).await.map_err(|error| {
            anyhow!("sequence {sequence} stage=current_gate expected_revision={expected_revision}: {error:#}")
        })?;
        last_plan = Some(draft.plan);
    }
    ensure!(head == fixture.rev_parse("refs/heads/main").await?, "fixture HEAD changed during packing");
    Ok((registrations, last_plan.ok_or_else(|| anyhow!("no pack was planned"))?, head))
}

/// One secret-free view of the transient serving read.
pub(super) struct ServingRead {
    pub(super) pin_id: Uuid,
    pub(super) pack_count: i64,
}

/// Capture one nonempty transient serving read for `reader` through the real
/// `PgServingReads::capture` (strict serving authority, the live Blob backend
/// identity of `store`, the verified gate realm and a bounded 300s lease).
///
/// Nothing here writes SQL: the header, refs and every pack/artifact descriptor
/// are produced by the production capture, so the later backup loads and decodes
/// exactly those rows. The capture is deliberately left unreleased (see `run`).
pub(super) async fn serving_read_capture(
    db: &Db,
    store: &BlobStore,
    verified: &pack::Verified,
    reader: &Identity,
) -> Result<ServingRead> {
    let scope = MetadataSnapshotScope::new(
        verified.repo,
        verified.tenant,
        reader.id,
        MetadataPinPurpose::Verification,
        verified.gate.object_format(),
        verified.gate.history_incarnation(),
        verified.gate.authority_epoch(),
        verified.gate.group_epoch(),
    )
    .map_err(|error| anyhow!("serving read scope rejected: {error:?}"))?;
    ensure!(scope.owner_id() == reader.id, "the serving read is not owned by the reader");
    let capture = PgServingReads
        .capture(&db.pool, &scope, store.backend_identity(), SERVING_READ_LEASE_SECONDS, deadline())
        .await
        .map_err(|error| anyhow!("real serving read capture refused: {error:?}"))?;
    ensure!(!capture.is_empty(), "the serving read capture is a checked empty repository");
    let captured = capture.registered_snapshot().ok_or_else(|| anyhow!("serving read has no registered snapshot"))?;
    let pin_id = capture.pin_id().ok_or_else(|| anyhow!("serving read capture minted no pin"))?;
    ensure!(pin_id == captured.pin_id(), "serving read pin differs from its snapshot");
    let scope = captured.scope();
    ensure!(
        scope.repository_id() == verified.repo
            && scope.tenant_id() == verified.tenant
            && scope.owner_id() == reader.id
            && scope.purpose() == MetadataPinPurpose::Verification,
        "the captured serving read scope differs from the requested repo/tenant/reader"
    );
    let pack_count = captured.pack_count();
    ensure!(pack_count == PACKS, "the serving read captured {pack_count} pack descriptors, expected {PACKS}");
    ensure!(
        captured.snapshot_digest_hex().len() == 64 && captured.membership_digest_hex().len() == 64,
        "the serving read digest is malformed"
    );
    Ok(ServingRead { pin_id, pack_count })
}
