//! Real PostgreSQL 17 + S3-compatible Blob + native Git fixture for the
//! crate-private slot-zero retirement and slot-one rotation foundation.
//!
//! The production primitives are crate-private, so the only way to exercise the
//! actual `admit_slot_zero_in_tx`, authorized refusal, terminal mirror and
//! `rotate_slot_one_in_tx` methods without changing visibility is this
//! `#[cfg(test)]` library module. The A3/A4/A5 support below is the already
//! reviewed `tests/retention_roots_support` fixture, path-included unchanged.
//! `extern crate self as rootyard` in `src/lib.rs` makes its `rootyard::`
//! imports resolve inside the crate's own test build.
//!
//! Every case is `#[ignore]`, hard-fails when PostgreSQL, the Blob profile, the
//! trusted Git binary or the disposable-bucket attestation is absent, and never
//! skips once explicitly invoked. The test writes no gate, authority, decision,
//! terminal, approval or event row directly: P0 is admitted and staged, an
//! unrelated ref B advances the gate through a real authorized P1 commit, P0 is
//! durably refused and mirrored as retirement-required without wrapper mutation,
//! and P2 re-executes the identical P0 wire ref command with a fresh private
//! identity/sequence/plan/proof/registration before a real authorized commit and
//! A5 snapshot. Collaboration uses separate ref A for P0/P2 and ref B for P1 so
//! the retried wire command remains exactly the original one.
//!
//! Run explicitly (with an owned disposable Blob bucket/prefix):
//!
//! ```text
//! ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB=1 \
//! ROOTYARD_TEST_DATABASE_URL=postgresql://... \
//! ROOTYARD_BLOB_DRIVER=opendal ROOTYARD_BLOB_SERVICE=s3 \
//! ROOTYARD_BLOB_ENDPOINT=... ROOTYARD_BLOB_BUCKET=... ROOTYARD_BLOB_REGION=... \
//! ROOTYARD_BLOB_ACCESS_KEY_ID=... ROOTYARD_BLOB_SECRET_ACCESS_KEY=... \
//! ROOTYARD_BLOB_ROOT=slot-one-proof-<unique> ROOTYARD_TEST_GIT=/absolute/git \
//! cargo test --locked --no-default-features --lib \
//!   ref_store::pg::slot_one::tests::native::slot_one_rotation_replays_identical_wire_command_on_real_a3_a4_a5 \
//!   -- --ignored --exact --test-threads=1
//! ```
//!
//! The smaller `slot_zero_rejection_selects_retirement_on_real_a3_a4` case covers
//! the same P0/P1/refusal/mirror prefix and can be selected by its exact name.

#![allow(clippy::too_many_arguments)]
#![allow(dead_code)]

#[path = "../../../../../tests/retention_roots_support/common.rs"]
mod common;
#[path = "../../../../../tests/retention_roots_support/db.rs"]
mod db;
#[path = "../../../../../tests/retention_roots_support/git.rs"]
mod git;
#[path = "../../../../../tests/retention_roots_support/pack.rs"]
mod pack;
#[path = "../../../../../tests/retention_roots_support/serving.rs"]
mod serving;

use anyhow::{Context, Result, anyhow, bail, ensure};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db::{Identity, Repository};
use rootyard::ref_store::{
    CommitMode, CommitRejectCode, CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, OperationIdentity,
    OperationLookup, OperationRecord, OperationState, RefCommitResult, RefName, RefPrecondition, RefTarget, RefUpdate,
    RequestDigest, TerminalKind,
    core::pack_commit::{
        AuthorizedCommitMode, AuthorizedCommitReceipt, CapturedRef, ContentDigest, PackArtifactRole,
        PackCommitBaseline, PackCommitError, PackCommitExpectation, PackCommitPlan, PackCommitRejectCode,
        PackCommitScope, PackCommitTerminal, PackMembershipEntry, PackPendingToken, PgAuthorizedCommit, PgPackCommit,
        PlannedArtifact, PlannedPack, PrepareOutcome,
    },
    pg::{
        PgRefStore,
        public_attempt::{PublicAttemptLookup, PublicAttemptRequest},
        public_terminal::{PublicAttemptRetirement, PublicAttemptTerminalOutcome},
        slot_one::{SlotOneRotationReceipt, SlotOneRotationRequest},
        slot_zero::{SlotZeroAdmissionRequest, SlotZeroReceipt},
    },
};
use std::path::Path;
use uuid::Uuid;

use db::deadline;

const REF_RETRY: &str = "refs/heads/retry";
const REF_SIDE: &str = "refs/heads/side";
const SLOT_ZERO_LANE: &str = "slot-zero-rotation";
const WIRE_DOMAIN: &str = "rootyard-test-wire-ref-command-v1";
const WIRE_BODY: &[u8] = b"identical logical receive-pack ref update";
const OWNED_BLOB_OPT_IN: &str = "ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB";

/// The durable state through P0 admission, P0 artifact staging, the real P1
/// authorized advance, the production superseded refusal and the read-only
/// retirement selection. The wrapper is still pending slot zero here.
struct Retired {
    verified: pack::Verified,
    actor: Identity,
    repository: Repository,
    retry_oid: String,
    side_oid: String,
    p0_files: git::PairFiles,
    public: PublicAttemptRequest,
    admission: SlotZeroReceipt,
    plan: PackCommitPlan,
    retirement: PublicAttemptRetirement,
    gate: CoreGateVersion,
}

#[tokio::test]
#[ignore = "requires real PostgreSQL 17, S3/Garage Blob and native Git"]
async fn slot_zero_rejection_selects_retirement_on_real_a3_a4() -> Result<()> {
    require_owned_disposable_blob_fixture()?;
    let db = db::Db::setup().await?;
    let outcome: Result<()> = async {
        require_postgres_17(&db).await?;
        let store = common::open_store()?;
        let git = git::git_binary()?;
        let retired = retire_p0(&db, &store, &git).await?;

        ensure!(
            retired.gate.revision() == retired.verified.gate.revision() + 1,
            "P1 did not advance the gate exactly one revision"
        );
        ensure!(
            retired.retirement.event_revision == retired.gate.revision(),
            "retirement event revision differs from the advanced gate"
        );
        ensure!(
            stored_ref(&db, retired.repository.id, REF_RETRY).await?.is_none(),
            "the refused P0 wire command became visible on ref A"
        );
        ensure!(
            stored_ref(&db, retired.repository.id, REF_SIDE).await?.as_deref() == Some(retired.side_oid.as_str()),
            "the real P1 ref B advance is not visible"
        );
        ensure!(
            stored_ref(&db, retired.repository.id, "refs/heads/main").await?.as_deref()
                == Some(retired.verified.commit_oid.as_str()),
            "P1 changed the unrelated main ref"
        );
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL 17, S3/Garage Blob and native Git"]
async fn slot_one_rotation_replays_identical_wire_command_on_real_a3_a4_a5() -> Result<()> {
    require_owned_disposable_blob_fixture()?;
    let db = db::Db::setup().await?;
    let outcome: Result<()> = async {
        require_postgres_17(&db).await?;
        let store = common::open_store()?;
        let git = git::git_binary()?;
        let retired = retire_p0(&db, &store, &git).await?;
        let p0_publication = publication_for(&db, retired.repository.id, retired.admission.private_id).await?;

        let (plan, rotation, gate) = rotate_and_commit(&db, &store, &git, &retired).await?;
        assert_a5_after_rotation(&db, &store, &retired, &plan).await?;
        assert_no_registry_promotion(&db, &retired, &plan, &rotation, &p0_publication).await?;
        assert_current_pending_wrapper_gap(&db, &retired).await?;
        ensure!(gate.revision() == retired.gate.revision() + 1, "P2 did not advance the gate exactly one revision");
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

/// Admit P0 for the exact ref A wire command, stage its real A3/A4 artifacts,
/// advance the gate through a separate authorized P1 ref B command, refuse P0
/// through the production superseded writer, and select the retirement through
/// the production mirror without mutating the pending wrapper.
async fn retire_p0(db: &db::Db, store: &BlobStore, git: &Path) -> Result<Retired> {
    let (verified, actor, repository) = serving::verify_new_serving(db, store, git, "slot-one-native").await?;
    let gate0 = db::gate_version(&db.pool, repository.id, actor.id).await?;
    ensure!(gate0.revision() == verified.gate.revision(), "initial gate revision differs from the serving receipt");
    let format = gate0.object_format();
    ensure!(format == GitObjectFormat::Sha1, "the shared serving fixture must provision a sha1 repository");
    let main_oid = verified.commit_oid.clone();

    let retry_oid =
        child_commit(&verified.fixture, &main_oid, "retry.txt", b"slot-zero retry\n", "slot zero retry").await?;
    let side_oid = child_commit(&verified.fixture, &main_oid, "side.txt", b"side advance\n", "side advance").await?;
    verified.fixture.update_ref(REF_RETRY, &retry_oid).await?;
    let p0_files = verified.fixture.pack_all("slot-zero-p0").await?;
    verified.fixture.update_ref(REF_SIDE, &side_oid).await?;
    let p1_files = verified.fixture.pack_all("slot-zero-p1").await?;

    let lane = IssuerLane::new(SLOT_ZERO_LANE)?;
    let refs0 = vec![ref_update(format, REF_RETRY, None, &retry_oid)?];
    let wire0 = wire_digest(format, REF_RETRY, None, &retry_oid, CommitMode::Atomic);
    let public = PublicAttemptRequest {
        repository_id: repository.id,
        admission_owner_id: actor.id,
        issuer_id: actor.id,
        public_id: Uuid::new_v4(),
        wire_digest: wire0,
        request_mode: CommitMode::Atomic,
        backend_identity: store.backend_identity().as_hex().to_owned(),
        object_format: format,
        history_incarnation: gate0.history_incarnation(),
        authority_epoch: gate0.authority_epoch(),
        group_epoch: gate0.group_epoch(),
        restore_incarnation: db::cluster_incarnation(&db.pool).await?,
    };
    let private0 = Uuid::new_v4();
    let baseline0 = capture_baseline(db, repository.id, actor.id).await?;
    let (admission, plan) =
        admit_slot_zero(db, &public, private0, &lane, &baseline0, refs0, std::slice::from_ref(&p0_files)).await?;

    // Real A3 protected upload + real A4 registration. These artifacts remain
    // durable but are never promoted: P0 does not commit.
    stage(db, store, &plan, &p0_files).await?;
    ensure!(plan.packs().len() == 1, "P0 fixture plan must have one pack");
    let p0_publication = publication_for(db, repository.id, private0).await?;
    ensure!(
        p0_publication.parent_digest == plan.parent_digest().as_hex(),
        "P0 A4 registration parent digest differs from the admitted plan"
    );
    ensure!(p0_publication.pack_id == plan.packs()[0].pack_id(), "P0 A4 registration pack id differs");
    ensure!(p0_publication.registration_id == plan.packs()[0].registration_id(), "P0 A4 registration id differs");

    let gate_before_p1 = db::gate_version(&db.pool, repository.id, actor.id).await?;
    ensure!(
        gate_before_p1.revision() == gate0.revision(),
        "P0 admission advanced the gate before the unrelated P1 advance"
    );
    let draft1 = pack::draft(
        db,
        repository.id,
        actor.id,
        2,
        &gate_before_p1,
        vec![ref_update(format, REF_SIDE, None, &side_oid)?],
        std::slice::from_ref(&p1_files),
    )
    .await?;
    stage(db, store, &draft1.plan, &p1_files).await?;
    let receipt1 = authorized_commit(db, store, git, &actor, draft1.plan.clone()).await?;
    let gate1 = db::gate_version(&db.pool, repository.id, actor.id).await?;
    ensure!(
        gate1.revision() == receipt1.terminal.revision && gate1.revision() == gate0.revision() + 1,
        "P1 authorized commit did not advance the gate exactly once"
    );
    ensure!(
        stored_ref(db, repository.id, "refs/heads/main").await?.as_deref() == Some(main_oid.as_str()),
        "P1 changed the unrelated main ref"
    );
    ensure!(
        stored_ref(db, repository.id, REF_SIDE).await?.as_deref() == Some(side_oid.as_str()),
        "P1 ref B is not visible"
    );
    ensure!(stored_ref(db, repository.id, REF_RETRY).await?.is_none(), "P0 became visible before any commit");

    let token = PackPendingToken::established(repository.id, actor.id, private0, *plan.parent_digest())?;
    let authorized = PgAuthorizedCommit::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("authorized adapter rejected the slot-zero fixture: {error:?}"))?;
    let terminal = authorized
        .reject_superseded_serving(&db.pool, &token, &plan, &actor, wire0, deadline())
        .await
        .map_err(|error| anyhow!("authorized superseded refusal failed ({}): {error:?}", error.code()))?
        .ok_or_else(|| anyhow!("authorized superseded refusal observed no advanced gate"))?;
    ensure!(terminal.kind == TerminalKind::Rejected, "P0 superseded terminal is not a rejection");
    ensure!(terminal.revision == gate1.revision(), "P0 rejection did not observe the advanced gate");
    ensure!(terminal.registrations.is_empty(), "P0 superseded rejection names active registrations");
    let rejection = terminal.rejection.as_ref().ok_or_else(|| anyhow!("P0 rejection has no typed reason"))?;
    ensure!(rejection.code == "revision_mismatch", "P0 rejection code is not revision_mismatch");
    ensure!(
        terminal.refs.iter().any(|result| matches!(
            result,
            RefCommitResult::NotApplied { name, reason: CommitRejectCode::OldOidMismatch } if name.as_str() == REF_RETRY
        )),
        "P0 rejection did not leave the retried ref unapplied"
    );

    let record = operation_record(db, repository.id, private0).await?;
    ensure!(record.state() == OperationState::Rejected, "P0 operation is not durably rejected");
    let durable = PackCommitTerminal::from_terminal_result(
        record.terminal_result().ok_or_else(|| anyhow!("P0 rejected operation has no terminal result"))?,
    )
    .map_err(|error| anyhow!("P0 durable terminal is not a pack commit terminal: {error:?}"))?;
    ensure!(durable.registrations.is_empty(), "P0 durable rejection names active registrations");

    let wrapper_before = wrapper_json(db, repository.id, public.public_id).await?;
    let retirement = retirement_required(db, &public, private0).await?;
    let wrapper_after = wrapper_json(db, repository.id, public.public_id).await?;
    ensure!(wrapper_before == wrapper_after, "the retirement selection mutated the pending wrapper");
    ensure!(
        retirement.event_revision == gate1.revision(),
        "selected retirement does not name the current advanced gate"
    );
    ensure!(
        operation_record(db, repository.id, private0).await?.state() == OperationState::Rejected,
        "the mirror selection changed the durable P0 terminal"
    );

    Ok(Retired {
        verified,
        actor,
        repository,
        retry_oid,
        side_oid,
        p0_files,
        public,
        admission,
        plan,
        retirement,
        gate: gate1,
    })
}

async fn admit_slot_zero(
    db: &db::Db,
    public: &PublicAttemptRequest,
    private_id: Uuid,
    lane: &IssuerLane,
    baseline: &PackCommitBaseline,
    refs: Vec<RefUpdate>,
    files: &[git::PairFiles],
) -> Result<(SlotZeroReceipt, PackCommitPlan)> {
    let request = SlotZeroAdmissionRequest {
        repository_id: public.repository_id,
        admission_owner_id: public.admission_owner_id,
        issuer_id: public.issuer_id,
        lane: lane.clone(),
        public_id: public.public_id,
        private_id,
        wire_digest: public.wire_digest,
        request_mode: public.request_mode,
        backend_identity: public.backend_identity.clone(),
        object_format: public.object_format,
        history_incarnation: public.history_incarnation,
        authority_epoch: public.authority_epoch,
        group_epoch: public.group_epoch,
        restore_incarnation: public.restore_incarnation,
    };

    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    let mut built = None;
    let admission = PgRefStore
        .admit_slot_zero_in_tx(
            tx,
            &request,
            |preview| {
                if preview.base_revision() != baseline.gate().revision() {
                    return Err(PackCommitError::Invalid(
                        "slot zero preview gate revision drifted from the captured baseline",
                    ));
                }
                let plan = plan_from_baseline(
                    baseline,
                    request.admission_owner_id,
                    preview.sequence(),
                    request.private_id,
                    &request.lane,
                    refs.clone(),
                    files,
                )?;
                built = Some(plan.clone());
                Ok(plan)
            },
            deadline(),
        )
        .await
        .map_err(|error| anyhow!("slot zero admission aborted: {error:?}"))?;
    let (tx, result) = admission.into_parts();
    let receipt = result.map_err(|error| anyhow!("slot zero admission refused: {error:?}"))?;
    let plan = built.ok_or_else(|| anyhow!("slot zero admission did not build a plan"))?;
    ensure!(!receipt.replayed, "fresh slot zero admission replayed");
    ensure!(receipt.state == OperationState::Pending, "slot zero receipt is not pending");
    ensure!(receipt.public_id == public.public_id, "slot zero receipt public id differs");
    ensure!(receipt.private_id == private_id, "slot zero receipt private id differs");
    ensure!(plan.identity().operation_id() == private_id, "slot zero plan private id differs");
    ensure!(plan.parent_digest() == &receipt.plan_digest, "slot zero plan digest differs from the receipt");
    tx.commit().await?;
    Ok((receipt, plan))
}

fn plan_from_baseline(
    baseline: &PackCommitBaseline,
    tenant: Uuid,
    sequence: i64,
    private_id: Uuid,
    lane: &IssuerLane,
    refs: Vec<RefUpdate>,
    files: &[git::PairFiles],
) -> Result<PackCommitPlan, PackCommitError> {
    let gate = baseline.gate();
    let mut planned = Vec::with_capacity(files.len());
    for file in files {
        let (pack_sha, pack_len) = git::digest_file(&file.pack)
            .map_err(|_| PackCommitError::Invalid("fixture pack digest could not be read"))?;
        let (idx_sha, idx_len) = git::digest_file(&file.idx)
            .map_err(|_| PackCommitError::Invalid("fixture idx digest could not be read"))?;
        planned.push(PlannedPack::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pack_sha)?, pack_len)?,
            PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(idx_sha)?, idx_len)?,
        )?);
    }
    let scope = PackCommitScope::new(
        gate.repository_id(),
        tenant,
        tenant,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let identity = OperationIdentity::new(
        gate.repository_id(),
        tenant,
        lane.clone(),
        sequence,
        private_id,
        RequestDigest::from_bytes([0; 32]),
    )?;
    let expectation = PackCommitExpectation::new(gate.revision(), *gate.digest(), baseline.mode())?;
    let old_entries = baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?;
    PackCommitPlan::new(
        scope,
        identity,
        expectation,
        HeadUpdate::Keep,
        refs,
        baseline.membership_digest(),
        old_entries,
        planned,
    )
}

async fn stage(db: &db::Db, store: &BlobStore, plan: &PackCommitPlan, files: &git::PairFiles) -> Result<()> {
    let publication = pack::publish(db, store, plan, files).await?;
    let pack_id = plan.packs().first().ok_or_else(|| anyhow!("fixture plan has no planned pack"))?.pack_id();
    pack::register(db, plan, pack_id, &publication).await?;
    Ok(())
}

async fn authorized_commit(
    db: &db::Db,
    store: &BlobStore,
    git: &Path,
    actor: &Identity,
    plan: PackCommitPlan,
) -> Result<AuthorizedCommitReceipt> {
    let mode = match plan.commit_mode() {
        CommitMode::Atomic => AuthorizedCommitMode::Atomic,
        CommitMode::AcceptedSubset => AuthorizedCommitMode::AcceptedSubset,
    };
    let authorized = PgAuthorizedCommit::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("authorized adapter rejected the fixture: {error:?}"))?;
    let prepared = match authorized
        .prepare(&db.pool, plan, deadline())
        .await
        .map_err(|error| anyhow!("authorized prepare refused ({}): {error:?}", error.code()))?
    {
        PrepareOutcome::Prepared(prepared) => prepared,
        PrepareOutcome::Replayed(_) => return Err(anyhow!("authorized prepare replayed a fresh operation")),
    };
    let selection = authorized
        .select(&db.pool, *prepared, actor, mode, deadline())
        .await
        .map_err(|error| anyhow!("authorized select refused ({}): {error:?}", error.code()))?;
    let verified = authorized
        .verify(selection, deadline())
        .await
        .map_err(|error| anyhow!("authorized verify refused ({}): {error:?}", error.code()))?;
    let receipt = authorized
        .commit(&db.pool, &verified, deadline())
        .await
        .map_err(|error| anyhow!("authorized commit refused ({}): {error:?}", error.code()))?;
    ensure!(
        receipt.is_committed() && !receipt.replayed,
        "authorized fixture commit was not a fresh committed terminal"
    );
    Ok(receipt)
}

async fn retirement_required(
    db: &db::Db,
    public: &PublicAttemptRequest,
    private_id: Uuid,
) -> Result<PublicAttemptRetirement> {
    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    let record = match PgRefStore
        .get(&tx, public.repository_id, private_id, deadline())
        .await
        .map_err(|error| anyhow!("P0 operation lookup failed: {error:?}"))?
    {
        OperationLookup::Known(record) => record,
        _ => bail!("P0 operation is not visible to the terminal mirror"),
    };
    ensure!(record.state() == OperationState::Rejected, "P0 operation is not durably rejected");
    let outcome = PgRefStore
        .mirror_public_attempt_terminal_in_tx(&tx, public, &record, deadline())
        .await
        .map_err(|error| anyhow!("public terminal mirror failed: {error:?}"))?;
    let retirement = match outcome {
        PublicAttemptTerminalOutcome::RetirementRequired(retirement) => retirement,
        PublicAttemptTerminalOutcome::Mirrored(receipt) => {
            bail!("terminal mirror published instead of selecting retirement: {receipt:?}")
        }
    };
    tx.rollback().await?;
    Ok(retirement)
}

async fn operation_record(db: &db::Db, repository_id: Uuid, operation_id: Uuid) -> Result<OperationRecord> {
    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    let lookup = PgRefStore
        .get(&tx, repository_id, operation_id, deadline())
        .await
        .map_err(|error| anyhow!("operation lookup failed: {error:?}"))?;
    tx.rollback().await?;
    match lookup {
        OperationLookup::Known(record) => Ok(record),
        _ => bail!("operation is not visible"),
    }
}

async fn wrapper_json(db: &db::Db, repository_id: Uuid, public_id: Uuid) -> Result<serde_json::Value> {
    let row = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT to_jsonb(w) FROM ref_store_public_operations w WHERE w.repository_id=$1 AND w.public_id=$2",
            &[&repository_id, &public_id],
        )
        .await?;
    Ok(row.get(0))
}

async fn stored_ref(db: &db::Db, repository_id: Uuid, name: &str) -> Result<Option<String>> {
    let name = name.to_owned();
    let row = db
        .pool
        .get()
        .await?
        .query_opt(
            "SELECT oid FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name=$2",
            &[&repository_id, &name],
        )
        .await?;
    Ok(row.map(|row| row.get(0)))
}

async fn capture_baseline(db: &db::Db, repository_id: Uuid, tenant_id: Uuid) -> Result<PackCommitBaseline> {
    let mut client = db.pool.get().await?;
    PgPackCommit
        .capture_baseline(&mut client, repository_id, tenant_id, deadline())
        .await
        .map_err(|error| anyhow!("baseline capture refused: {error:?}"))
}

async fn child_commit(
    fixture: &git::GitRepo,
    parent: &str,
    file: &str,
    content: &[u8],
    message: &str,
) -> Result<String> {
    let blob = fixture.add_blob(content).await?;
    let entry = format!("100644 blob {blob}\t{file}\n");
    let tree = git::GitRepo::text(&fixture.run(&["mktree"], Some(entry.as_bytes())).await?)?;
    git::GitRepo::text(&fixture.run(&["commit-tree", tree.as_str(), "-p", parent, "-m", message], None).await?)
}

fn ref_update(format: GitObjectFormat, name: &str, old: Option<&str>, new: &str) -> Result<RefUpdate> {
    let precondition = match old {
        Some(value) => RefPrecondition::Present(GitOid::parse(format, value)?),
        None => RefPrecondition::Absent,
    };
    Ok(RefUpdate::new(RefName::branch(name)?, precondition, RefTarget::Oid(GitOid::parse(format, new)?)))
}

fn wire_digest(format: GitObjectFormat, name: &str, old: Option<&str>, new: &str, mode: CommitMode) -> RequestDigest {
    let old = old.unwrap_or_default();
    let parts: [&[u8]; 6] = [
        format.as_str().as_bytes(),
        name.as_bytes(),
        old.as_bytes(),
        new.as_bytes(),
        mode.as_str().as_bytes(),
        WIRE_BODY,
    ];
    RequestDigest::of(WIRE_DOMAIN, &parts)
}

async fn rotate_and_commit(
    db: &db::Db,
    store: &BlobStore,
    git: &Path,
    retired: &Retired,
) -> Result<(PackCommitPlan, SlotOneRotationReceipt, CoreGateVersion)> {
    let format = retired.verified.gate.object_format();
    let refs = vec![ref_update(format, REF_RETRY, None, &retired.retry_oid)?];
    ensure!(refs.as_slice() == retired.plan.refs(), "P2 changed the exact wire ref command");
    let wire = wire_digest(format, REF_RETRY, None, &retired.retry_oid, CommitMode::Atomic);
    ensure!(wire == retired.public.wire_digest, "P2 wire digest differs from the P0 logical incoming body");

    let baseline = capture_baseline(db, retired.repository.id, retired.verified.tenant).await?;
    ensure!(
        baseline.gate().revision() == retired.gate.revision() && baseline.gate().digest() == retired.gate.digest(),
        "rotation baseline is not the advanced P1 gate"
    );
    let rotation = SlotOneRotationRequest { public: retired.public.clone(), retirement: retired.retirement.clone() };
    let lane = IssuerLane::new(SLOT_ZERO_LANE)?;

    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    let mut built = None;
    let outcome = PgRefStore
        .rotate_slot_one_in_tx(
            tx,
            &rotation,
            |preview| {
                if preview.base_revision() != baseline.gate().revision() {
                    return Err(PackCommitError::Invalid(
                        "slot one preview gate revision drifted from the captured baseline",
                    ));
                }
                let plan = plan_from_baseline(
                    &baseline,
                    retired.verified.tenant,
                    preview.sequence(),
                    preview.private_id(),
                    &lane,
                    refs.clone(),
                    std::slice::from_ref(&retired.p0_files),
                )?;
                built = Some(plan.clone());
                Ok(plan)
            },
            deadline(),
        )
        .await
        .map_err(|error| anyhow!("slot one rotation aborted: {error:?}"))?;
    let (tx, result) = outcome.into_parts();
    let receipt = result.map_err(|error| anyhow!("slot one rotation refused: {error:?}"))?;
    let plan = built.ok_or_else(|| anyhow!("slot one rotation did not build a plan"))?;

    ensure!(!receipt.replayed, "fresh slot one rotation replayed");
    ensure!(receipt.state == OperationState::Pending, "slot one receipt is not pending");
    ensure!(receipt.public_id == retired.public.public_id, "slot one receipt public id differs");
    ensure!(receipt.private_id != retired.admission.private_id, "slot one reused the retired private id");
    ensure!(receipt.retired_private_id == retired.admission.private_id, "slot one receipt retired private id differs");
    ensure!(receipt.retired_event_id == retired.retirement.event_id, "slot one receipt retired event id differs");
    ensure!(
        receipt.retired_event_revision == retired.retirement.event_revision,
        "slot one receipt retired event revision differs"
    );
    ensure!(receipt.sequence > retired.admission.sequence, "slot one sequence did not advance the retired lane");
    ensure!(receipt.base_revision == retired.gate.revision(), "slot one base revision is not the current gate");
    ensure!(receipt.plan_digest != retired.admission.plan_digest, "slot one reused the retired plan digest");
    ensure!(receipt.proof_digest != retired.admission.proof_digest, "slot one reused the retired proof digest");
    ensure!(receipt.wire_digest == retired.public.wire_digest, "slot one rewrote the logical incoming wire body");
    ensure!(plan.identity().lane().as_str() == SLOT_ZERO_LANE, "slot one changed issuer lane");
    ensure!(plan.identity().sequence() == receipt.sequence, "slot one plan sequence differs from the receipt");
    ensure!(plan.identity().operation_id() == receipt.private_id, "slot one plan private id differs from the receipt");
    ensure!(plan.parent_digest() == &receipt.plan_digest, "slot one plan digest differs from the receipt");
    ensure!(plan.refs() == retired.plan.refs(), "slot one plan changed the exact wire ref command");
    ensure!(plan.packs().len() == 1 && retired.plan.packs().len() == 1, "fixture plans must each have one pack");
    ensure!(plan.packs()[0].pack_id() != retired.plan.packs()[0].pack_id(), "slot one reused the retired pack id");
    ensure!(
        plan.packs()[0].registration_id() != retired.plan.packs()[0].registration_id(),
        "slot one reused the retired registration id"
    );
    tx.commit().await?;

    match lookup_public(db, &retired.public).await? {
        PublicAttemptLookup::Pending(evidence) => {
            ensure!(evidence.current.slot == 1, "rotated current attempt is not slot one");
            ensure!(evidence.current.private_id == receipt.private_id, "rotated current private id differs");
            ensure!(evidence.current.state == OperationState::Pending, "rotated current attempt is not pending");
            let retired_attempt = evidence
                .retired
                .as_ref()
                .ok_or_else(|| anyhow!("rotated wrapper has no retired slot-zero evidence"))?;
            ensure!(retired_attempt.slot == 0, "rotated retired attempt is not slot zero");
            ensure!(
                retired_attempt.private_id == retired.admission.private_id,
                "rotated retired private id differs from P0"
            );
            ensure!(retired_attempt.state == OperationState::Rejected, "rotated retired attempt is not rejected");
        }
        other => bail!("rotated wrapper is not pending slot one: {other:?}"),
    }

    let replayed = replay_rotation(db, &rotation).await?;
    ensure!(replayed.replayed, "exact pending rotation was not a replay");
    ensure!(replayed.private_id == receipt.private_id, "rotation replay private id differs");
    ensure!(replayed.plan_digest == receipt.plan_digest, "rotation replay plan digest differs");
    ensure!(replayed.proof_digest == receipt.proof_digest, "rotation replay proof digest differs");
    ensure!(replayed.sequence == receipt.sequence, "rotation replay sequence differs");
    ensure!(replayed.base_revision == receipt.base_revision, "rotation replay base revision differs");

    stage(db, store, &plan, &retired.p0_files).await?;
    let committed = authorized_commit(db, store, git, &retired.actor, plan.clone()).await?;
    let gate = db::gate_version(&db.pool, retired.repository.id, retired.actor.id).await?;
    ensure!(
        gate.revision() == committed.terminal.revision && gate.revision() == retired.gate.revision() + 1,
        "P2 authorized commit did not advance the gate exactly once"
    );
    ensure!(
        stored_ref(db, retired.repository.id, "refs/heads/main").await?.as_deref()
            == Some(retired.verified.commit_oid.as_str()),
        "P2 changed the unrelated main ref"
    );
    ensure!(
        stored_ref(db, retired.repository.id, REF_SIDE).await?.as_deref() == Some(retired.side_oid.as_str()),
        "P2 changed the unrelated P1 ref B"
    );
    ensure!(
        stored_ref(db, retired.repository.id, REF_RETRY).await?.as_deref() == Some(retired.retry_oid.as_str()),
        "P2 did not apply the original P0 wire command to ref A"
    );
    ensure!(committed.terminal.registrations.len() == 1, "P2 terminal does not name exactly one registration");
    let registration = &committed.terminal.registrations[0];
    ensure!(
        registration.pack_id == plan.packs()[0].pack_id()
            && registration.registration_id == plan.packs()[0].registration_id(),
        "P2 terminal registration differs from the fresh plan"
    );
    ensure!(registration.pack_id != retired.plan.packs()[0].pack_id(), "P2 terminal promoted the retired P0 pack");
    Ok((plan, receipt, gate))
}

async fn replay_rotation(db: &db::Db, rotation: &SlotOneRotationRequest) -> Result<SlotOneRotationReceipt> {
    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    let outcome = PgRefStore
        .rotate_slot_one_in_tx(
            tx,
            rotation,
            |_| panic!("exact pending rotation replay must not build a plan"),
            deadline(),
        )
        .await
        .map_err(|error| anyhow!("slot one replay aborted: {error:?}"))?;
    let (tx, result) = outcome.into_parts();
    let receipt = result.map_err(|error| anyhow!("slot one replay refused: {error:?}"))?;
    ensure!(receipt.replayed, "exact pending rotation was not a replay");
    tx.rollback().await?;
    Ok(receipt)
}

async fn lookup_public_raw(
    db: &db::Db,
    request: &PublicAttemptRequest,
) -> Result<std::result::Result<PublicAttemptLookup, PackCommitError>> {
    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    let result = PgRefStore.lookup_public_attempt(&tx, request, deadline()).await;
    tx.rollback().await?;
    Ok(result)
}

async fn lookup_public(db: &db::Db, request: &PublicAttemptRequest) -> Result<PublicAttemptLookup> {
    lookup_public_raw(db, request).await?.map_err(|error| anyhow!("public attempt lookup failed: {error:?}"))
}

async fn assert_a5_after_rotation(
    db: &db::Db,
    store: &BlobStore,
    retired: &Retired,
    plan: &PackCommitPlan,
) -> Result<()> {
    let source = pack::create_serving_snapshot(db, store, &retired.actor, &retired.repository, 300).await?;
    ensure!(source.read.head_ref() == "refs/heads/main", "A5 head ref is not main");
    ensure!(
        source.read.head_oid_hex() == Some(retired.verified.commit_oid.as_str()),
        "A5 head oid changed after rotation"
    );
    assert_snapshot_ref(source.read.refs(), "refs/heads/main", &retired.verified.commit_oid)?;
    assert_snapshot_ref(source.read.refs(), REF_RETRY, &retired.retry_oid)?;
    assert_snapshot_ref(source.read.refs(), REF_SIDE, &retired.side_oid)?;
    ensure!(source.read.pack_count() > 0, "A5 snapshot has no registered pack membership");
    ensure!(
        source.read.packs().iter().any(|pack| pack.pack_id() == plan.packs()[0].pack_id()),
        "A5 snapshot omits the rotated P2 pack"
    );
    ensure!(
        !source.read.packs().iter().any(|pack| pack.pack_id() == retired.plan.packs()[0].pack_id()),
        "A5 snapshot promoted the retired P0 pack"
    );
    Ok(())
}

fn assert_snapshot_ref(refs: &[CapturedRef], name: &str, oid: &str) -> Result<()> {
    let reference =
        refs.iter().find(|reference| reference.name() == name).ok_or_else(|| anyhow!("A5 snapshot omits {name}"))?;
    ensure!(reference.oid_hex() == oid, "A5 snapshot {name} differs from the durable ref");
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct PublicationRow {
    plan_operation_id: Uuid,
    parent_digest: String,
    pack_id: Uuid,
    registration_id: Uuid,
    gate_revision: i64,
}

async fn publication_rows(db: &db::Db, repository_id: Uuid) -> Result<Vec<PublicationRow>> {
    let rows = db
        .pool
        .get()
        .await?
        .query(
            "SELECT plan_operation_id,parent_digest,pack_id,registration_id,gate_revision
               FROM ref_store_core_pack_publications
              WHERE repository_id=$1
              ORDER BY created_at, registration_id",
            &[&repository_id],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| PublicationRow {
            plan_operation_id: row.get(0),
            parent_digest: row.get(1),
            pack_id: row.get(2),
            registration_id: row.get(3),
            gate_revision: row.get(4),
        })
        .collect())
}

async fn publication_for(db: &db::Db, repository_id: Uuid, operation_id: Uuid) -> Result<PublicationRow> {
    let mut matching =
        publication_rows(db, repository_id).await?.into_iter().filter(|row| row.plan_operation_id == operation_id);
    let row = matching.next().ok_or_else(|| anyhow!("publication row is missing for the operation"))?;
    ensure!(matching.next().is_none(), "operation has more than one publication row");
    Ok(row)
}

#[derive(Debug, Eq, PartialEq)]
struct AttemptRow {
    slot: i16,
    private_id: Uuid,
    plan_digest: String,
    proof_digest: String,
    base_revision: i64,
}

async fn attempt_rows(db: &db::Db, repository_id: Uuid, public_id: Uuid) -> Result<Vec<AttemptRow>> {
    let rows = db
        .pool
        .get()
        .await?
        .query(
            "SELECT slot,private_id,plan_digest,proof_digest,base_revision
               FROM ref_store_private_attempts
              WHERE repository_id=$1 AND public_id=$2
              ORDER BY slot",
            &[&repository_id, &public_id],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| AttemptRow {
            slot: row.get(0),
            private_id: row.get(1),
            plan_digest: row.get(2),
            proof_digest: row.get(3),
            base_revision: row.get(4),
        })
        .collect())
}

async fn assert_no_registry_promotion(
    db: &db::Db,
    retired: &Retired,
    plan: &PackCommitPlan,
    rotation: &SlotOneRotationReceipt,
    p0_before: &PublicationRow,
) -> Result<()> {
    let p0_after = publication_for(db, retired.repository.id, retired.admission.private_id).await?;
    ensure!(p0_before == &p0_after, "P2 rewrote the durable P0 publication registration");
    let p2 = publication_for(db, retired.repository.id, rotation.private_id).await?;

    ensure!(p0_before.parent_digest == retired.plan.parent_digest().as_hex(), "P0 publication parent digest differs");
    ensure!(p0_before.pack_id == retired.plan.packs()[0].pack_id(), "P0 publication pack id differs");
    ensure!(
        p0_before.registration_id == retired.plan.packs()[0].registration_id(),
        "P0 publication registration id differs"
    );
    ensure!(p0_before.gate_revision == retired.plan.expected().revision(), "P0 publication gate revision differs");
    ensure!(p2.parent_digest == plan.parent_digest().as_hex(), "P2 publication parent digest differs");
    ensure!(p2.pack_id == plan.packs()[0].pack_id(), "P2 publication pack id differs");
    ensure!(p2.registration_id == plan.packs()[0].registration_id(), "P2 publication registration id differs");
    ensure!(p2.gate_revision == plan.expected().revision(), "P2 publication gate revision differs");
    ensure!(p0_before.pack_id != p2.pack_id, "P2 reused the retired pack id");
    ensure!(p0_before.registration_id != p2.registration_id, "P2 reused the retired registration id");
    ensure!(p0_before.parent_digest != p2.parent_digest, "P2 reused the retired parent digest");

    let attempts = attempt_rows(db, retired.repository.id, retired.public.public_id).await?;
    ensure!(attempts.len() == 2, "rotated wrapper does not have exactly two private attempts");
    let slot_zero = &attempts[0];
    ensure!(slot_zero.slot == 0, "retired attempt is not slot zero");
    ensure!(slot_zero.private_id == retired.admission.private_id, "retired attempt private id changed");
    ensure!(slot_zero.plan_digest == retired.admission.plan_digest.as_hex(), "retired attempt plan digest changed");
    ensure!(slot_zero.proof_digest == retired.admission.proof_digest.as_hex(), "retired attempt proof digest changed");
    ensure!(slot_zero.base_revision == retired.admission.base_revision, "retired attempt base revision changed");
    let slot_one = &attempts[1];
    ensure!(slot_one.slot == 1, "rotated attempt is not slot one");
    ensure!(slot_one.private_id == rotation.private_id, "rotated attempt private id differs");
    ensure!(slot_one.plan_digest == rotation.plan_digest.as_hex(), "rotated attempt plan digest differs");
    ensure!(slot_one.proof_digest == rotation.proof_digest.as_hex(), "rotated attempt proof digest differs");
    ensure!(slot_one.base_revision == rotation.base_revision, "rotated attempt base revision differs");

    let record = operation_record(db, retired.repository.id, retired.admission.private_id).await?;
    ensure!(record.state() == OperationState::Rejected, "P0 durable rejection was rewritten by rotation");
    let terminal = PackCommitTerminal::from_terminal_result(
        record.terminal_result().ok_or_else(|| anyhow!("P0 rejected operation has no terminal result"))?,
    )
    .map_err(|error| anyhow!("P0 durable terminal is not a pack commit terminal: {error:?}"))?;
    ensure!(terminal.registrations.is_empty(), "P0 durable rejection gained a registration");
    Ok(())
}

async fn assert_current_pending_wrapper_gap(db: &db::Db, retired: &Retired) -> Result<()> {
    // The terminal writer that closes a slot-one wrapper is deliberately a
    // separate product checkpoint. At 9cf the real P2 commit is durable in the
    // migration-138 registry while the migration-152 wrapper remains pending;
    // the resolver must fail closed on that exact mismatch. Integration later
    // replaces this assertion with the committed wrapper read.
    match lookup_public_raw(db, &retired.public).await? {
        Err(PackCommitError::Rejected(rejection)) => {
            ensure!(
                rejection.code == PackCommitRejectCode::LedgerIntegrity,
                "pending-wrapper gap raised the wrong rejection code"
            );
            ensure!(
                rejection.detail == "current private attempt state differs from its public operation",
                "pending-wrapper gap raised an unexpected detail"
            );
        }
        Err(other) => bail!("pending-wrapper gap raised an unexpected error: {other:?}"),
        Ok(other) => bail!("expected the current pending-wrapper gap, got {other:?}"),
    }
    Ok(())
}

fn require_owned_disposable_blob_fixture() -> Result<()> {
    ensure!(
        matches!(std::env::var(OWNED_BLOB_OPT_IN).as_deref(), Ok("1")),
        "this real fixture requires {OWNED_BLOB_OPT_IN}=1: the caller must own the whole configured Blob bucket/namespace and dispose of the complete fixture after the run"
    );
    Ok(())
}

async fn require_postgres_17(db: &db::Db) -> Result<()> {
    let version: String =
        db.pool.get().await?.query_one("SELECT current_setting('server_version_num')", &[]).await?.get(0);
    let number: u32 = version.parse().with_context(|| format!("server_version_num is not numeric: {version}"))?;
    ensure!(
        (17_0000..18_0000).contains(&number),
        "this fixture requires PostgreSQL 17, got server_version_num={version}"
    );
    Ok(())
}
