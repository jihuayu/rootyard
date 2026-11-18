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
//! terminal, approval or event row directly: P0 is admitted and the P1 gate
//! advance, P0 superseded refusal, terminal mirror and rotation all run through
//! production methods over real A3/A4/native artifacts.
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
//!   ref_store::pg::slot_one::tests::native::slot_zero_rejection_selects_retirement_on_real_a3_a4 \
//!   -- --ignored --exact --test-threads=1
//! ```

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
        AuthorizedCommitMode, AuthorizedCommitReceipt, ContentDigest, PackArtifactRole, PackCommitBaseline,
        PackCommitError, PackCommitExpectation, PackCommitPlan, PackCommitScope, PackCommitTerminal,
        PackMembershipEntry, PackPendingToken, PgAuthorizedCommit, PgPackCommit, PlannedArtifact, PlannedPack,
        PrepareOutcome,
    },
    pg::{
        PgRefStore,
        public_attempt::PublicAttemptRequest,
        public_terminal::{PublicAttemptRetirement, PublicAttemptTerminalOutcome},
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
