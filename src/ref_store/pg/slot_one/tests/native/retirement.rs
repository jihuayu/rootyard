//! P0 admission, real P1 ref B advance, production superseded refusal and the
//! read-only retirement selection.

use super::db::deadline;
use super::{
    REF_RETRY, REF_SIDE, Retired, SLOT_ZERO_LANE, db, git, pack,
    publication::{
        authorized_commit, capture_baseline, child_commit, plan_from_baseline, ref_update, stage, wire_digest,
    },
    readback::{operation_record, private_retirement_evidence, publication_for, stored_ref},
    serving,
};
use anyhow::{Result, anyhow, bail, ensure};
use rootyard::blob_git_gateway::slot_one_acceptance_support as acceptance;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::{
    CommitMode, CommitRejectCode, GitObjectFormat, IssuerLane, OperationLookup, OperationState, RefCommitResult,
    RefUpdate, TerminalKind,
    core::pack_commit::{
        PackCommitBaseline, PackCommitError, PackCommitPlan, PackCommitTerminal, PackPendingToken, PgAuthorizedCommit,
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

#[tokio::test]
#[ignore = "requires real PostgreSQL 17, S3/Garage Blob and native Git"]
async fn slot_zero_private_stage_selection_and_commit_use_the_exact_public_attempt() -> Result<()> {
    use super::{common, setup};
    use rootyard::ref_store::{
        RefStoreError, RequestDigest,
        core::pack_commit::{
            AuthorizedCommitError, AuthorizedCommitMode, PackCommitRejectCode, PackRegistrationRequest, PgPackCommit,
            PrepareOutcome,
        },
    };

    setup::require_owned_disposable_fixture()?;
    let db = db::Db::setup().await?;
    let outcome: Result<()> = async {
        setup::require_postgres_17(&db).await?;
        let store = common::open_store()?;
        let git = git::git_binary()?;
        let actor = db::serving_actor(&db.pool, "slot-zero-owner-").await?;
        let repo = db::provision_serving(&db.pool, &actor, &store, "slot-zero-register").await?;
        let baseline = capture_baseline(&db, repo.id, actor.id).await?;
        let gate = baseline.gate();
        let fixture = git::GitRepo::new(git.clone(), gate.object_format()).await?;
        let oid = fixture.build_commit("new-ref", b"new\n", "slot zero").await?;
        fixture.update_ref(REF_RETRY, &oid).await?;
        let files = fixture.pack_all("slot-zero-register").await?;
        let public = PublicAttemptRequest {
            repository_id: repo.id,
            admission_owner_id: actor.id,
            issuer_id: actor.id,
            public_id: Uuid::new_v4(),
            wire_digest: wire_digest(gate.object_format(), REF_RETRY, None, &oid, CommitMode::Atomic),
            request_mode: CommitMode::Atomic,
            backend_identity: store.backend_identity().as_hex().to_owned(),
            object_format: gate.object_format(),
            history_incarnation: gate.history_incarnation(),
            authority_epoch: gate.authority_epoch(),
            group_epoch: gate.group_epoch(),
            restore_incarnation: db::cluster_incarnation(&db.pool).await?,
        };
        let (admitted, plan) = admit_slot_zero(
            &db,
            &public,
            Uuid::new_v4(),
            &IssuerLane::new(SLOT_ZERO_LANE)?,
            &baseline,
            vec![ref_update(gate.object_format(), REF_RETRY, None, &oid)?],
            std::slice::from_ref(&files),
        )
        .await?;
        let publication = pack::publish(&db, &store, &plan, &files).await?;
        let pack_id = plan.packs()[0].pack_id();
        let request = || PackRegistrationRequest::new(&plan, pack_id, &publication);
        let mut client = db.pool.get().await?;
        ensure!(
            matches!(
                PgPackCommit.register_publication(&mut client, request()?, deadline()).await,
                Err(PackCommitError::RefStore(RefStoreError::IdentityConflict))
            ),
            "legacy registration accepted a claimed private UUID"
        );
        let first = PgPackCommit.register_private_publication(&mut client, request()?, &public, deadline()).await?;
        ensure!(!first.replayed, "first private registration must be fresh");
        let second = PgPackCommit.register_private_publication(&mut client, request()?, &public, deadline()).await?;
        ensure!(second.replayed && second.ack == first.ack, "an exact private registration did not replay");
        ensure!(
            matches!(
                PgPackCommit.register_publication(&mut client, request()?, deadline()).await,
                Err(PackCommitError::RefStore(RefStoreError::IdentityConflict))
            ),
            "legacy registration replayed a claimed private UUID"
        );
        let mut wrong_wire = public.clone();
        wrong_wire.wire_digest = RequestDigest::of("unrelated-wire", &[b"wrong"]);
        ensure!(
            matches!(
                PgPackCommit.register_private_publication(&mut client, request()?, &wrong_wire, deadline()).await,
                Err(PackCommitError::RefStore(RefStoreError::DigestConflict))
            ),
            "a different wire digest replayed the committed private registration"
        );
        drop(client);
        let adapter = PgAuthorizedCommit::new(store.clone(), git)?;
        let wrapper_before = wrapper_json(&db, repo.id, public.public_id).await?;
        ensure!(
            matches!(
                adapter.prepare(&db.pool, plan.clone(), deadline()).await,
                Err(AuthorizedCommitError::Pack(PackCommitError::RefStore(RefStoreError::IdentityConflict)))
            ),
            "legacy prepare accepted a claimed private UUID"
        );
        ensure!(
            matches!(
                adapter.prepare_private(&db.pool, plan.clone(), &wrong_wire, deadline()).await,
                Err(AuthorizedCommitError::Pack(PackCommitError::RefStore(RefStoreError::DigestConflict)))
            ),
            "a different wire digest captured the private attempt"
        );
        let mut wrong_backend = public.clone();
        wrong_backend.backend_identity = "00".repeat(32);
        ensure!(
            matches!(
                adapter.prepare_private(&db.pool, plan.clone(), &wrong_backend, deadline()).await,
                Err(AuthorizedCommitError::Pack(PackCommitError::Rejected(rejection)))
                    if rejection.code == PackCommitRejectCode::PublicationMismatch
            ),
            "a different backend captured the private attempt"
        );
        let capture = adapter.prepare_private(&db.pool, plan.clone(), &public, deadline()).await?;
        let PrepareOutcome::Prepared(capture) = capture else {
            bail!("pending private attempt replayed a terminal");
        };
        ensure!(capture.operation_id() == admitted.private_id);
        ensure!(capture.gate_revision() == gate.revision());
        ensure!(capture.new_packs().len() == 1 && capture.new_packs()[0].pack_id() == pack_id);
        let mut invalid_token = actor.clone();
        invalid_token.token_digest[0] ^= 1;
        ensure!(
            matches!(
                adapter.select(&db.pool, *capture, &invalid_token, AuthorizedCommitMode::Atomic, deadline()).await,
                Err(AuthorizedCommitError::Denied("token_invalid"))
            ),
            "selection accepted a token that failed the live authority lookup"
        );
        let existing = db
            .pool
            .get()
            .await?
            .query_opt(
                "SELECT decision_id FROM ref_store_publication_decisions WHERE repository_id=$1 AND operation_id=$2",
                &[&repo.id, &admitted.private_id],
            )
            .await?;
        ensure!(existing.is_none(), "denied selection wrote a decision");

        let prepare = || adapter.prepare_private(&db.pool, plan.clone(), &public, deadline());
        let PrepareOutcome::Prepared(capture) = prepare().await? else {
            bail!("pending private attempt replayed a terminal");
        };
        let selection = adapter.select(&db.pool, *capture, &actor, AuthorizedCommitMode::Atomic, deadline()).await?;
        ensure!(selection.operation_id() == admitted.private_id);
        ensure!(selection.planned_refs() == 1 && selection.selected().accepted() == plan.refs());
        let PrepareOutcome::Prepared(capture) = prepare().await? else {
            bail!("open decision unexpectedly terminalized the private operation");
        };
        let replay = adapter.select(&db.pool, *capture, &actor, AuthorizedCommitMode::Atomic, deadline()).await?;
        ensure!(
            replay.decision_id() == selection.decision_id()
                && replay.selection_digest() == selection.selection_digest()
        );

        let decision = db
            .pool
            .get()
            .await?
            .query_one(
                "SELECT decision_id,state,base_revision,selection_digest
                 FROM ref_store_publication_decisions WHERE repository_id=$1 AND operation_id=$2",
                &[&repo.id, &admitted.private_id],
            )
            .await?;
        ensure!(decision.get::<_, Uuid>(0) == selection.decision_id());
        ensure!(decision.get::<_, String>(1) == "OPEN");
        ensure!(decision.get::<_, i64>(2) == gate.revision());
        ensure!(decision.get::<_, String>(3) == selection.selection_digest().as_hex());

        ensure!(wrapper_json(&db, repo.id, public.public_id).await? == wrapper_before);
        ensure!(operation_record(&db, repo.id, admitted.private_id).await?.state() == OperationState::Pending);
        let stored = publication_for(&db, repo.id, admitted.private_id).await?;
        ensure!(stored.parent_digest == plan.parent_digest().as_hex());
        ensure!(stored_ref(&db, repo.id, REF_RETRY).await?.is_none(), "selection published a ref");
        ensure!(db::gate_version(&db.pool, repo.id, actor.id).await?.revision() == gate.revision());
        let verified = adapter.verify(replay, deadline()).await?;
        let result = adapter.commit(&db.pool, &verified, deadline()).await?;
        let revision = gate.revision() + 1;
        ensure!(result.is_committed() && !result.replayed);
        ensure!(result.selection_digest == *selection.selection_digest());
        ensure!(result.terminal.revision == revision);
        ensure!(result.terminal.registrations.len() == 1 && result.terminal.registrations[0].pack_id == pack_id);
        ensure!(stored_ref(&db, repo.id, REF_RETRY).await?.as_deref() == Some(oid.as_str()));
        ensure!(db::gate_version(&db.pool, repo.id, actor.id).await?.revision() == revision);
        ensure!(operation_record(&db, repo.id, admitted.private_id).await? == result.record);
        ensure!(wrapper_json(&db, repo.id, public.public_id).await? == wrapper_before);

        let effects = db
            .pool
            .get()
            .await?
            .query_one(
                "SELECT d.state,d.consume_receipt_id,e.outcome,e.revision,m.joined_revision
                 FROM ref_store_publication_decisions d
                 JOIN ref_store_core_events e USING (repository_id,operation_id)
                 JOIN ref_store_core_pack_memberships m ON m.repository_id=d.repository_id AND m.pack_id=$3
                 WHERE d.repository_id=$1 AND d.operation_id=$2",
                &[&repo.id, &admitted.private_id, &pack_id],
            )
            .await?;
        ensure!(effects.get::<_, String>(0) == "CONSUMED");
        ensure!(effects.get::<_, Uuid>(1) == admitted.private_id);
        ensure!(effects.get::<_, String>(2) == "committed");
        ensure!(effects.get::<_, i64>(3) == revision && effects.get::<_, i64>(4) == revision);
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

/// Admit P0 for the exact ref A wire command, stage its real A3/A4 artifacts,
/// advance the gate through a separate authorized P1 ref B command, refuse P0
/// through the production superseded writer, and select the retirement through
/// the production mirror without mutating the pending wrapper.
pub(super) async fn retire_p0(db: &db::Db, store: &BlobStore, git: &Path) -> Result<Retired> {
    retire_p0_inner(db, store, git, false).await
}

/// Same real retirement prefix, but P0's public wire digest is derived by the
/// gateway's production parser/digest from the exact command-plus-pack body.
/// The private direct-handoff acceptance reconstructs that same body, so the
/// handoff consumes a genuine producer value rather than a logical fixture
/// digest.
pub(super) async fn retire_p0_with_producer(db: &db::Db, store: &BlobStore, git: &Path) -> Result<Retired> {
    retire_p0_inner(db, store, git, true).await
}

async fn retire_p0_inner(db: &db::Db, store: &BlobStore, git: &Path, producer_request: bool) -> Result<Retired> {
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
    let public_id = Uuid::new_v4();
    let wire0 = if producer_request {
        let body_dir = tempfile::tempdir()?;
        let body = body_dir.path().join("slot-zero-p0.request");
        acceptance::write_producer_body(&body, &p0_files.pack, format, REF_RETRY, None, &retry_oid, true)?;
        acceptance::producer_request_digest(repository.id, public_id, format, &body, deadline())
            .await
            .map_err(|error| anyhow!("producer request digest refused: {error:?}"))?
    } else {
        wire_digest(format, REF_RETRY, None, &retry_oid, CommitMode::Atomic)
    };
    let public = PublicAttemptRequest {
        repository_id: repository.id,
        admission_owner_id: actor.id,
        issuer_id: actor.id,
        public_id,
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
    let private_evidence = private_retirement_evidence(db, &public, &admission, &retirement).await?;

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
        private_evidence,
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
    let tx = tokio_postgres::Client::transaction(&mut client).await?;
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
        .map_err(|_| anyhow!("P0 operation lookup failed"))?
    {
        OperationLookup::Known(record) => record,
        _ => bail!("P0 operation is not visible to the terminal mirror"),
    };
    ensure!(record.state() == OperationState::Rejected, "P0 operation is not durably rejected");
    let outcome = PgRefStore
        .mirror_public_attempt_terminal_in_tx(&tx, public, &record, deadline())
        .await
        .map_err(|_| anyhow!("public terminal mirror failed"))?;
    let retirement = match outcome {
        PublicAttemptTerminalOutcome::RetirementRequired(retirement) => retirement,
        PublicAttemptTerminalOutcome::Mirrored(_) => {
            bail!("terminal mirror published instead of selecting retirement")
        }
    };
    tx.rollback().await?;
    Ok(retirement)
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
