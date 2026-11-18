//! Slot-one rotation over the identical retried wire ref command, exact pending
//! replay and read-only resolver checks.

use super::db::deadline;
use super::{
    REF_RETRY, Retired, SLOT_ZERO_LANE, db,
    publication::{authorized_commit, capture_baseline, plan_from_baseline, ref_update, stage, wire_digest},
    readback::stored_ref,
};
use anyhow::{Result, anyhow, bail, ensure};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::{
    CommitMode, CoreGateVersion, IssuerLane, OperationState,
    core::pack_commit::{PackCommitError, PackCommitPlan, PackCommitRejectCode},
    pg::{
        PgRefStore,
        public_attempt::{PublicAttemptLookup, PublicAttemptRequest},
        slot_one::{SlotOneRotationReceipt, SlotOneRotationRequest},
    },
};
use std::path::Path;

pub(super) async fn rotate_and_commit(
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

pub(super) async fn assert_current_pending_wrapper_gap(db: &db::Db, retired: &Retired) -> Result<()> {
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
