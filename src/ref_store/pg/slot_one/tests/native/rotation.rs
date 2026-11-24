//! Slot-one rotation over the identical retried wire ref command, exact pending
//! replay, the pre-mirror resolver refusal and current terminal mirroring.

use super::db::deadline;
use super::{
    REF_RETRY, REF_SIDE, Retired, SLOT_ZERO_LANE, db,
    publication::{authorized_commit, capture_baseline, plan_from_baseline, ref_update, stage, wire_digest},
    readback::{attempt_rows, operation_event_id, operation_record, public_attempt_event_count, stored_ref},
};
use anyhow::{Result, anyhow, bail, ensure};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::{
    CommitMode, CoreGateVersion, IssuerLane, OperationRecord, OperationState,
    core::pack_commit::{PackCommitError, PackCommitPlan, PackCommitRejectCode},
    pg::{
        PgRefStore,
        public_attempt::{PublicAttemptLookup, PublicAttemptRequest},
        public_terminal::{PublicAttemptTerminalOutcome, PublicAttemptTerminalReceipt},
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
    let tx = tokio_postgres::Client::transaction(&mut client).await?;
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
            let retired_attempt =
                evidence.retired.last().ok_or_else(|| anyhow!("rotated wrapper has no retired slot-zero evidence"))?;
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
    let tx = tokio_postgres::Client::transaction(&mut client).await?;
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
    // The real P2 commit is durable in the migration-138 registry while the
    // migration-152 wrapper is still pending. Before the explicit terminal
    // mirror below, the resolver must fail closed on that exact mismatch; the
    // committed readback is asserted only after the mirror commits.
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

pub(super) async fn mirror_p2_terminal_and_prove_replay(
    db: &db::Db,
    retired: &Retired,
    p2: &SlotOneRotationReceipt,
) -> Result<()> {
    let p2_record = operation_record(db, retired.repository.id, p2.private_id).await?;
    ensure!(
        p2_record.identity().operation_id() == p2.private_id,
        "P2 durable operation identity differs from the rotation receipt"
    );
    ensure!(
        p2_record.identity().digest() == &p2.plan_digest,
        "P2 durable operation plan digest differs from the rotation receipt"
    );
    ensure!(p2_record.state() == OperationState::Committed, "P2 durable operation is not committed");
    let expected_event = operation_event_id(db, retired.repository.id, p2.private_id)
        .await?
        .ok_or_else(|| anyhow!("P2 committed operation has no core event"))?;
    let event_count_before = public_attempt_event_count(db, retired.repository.id, retired.public.public_id).await?;
    let attempts_before = attempt_rows(db, retired.repository.id, retired.public.public_id).await?;
    let main_before = stored_ref(db, retired.repository.id, "refs/heads/main").await?;
    let retry_before = stored_ref(db, retired.repository.id, REF_RETRY).await?;
    let side_before = stored_ref(db, retired.repository.id, REF_SIDE).await?;

    let first = mirror_terminal_commit(db, &retired.public, &p2_record).await?;
    ensure!(first.state == OperationState::Committed, "first P2 terminal mirror is not committed");
    ensure!(!first.replayed, "first P2 terminal mirror replayed instead of publishing");
    ensure!(first.event_id == expected_event, "first P2 terminal mirror used another core event");

    let committed_lookup = lookup_public(db, &retired.public).await?;
    let evidence = match &committed_lookup {
        PublicAttemptLookup::Committed(evidence) => evidence,
        _ => bail!("mirrored P2 public attempt is not committed"),
    };
    ensure!(evidence.current.slot == 1, "mirrored P2 current attempt is not slot one");
    ensure!(evidence.current.private_id == p2.private_id, "mirrored P2 current private id differs");
    ensure!(evidence.current.state == OperationState::Committed, "mirrored P2 current attempt is not committed");
    ensure!(evidence.current.event_id == Some(expected_event), "mirrored P2 current event id differs");
    ensure!(
        evidence.current.event_revision == Some(p2.base_revision + 1),
        "mirrored P2 current event revision differs"
    );
    let retired_attempt =
        evidence.retired.last().ok_or_else(|| anyhow!("mirrored P2 wrapper has no retired slot-zero attempt"))?;
    ensure!(retired_attempt.slot == 0, "mirrored P2 retired attempt is not slot zero");
    ensure!(retired_attempt.private_id == retired.admission.private_id, "mirrored P2 retired private id changed");
    ensure!(retired_attempt.state == OperationState::Rejected, "mirrored P2 retired attempt is not rejected");
    ensure!(retired_attempt.event_id == Some(retired.retirement.event_id), "mirrored P2 retired event id changed");
    ensure!(
        retired_attempt.event_revision == Some(retired.retirement.event_revision),
        "mirrored P2 retired event revision changed"
    );

    let p0_record = operation_record(db, retired.repository.id, retired.admission.private_id).await?;
    let refusal = mirror_terminal_refusal(db, &retired.public, &p0_record).await?;
    match refusal {
        PackCommitError::Rejected(rejection) => {
            ensure!(
                rejection.code == PackCommitRejectCode::LedgerIntegrity,
                "old P0 terminal retry raised the wrong rejection code"
            );
            ensure!(
                rejection.detail == "slot one current private identity differs from the terminal record",
                "old P0 terminal retry raised an unexpected detail"
            );
        }
        _ => bail!("old P0 terminal retry did not fail closed"),
    }
    ensure!(
        lookup_public(db, &retired.public).await? == committed_lookup,
        "old P0 terminal retry changed the current committed wrapper"
    );

    let replay = mirror_terminal_commit(db, &retired.public, &p2_record).await?;
    ensure!(replay.state == OperationState::Committed, "second P2 terminal mirror is not committed");
    ensure!(replay.replayed, "second exact P2 terminal mirror was not a replay");
    ensure!(replay.event_id == expected_event, "second P2 terminal mirror used another core event");

    ensure!(
        lookup_public(db, &retired.public).await? == committed_lookup,
        "exact P2 terminal replay changed the committed wrapper"
    );
    ensure!(
        stored_ref(db, retired.repository.id, "refs/heads/main").await? == main_before,
        "exact P2 terminal replay changed main"
    );
    ensure!(
        stored_ref(db, retired.repository.id, REF_RETRY).await? == retry_before,
        "exact P2 terminal replay changed ref A"
    );
    ensure!(
        stored_ref(db, retired.repository.id, REF_SIDE).await? == side_before,
        "exact P2 terminal replay changed ref B"
    );
    ensure!(
        attempt_rows(db, retired.repository.id, retired.public.public_id).await? == attempts_before,
        "exact P2 terminal replay changed private attempts"
    );
    ensure!(
        public_attempt_event_count(db, retired.repository.id, retired.public.public_id).await? == event_count_before,
        "exact P2 terminal replay changed the core event count"
    );
    ensure!(
        operation_event_id(db, retired.repository.id, retired.admission.private_id).await?
            == Some(retired.retirement.event_id),
        "exact P2 terminal replay changed the retired P0 event"
    );
    ensure!(
        operation_event_id(db, retired.repository.id, p2.private_id).await? == Some(expected_event),
        "exact P2 terminal replay changed the current P2 event"
    );
    Ok(())
}

async fn mirror_terminal_commit(
    db: &db::Db,
    request: &PublicAttemptRequest,
    record: &OperationRecord,
) -> Result<PublicAttemptTerminalReceipt> {
    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    match PgRefStore.mirror_public_attempt_terminal_in_tx(&tx, request, record, deadline()).await {
        Ok(PublicAttemptTerminalOutcome::Mirrored(receipt)) => {
            tx.commit().await?;
            Ok(receipt)
        }
        Ok(PublicAttemptTerminalOutcome::RetirementRequired(_)) => {
            tx.rollback().await?;
            bail!("current slot-one terminal mirror requested retirement")
        }
        Err(error) => {
            tx.rollback().await?;
            Err(anyhow!("current slot-one terminal mirror failed: {error:?}"))
        }
    }
}

async fn mirror_terminal_refusal(
    db: &db::Db,
    request: &PublicAttemptRequest,
    record: &OperationRecord,
) -> Result<PackCommitError> {
    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    match PgRefStore.mirror_public_attempt_terminal_in_tx(&tx, request, record, deadline()).await {
        Err(error) => {
            tx.rollback().await?;
            Ok(error)
        }
        Ok(PublicAttemptTerminalOutcome::Mirrored(_)) => {
            tx.rollback().await?;
            bail!("old P0 terminal retry unexpectedly published")
        }
        Ok(PublicAttemptTerminalOutcome::RetirementRequired(_)) => {
            tx.rollback().await?;
            bail!("old P0 terminal retry unexpectedly requested retirement")
        }
    }
}
