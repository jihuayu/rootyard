//! Real PostgreSQL/Blob acceptance for the private gateway slot-one handoff.
//!
//! The cases call the actual crate-private `SlotOneReceive::from_verified_slot_zero`
//! and `rotate_slot_one`, using the same owned PG/S3/native-Git fixture as the
//! slot-zero/slot-one native foundation. P0 is a real admitted/staged operation
//! with an exact producer request digest derived from its command-plus-pack body;
//! P1 is a real authorized unrelated ref advance; the production superseded
//! refusal and retirement mirror select the exact slot-zero event. No gate,
//! authority, wrapper, decision or event row is written by hand.
//!
//! Every case is `#[ignore]`, hard-fails when the owned PG/Blob fixture markers
//! are absent, and runs the existing bounded `Db::finish` cleanup. The remote
//! Blob namespace is the fixture's already-attested unique run prefix.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, anyhow, bail, ensure};
use axum::http::{HeaderMap, HeaderValue, header};
use base64::Engine as _;
use deadpool_postgres::Pool;
use serde_json::Value;
use uuid::Uuid;

use rootyard::{
    auth,
    blob_git_gateway::{BlobGitConfig, BlobGitState, error::GatewayError, slot_one_acceptance_support as acceptance},
    blob_store::opendal::BlobStore,
    db::{self as product_db, Identity},
    ref_store::{
        CoreGateVersion, OperationRecord, OperationState,
        core::pack_commit::{PackArtifactRole, PackCommitPlan},
        pg::{
            PgRefStore,
            public_attempt::{PublicAttemptEvidence, PublicAttemptLookup, PublicAttemptRequest},
            public_terminal::{PublicAttemptTerminalOutcome, PublicAttemptTerminalReceipt},
        },
        serving::{self, ServingRepository},
    },
    token_management::service::revoke_token,
};

use super::{
    REF_RETRY, REF_SIDE, Retired,
    db::{self, deadline},
    git, pack,
    publication::{authorized_commit, capture_baseline, child_commit, ref_update, stage},
    readback::{assert_a5_after_rotation, operation_event_id, operation_record, publication_for, stored_ref},
    retirement::retire_p0_with_producer,
    setup::{require_owned_disposable_fixture, require_postgres_17},
};

const REF_LATER: &str = "refs/heads/later";
const LEDGER_SNAPSHOT: &str = r#"
SELECT jsonb_build_object(
    'wrapper', (
        SELECT to_jsonb(w)
          FROM ref_store_public_operations w
         WHERE w.repository_id=$1 AND w.public_id=$2
    ),
    'attempts', COALESCE((
        SELECT jsonb_agg(to_jsonb(a) ORDER BY a.slot)
          FROM ref_store_private_attempts a
         WHERE a.repository_id=$1 AND a.public_id=$2
    ), '[]'::jsonb),
    'operations', COALESCE((
        SELECT jsonb_agg(to_jsonb(o) ORDER BY o.operation_id)
          FROM ref_store_operations o
         WHERE o.repository_id=$1
           AND o.operation_id IN (
               SELECT private_id FROM ref_store_private_attempts
                WHERE repository_id=$1 AND public_id=$2
           )
    ), '[]'::jsonb),
    'bindings', COALESCE((
        SELECT jsonb_agg(to_jsonb(s) ORDER BY s.operation_id)
          FROM ref_store_serving_operations s
         WHERE s.repository_id=$1
           AND s.operation_id IN (
               SELECT private_id FROM ref_store_private_attempts
                WHERE repository_id=$1 AND public_id=$2
           )
    ), '[]'::jsonb),
    'events', COALESCE((
        SELECT jsonb_agg(to_jsonb(e) ORDER BY e.event_id)
          FROM ref_store_core_events e
         WHERE e.repository_id=$1
           AND e.operation_id IN (
               SELECT private_id FROM ref_store_private_attempts
                WHERE repository_id=$1 AND public_id=$2
           )
    ), '[]'::jsonb),
    'refs', COALESCE((
        SELECT jsonb_agg(to_jsonb(r) ORDER BY r.ref_name)
          FROM ref_store_core_refs r
         WHERE r.repository_id=$1
    ), '[]'::jsonb),
    'gate', (
        SELECT to_jsonb(g) FROM ref_store_core_gates g WHERE g.repository_id=$1
    ),
    'lanes', COALESCE((
        SELECT jsonb_agg(to_jsonb(l) ORDER BY l.issuer_id, l.lane)
          FROM ref_store_issuer_lanes l
         WHERE l.repository_id=$1
    ), '[]'::jsonb),
    'publications', COALESCE((
        SELECT jsonb_agg(to_jsonb(p) ORDER BY p.registration_id)
          FROM ref_store_core_pack_publications p
         WHERE p.repository_id=$1
    ), '[]'::jsonb)
)
"#;

struct WrapperRow {
    current_slot: i16,
    state: String,
    event_id: Option<Uuid>,
    retired_event_id: Option<Uuid>,
    cancelled_private_id: Option<Uuid>,
    restore_incarnation: Uuid,
    backend_identity: String,
    object_format: String,
}

struct AttemptRow {
    slot: i16,
    private_id: Uuid,
    plan_digest: String,
    proof_digest: String,
    base_revision: i64,
    lane: String,
    sequence: i64,
    state: String,
}

#[tokio::test]
#[ignore = "requires real PostgreSQL 17, S3/Garage Blob and native Git"]
async fn slot_one_handoff_commits_fresh_private_attempt_on_real_a3_a4_a5() -> Result<()> {
    require_owned_disposable_fixture()?;
    let db = super::db::Db::setup().await?;
    let outcome: Result<()> = async {
        require_postgres_17(&db).await?;
        let store = super::common::open_store()?;
        let git = super::git::git_binary()?;
        let retired = retire_p0_with_producer(&db, &store, &git).await?;
        let (state, _scratch) = gateway_state(&db, &store, &git)?;
        let serving = live_serving(&db, &store, &retired).await?;
        ensure!(
            serving.cluster_incarnation == retired.public.restore_incarnation,
            "live serving restore incarnation differs from P0"
        );
        let evidence = rejected_slot_zero(&db, &retired.public).await?;
        let baseline = capture_baseline(&db, retired.repository.id, retired.verified.tenant).await?;
        ensure!(baseline.gate().revision() == retired.gate.revision(), "rotation baseline is not the advanced P1 gate");
        let body_dir = tempfile::tempdir()?;
        let body = write_p0_body(&body_dir, &retired)?;
        let p0_publication = publication_for(&db, retired.repository.id, retired.admission.private_id).await?;

        let admission = acceptance::rotate_direct(
            &state,
            &serving,
            &retired.actor,
            retired.public.public_id,
            &body,
            &retired.p0_files.pack,
            &retired.p0_files.idx,
            &baseline,
            &evidence,
            &retired.retirement,
            deadline(),
        )
        .await
        .map_err(acceptance::refusal)?;
        let (plan, receipt) = match admission {
            acceptance::Admission::Fresh { plan, receipt } => (plan, receipt),
            acceptance::Admission::Replayed(_) => bail!("fresh direct handoff replayed"),
        };
        assert_fresh_receipt(&retired, &plan, &receipt)?;

        let (pack_sha, pack_len) = super::git::digest_file(&retired.p0_files.pack)?;
        let (idx_sha, idx_len) = super::git::digest_file(&retired.p0_files.idx)?;
        ensure!(plan.packs().len() == 1, "fresh slot-one plan must have one pack");
        let planned = &plan.packs()[0];
        ensure!(
            planned.artifact(PackArtifactRole::Pack).content().as_str() == pack_sha.as_str()
                && planned.artifact(PackArtifactRole::Pack).length() == pack_len,
            "fresh plan did not preserve the exact staged pack bytes"
        );
        ensure!(
            planned.artifact(PackArtifactRole::Idx).content().as_str() == idx_sha.as_str()
                && planned.artifact(PackArtifactRole::Idx).length() == idx_len,
            "fresh plan did not preserve the exact staged idx bytes"
        );
        ensure!(
            planned.pack_id() != retired.plan.packs()[0].pack_id()
                && planned.registration_id() != retired.plan.packs()[0].registration_id(),
            "fresh slot-one plan reused the retired pack identity"
        );

        stage(&db, &store, &plan, &retired.p0_files).await?;
        let committed = authorized_commit(&db, &store, &git, &retired.actor, plan.clone()).await?;
        ensure!(
            committed.terminal.revision == retired.gate.revision() + 1,
            "P2 authorized commit did not advance the gate exactly once"
        );
        ensure!(
            committed.terminal.registrations.len() == 1
                && committed.terminal.registrations[0].pack_id == planned.pack_id()
                && committed.terminal.registrations[0].registration_id == planned.registration_id(),
            "P2 terminal does not name the fresh private plan registration"
        );
        let p2_event = operation_event_id(&db, retired.repository.id, receipt.private_id)
            .await?
            .ok_or_else(|| anyhow!("P2 committed operation has no core event"))?;

        let p0_after = publication_for(&db, retired.repository.id, retired.admission.private_id).await?;
        ensure!(p0_publication == p0_after, "P2 rewrote the durable P0 publication registration");
        let p2_publication = publication_for(&db, retired.repository.id, receipt.private_id).await?;
        ensure!(
            p2_publication.plan_operation_id == receipt.private_id
                && p2_publication.parent_digest == plan.parent_digest().as_hex()
                && p2_publication.pack_id == planned.pack_id()
                && p2_publication.registration_id == planned.registration_id()
                && p2_publication.gate_revision == plan.expected().revision(),
            "P2 publication projection differs from the fresh plan"
        );

        assert_a5_after_rotation(&db, &store, &retired, &plan).await?;

        let p2_record = operation_record(&db, retired.repository.id, receipt.private_id).await?;
        ensure!(p2_record.state() == OperationState::Committed, "P2 operation is not durably committed");
        let mirror = mirror_committed_terminal(&db, &retired.public, &p2_record).await?;
        ensure!(
            !mirror.replayed && mirror.state == OperationState::Committed,
            "first P2 terminal mirror did not publish a committed terminal"
        );
        ensure!(mirror.event_id == p2_event, "P2 terminal mirror used another core event");

        let wrapper = wrapper_row(&db, retired.repository.id, retired.public.public_id).await?;
        ensure!(wrapper.current_slot == 1, "public wrapper is not slot one");
        ensure!(wrapper.state == "committed", "public wrapper is not committed");
        ensure!(wrapper.event_id == Some(p2_event), "public wrapper event differs from P2");
        ensure!(
            wrapper.retired_event_id == Some(retired.retirement.event_id),
            "public wrapper retired event differs from P0"
        );
        ensure!(wrapper.cancelled_private_id.is_none(), "public wrapper unexpectedly names a cancellation");
        ensure!(
            wrapper.restore_incarnation == serving.cluster_incarnation,
            "public wrapper restore incarnation differs from the live realm"
        );
        ensure!(
            wrapper.backend_identity.as_str() == store.backend_identity().as_hex(),
            "public wrapper backend identity differs from the live store"
        );
        ensure!(wrapper.object_format == "sha1", "public wrapper format is not sha1");

        let attempts = attempt_rows(&db, retired.repository.id, retired.public.public_id).await?;
        ensure!(attempts.len() == 2, "public wrapper does not have exactly two attempts");
        let slot_zero = &attempts[0];
        ensure!(slot_zero.slot == 0, "retired attempt is not slot zero");
        ensure!(slot_zero.private_id == retired.admission.private_id, "retired attempt private id changed");
        ensure!(slot_zero.state == "rejected", "retired attempt is not rejected");
        ensure!(slot_zero.plan_digest == retired.admission.plan_digest.as_hex(), "retired plan digest changed");
        ensure!(slot_zero.proof_digest == retired.admission.proof_digest.as_hex(), "retired proof digest changed");
        ensure!(slot_zero.sequence == retired.admission.sequence, "retired sequence changed");
        let slot_one = &attempts[1];
        ensure!(slot_one.slot == 1, "rotated attempt is not slot one");
        ensure!(slot_one.private_id == receipt.private_id, "rotated attempt private id differs");
        ensure!(slot_one.state == "committed", "rotated attempt is not committed");
        ensure!(slot_one.plan_digest == receipt.plan_digest.as_hex(), "rotated plan digest differs");
        ensure!(slot_one.proof_digest == receipt.proof_digest.as_hex(), "rotated proof digest differs");
        ensure!(slot_one.sequence > slot_zero.sequence, "rotated sequence did not advance the retired lane");
        ensure!(slot_one.base_revision == retired.gate.revision(), "rotated base revision is not P1");
        ensure!(slot_one.lane == slot_zero.lane, "rotated attempt switched issuer lane");

        ensure!(
            stored_ref(&db, retired.repository.id, REF_RETRY).await?.as_deref() == Some(retired.retry_oid.as_str()),
            "P2 did not apply the original P0 wire command to ref A"
        );
        ensure!(
            stored_ref(&db, retired.repository.id, "refs/heads/main").await?.as_deref()
                == Some(retired.verified.commit_oid.as_str()),
            "P2 changed the unrelated main ref"
        );
        ensure!(
            stored_ref(&db, retired.repository.id, REF_SIDE).await?.as_deref() == Some(retired.side_oid.as_str()),
            "P2 changed the unrelated P1 ref B"
        );
        ensure!(
            super::db::gate_version(&db.pool, retired.repository.id, retired.verified.tenant).await?.revision()
                == retired.gate.revision() + 1,
            "durable gate did not advance exactly once after P2"
        );

        match public_lookup(&db, &retired.public).await? {
            PublicAttemptLookup::Committed(evidence) => {
                ensure!(evidence.current.slot == 1, "mirrored current attempt is not slot one");
                ensure!(evidence.current.private_id == receipt.private_id, "mirrored current private id differs");
                ensure!(
                    evidence.current.state == OperationState::Committed,
                    "mirrored current attempt is not committed"
                );
                ensure!(evidence.current.event_id == Some(p2_event), "mirrored current event differs from P2");
                ensure!(
                    evidence.current.event_revision == Some(receipt.base_revision + 1),
                    "mirrored current event revision differs"
                );
                let retired_attempt = evidence
                    .retired
                    .as_ref()
                    .ok_or_else(|| anyhow!("mirrored wrapper has no retired slot-zero attempt"))?;
                ensure!(retired_attempt.slot == 0, "mirrored retired attempt is not slot zero");
                ensure!(
                    retired_attempt.private_id == retired.admission.private_id,
                    "mirrored retired private id changed"
                );
                ensure!(retired_attempt.state == OperationState::Rejected, "mirrored retired attempt is not rejected");
                ensure!(
                    retired_attempt.event_id == Some(retired.retirement.event_id),
                    "mirrored retired event id changed"
                );
            }
            other => bail!("mirrored public attempt is not committed: {other:?}"),
        }

        // The public terminal receipt and the durable wrapper expose no private
        // UUID; the private attempt is only asserted through exact SQL above.
        ensure!(
            !format!("{mirror:?}").contains(&receipt.private_id.to_string()),
            "public terminal mirror debug leaked the rotated private UUID"
        );
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL 17, S3/Garage Blob and native Git"]
async fn slot_one_handoff_revoked_fresh_rolls_back_and_replays_after_later_gate() -> Result<()> {
    require_owned_disposable_fixture()?;
    let db = super::db::Db::setup().await?;
    let outcome: Result<()> = async {
        require_postgres_17(&db).await?;
        let store = super::common::open_store()?;
        let git = super::git::git_binary()?;
        let retired = retire_p0_with_producer(&db, &store, &git).await?;
        let (state, _scratch) = gateway_state(&db, &store, &git)?;
        let serving = live_serving(&db, &store, &retired).await?;
        ensure!(
            serving.cluster_incarnation == retired.public.restore_incarnation,
            "live serving restore incarnation differs from P0"
        );
        let evidence = rejected_slot_zero(&db, &retired.public).await?;
        let baseline = capture_baseline(&db, retired.repository.id, retired.verified.tenant).await?;
        let body_dir = tempfile::tempdir()?;
        let body = write_p0_body(&body_dir, &retired)?;
        let retired_snapshot = ledger_snapshot(&db, retired.repository.id, retired.public.public_id).await?;

        // A real production token revocation must make the fresh gateway path
        // fail at its same-outer live authorization check, after the primitive
        // has written and released its savepoint. The outer rollback must leave
        // no slot-one candidate, sequence, operation, binding, event or ref.
        revoke_identity(&db.pool, &retired.actor).await?;
        let refused = acceptance::rotate_direct(
            &state,
            &serving,
            &retired.actor,
            retired.public.public_id,
            &body,
            &retired.p0_files.pack,
            &retired.p0_files.idx,
            &baseline,
            &evidence,
            &retired.retirement,
            deadline(),
        )
        .await;
        ensure!(
            matches!(refused, Err(GatewayError::Unauthorized)),
            "revoked fresh handoff did not fail the same-outer live authorization"
        );
        ensure!(
            ledger_snapshot(&db, retired.repository.id, retired.public.public_id).await? == retired_snapshot,
            "revoked fresh handoff left a durable candidate, sequence, ref or write effect"
        );
        let wrapper_after_refusal = wrapper_row(&db, retired.repository.id, retired.public.public_id).await?;
        ensure!(
            wrapper_after_refusal.current_slot == 0
                && wrapper_after_refusal.state == "rejected"
                && wrapper_after_refusal.retired_event_id.is_none()
                && wrapper_after_refusal.event_id == Some(retired.retirement.event_id),
            "revoked fresh handoff changed the slot-zero wrapper"
        );

        // Restore exactly the same user identity through the production token
        // path. The new token is a different live credential, not a mock.
        let restored = issue_identity(&db.pool, &retired.actor.username).await?;
        ensure!(restored.id == retired.actor.id, "restored token belongs to another user");
        let admission = acceptance::rotate_direct(
            &state,
            &serving,
            &restored,
            retired.public.public_id,
            &body,
            &retired.p0_files.pack,
            &retired.p0_files.idx,
            &baseline,
            &evidence,
            &retired.retirement,
            deadline(),
        )
        .await
        .map_err(acceptance::refusal)?;
        let (fresh_plan, fresh) = match admission {
            acceptance::Admission::Fresh { plan, receipt } => (plan, receipt),
            acceptance::Admission::Replayed(_) => bail!("restored fresh handoff replayed"),
        };
        assert_fresh_receipt(&retired, &fresh_plan, &fresh)?;
        let pending_snapshot = ledger_snapshot(&db, retired.repository.id, retired.public.public_id).await?;
        ensure!(pending_snapshot != retired_snapshot, "successful rotation did not record its private advancement");

        // A later real authorized commit on an unrelated ref advances the gate
        // while the exact slot-one rotation is still pending. It is not a new
        // slot-one candidate and does not mirror or rewrite the pending wrapper.
        let later_gate = advance_gate(&db, &store, &git, &retired, &restored).await?;
        ensure!(
            later_gate.revision() == retired.gate.revision() + 1,
            "later unrelated commit did not advance the gate exactly once"
        );
        let replay_baseline = capture_baseline(&db, retired.repository.id, retired.verified.tenant).await?;
        ensure!(replay_baseline.gate().revision() == later_gate.revision(), "replay baseline is not the later gate");
        let before_replay = ledger_snapshot(&db, retired.repository.id, retired.public.public_id).await?;

        let replay = acceptance::rotate_direct(
            &state,
            &serving,
            &restored,
            retired.public.public_id,
            &body,
            &retired.p0_files.pack,
            &retired.p0_files.idx,
            &replay_baseline,
            &evidence,
            &retired.retirement,
            deadline(),
        )
        .await
        .map_err(acceptance::refusal)?;
        let replay_receipt = match replay {
            acceptance::Admission::Replayed(receipt) => receipt,
            acceptance::Admission::Fresh { .. } => bail!("later-gate exact rotation was not a replay"),
        };
        ensure!(replay_receipt.replayed, "later-gate exact rotation did not report replay");
        ensure!(
            replay_receipt.private_id == fresh.private_id
                && replay_receipt.sequence == fresh.sequence
                && replay_receipt.base_revision == fresh.base_revision
                && replay_receipt.plan_digest == fresh.plan_digest
                && replay_receipt.proof_digest == fresh.proof_digest
                && replay_receipt.wire_digest == fresh.wire_digest,
            "later-gate replay changed the original private rotation"
        );
        ensure!(
            ledger_snapshot(&db, retired.repository.id, retired.public.public_id).await? == before_replay,
            "later-gate replay changed candidate, sequence, ref, event or write effects"
        );
        ensure!(
            operation_event_id(&db, retired.repository.id, retired.admission.private_id).await?
                == Some(retired.retirement.event_id),
            "later-gate replay changed the original P0 terminal"
        );

        // Revoked replay: the primitive proves the stored rotation, then the
        // same-outer live lookup refuses and rolls the whole transaction back.
        revoke_identity(&db.pool, &restored).await?;
        let refused_replay = acceptance::rotate_direct(
            &state,
            &serving,
            &restored,
            retired.public.public_id,
            &body,
            &retired.p0_files.pack,
            &retired.p0_files.idx,
            &replay_baseline,
            &evidence,
            &retired.retirement,
            deadline(),
        )
        .await;
        ensure!(
            matches!(refused_replay, Err(GatewayError::Unauthorized)),
            "revoked exact replay did not fail the same-outer live authorization"
        );
        ensure!(
            ledger_snapshot(&db, retired.repository.id, retired.public.public_id).await? == before_replay,
            "revoked exact replay left a durable effect"
        );

        // Restore a second time and prove the same live identity/realm still
        // replays the original pending rotation without any effect count change.
        let restored_again = issue_identity(&db.pool, &retired.actor.username).await?;
        ensure!(restored_again.id == retired.actor.id, "second restored token belongs to another user");
        let replay_again = acceptance::rotate_direct(
            &state,
            &serving,
            &restored_again,
            retired.public.public_id,
            &body,
            &retired.p0_files.pack,
            &retired.p0_files.idx,
            &replay_baseline,
            &evidence,
            &retired.retirement,
            deadline(),
        )
        .await
        .map_err(acceptance::refusal)?;
        match replay_again {
            acceptance::Admission::Replayed(receipt) => {
                ensure!(receipt == replay_receipt, "restored replay returned another receipt");
            }
            acceptance::Admission::Fresh { .. } => bail!("restored exact rotation was not a replay"),
        }
        ensure!(
            ledger_snapshot(&db, retired.repository.id, retired.public.public_id).await? == before_replay,
            "restored exact replay changed candidate, sequence, ref, event or write effects"
        );
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

fn gateway_state(db: &db::Db, store: &BlobStore, git: &Path) -> Result<(Arc<BlobGitState>, tempfile::TempDir)> {
    let scratch = tempfile::tempdir()?;
    let state = BlobGitState::new(BlobGitConfig {
        pool: db.pool.clone(),
        store: store.clone(),
        git_binary: git.to_path_buf(),
        scratch_root: scratch.path().to_path_buf(),
        max_concurrent_requests: 4,
        max_request_bytes: 16 * 1024 * 1024,
        max_response_bytes: 64 * 1024 * 1024,
        max_inflight_bytes: 64 * 1024 * 1024,
        operation_deadline: Duration::from_secs(120),
        native_limits: Default::default(),
    })
    .map_err(|error| anyhow!("slot-one gateway state refused: {error}"))?;
    Ok((Arc::new(state), scratch))
}

async fn live_serving(db: &db::Db, store: &BlobStore, retired: &Retired) -> Result<ServingRepository> {
    serving::lookup(
        &db.pool,
        &retired.actor,
        &retired.repository.owner,
        &retired.repository.name,
        true,
        store.backend_identity(),
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("live serving lookup failed: {error}"))
}

fn write_p0_body(dir: &tempfile::TempDir, retired: &Retired) -> Result<PathBuf> {
    let body = dir.path().join("slot-zero-p0.request");
    acceptance::write_producer_body(
        &body,
        &retired.p0_files.pack,
        retired.public.object_format,
        REF_RETRY,
        None,
        &retired.retry_oid,
        true,
    )?;
    Ok(body)
}

fn assert_fresh_receipt(retired: &Retired, plan: &PackCommitPlan, receipt: &acceptance::ReceiptView) -> Result<()> {
    ensure!(!receipt.replayed, "fresh receipt is marked replayed");
    ensure!(receipt.state == OperationState::Pending, "fresh receipt is not pending");
    ensure!(receipt.public_id == retired.public.public_id, "fresh receipt public id differs");
    ensure!(receipt.private_id != retired.admission.private_id, "fresh receipt reused the retired private id");
    ensure!(receipt.retired_private_id == retired.admission.private_id, "fresh receipt retired private id differs");
    ensure!(receipt.retired_event_id == retired.retirement.event_id, "fresh receipt retired event differs");
    ensure!(
        receipt.retired_event_revision == retired.retirement.event_revision,
        "fresh receipt retired event revision differs"
    );
    ensure!(
        receipt.base_revision == retired.gate.revision() && receipt.base_revision == plan.expected().revision(),
        "fresh receipt base revision is not the advanced P1 gate"
    );
    ensure!(receipt.sequence > retired.admission.sequence, "fresh receipt sequence did not advance");
    ensure!(receipt.plan_digest == *plan.parent_digest(), "fresh receipt plan digest differs from its plan");
    ensure!(receipt.plan_digest != retired.admission.plan_digest, "fresh receipt reused the retired plan digest");
    ensure!(receipt.proof_digest != retired.admission.proof_digest, "fresh receipt reused the retired proof digest");
    ensure!(receipt.wire_digest == retired.public.wire_digest, "fresh receipt changed the producer wire digest");
    ensure!(
        plan.identity().operation_id() == receipt.private_id
            && plan.identity().sequence() == receipt.sequence
            && plan.identity().lane().as_str() == retired.plan.identity().lane().as_str(),
        "fresh plan identity does not match the rotation receipt"
    );
    ensure!(plan.refs() == retired.plan.refs(), "fresh plan changed the exact original ref command");
    Ok(())
}

async fn advance_gate(
    db: &db::Db,
    store: &BlobStore,
    git: &Path,
    retired: &Retired,
    actor: &Identity,
) -> Result<CoreGateVersion> {
    let format = retired.verified.gate.object_format();
    let later_oid =
        child_commit(&retired.verified.fixture, &retired.verified.commit_oid, "later.txt", b"later gate\n", "later")
            .await?;
    retired.verified.fixture.update_ref(REF_LATER, &later_oid).await?;
    let files = retired.verified.fixture.pack_all("slot-one-later").await?;
    let draft = pack::draft(
        db,
        retired.repository.id,
        retired.verified.tenant,
        3,
        &retired.gate,
        vec![ref_update(format, REF_LATER, None, &later_oid)?],
        std::slice::from_ref(&files),
    )
    .await?;
    stage(db, store, &draft.plan, &files).await?;
    let committed = authorized_commit(db, store, git, actor, draft.plan).await?;
    ensure!(
        committed.terminal.revision == retired.gate.revision() + 1,
        "later authorized commit did not advance the gate exactly once"
    );
    ensure!(
        stored_ref(db, retired.repository.id, REF_LATER).await?.as_deref() == Some(later_oid.as_str()),
        "later authorized commit did not apply its own ref"
    );
    super::db::gate_version(&db.pool, retired.repository.id, retired.verified.tenant).await
}

async fn rejected_slot_zero(db: &db::Db, public: &PublicAttemptRequest) -> Result<PublicAttemptEvidence> {
    match public_lookup(db, public).await? {
        PublicAttemptLookup::Rejected(evidence)
            if evidence.current.slot == 0
                && evidence.current.state == OperationState::Rejected
                && evidence.retired.is_none() =>
        {
            Ok(evidence)
        }
        _ => bail!("retirement selection is not the exact current slot-zero rejection"),
    }
}

async fn public_lookup(db: &db::Db, request: &PublicAttemptRequest) -> Result<PublicAttemptLookup> {
    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    let result = PgRefStore.lookup_public_attempt(&tx, request, deadline()).await;
    tx.rollback().await?;
    result.map_err(|error| anyhow!("public attempt lookup failed: {error:?}"))
}

async fn mirror_committed_terminal(
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
            bail!("committed slot-one terminal mirror requested retirement")
        }
        Err(error) => {
            tx.rollback().await?;
            Err(anyhow!("committed slot-one terminal mirror failed: {error:?}"))
        }
    }
}

async fn wrapper_row(db: &db::Db, repository_id: Uuid, public_id: Uuid) -> Result<WrapperRow> {
    let row = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT current_slot,state,event_id,retired_event_id,cancelled_private_id,
                    restore_incarnation,backend_identity,object_format
               FROM ref_store_public_operations
              WHERE repository_id=$1 AND public_id=$2",
            &[&repository_id, &public_id],
        )
        .await?;
    Ok(WrapperRow {
        current_slot: row.get(0),
        state: row.get(1),
        event_id: row.get(2),
        retired_event_id: row.get(3),
        cancelled_private_id: row.get(4),
        restore_incarnation: row.get(5),
        backend_identity: row.get(6),
        object_format: row.get(7),
    })
}

async fn attempt_rows(db: &db::Db, repository_id: Uuid, public_id: Uuid) -> Result<Vec<AttemptRow>> {
    let rows = db
        .pool
        .get()
        .await?
        .query(
            "SELECT a.slot,a.private_id,a.plan_digest,a.proof_digest,a.base_revision,
                    o.lane,o.sequence,o.state
               FROM ref_store_private_attempts a
               JOIN ref_store_operations o
                 ON o.repository_id=a.repository_id AND o.operation_id=a.private_id
              WHERE a.repository_id=$1 AND a.public_id=$2
              ORDER BY a.slot",
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
            lane: row.get(5),
            sequence: row.get(6),
            state: row.get(7),
        })
        .collect())
}

async fn ledger_snapshot(db: &db::Db, repository_id: Uuid, public_id: Uuid) -> Result<Value> {
    let row = db.pool.get().await?.query_one(LEDGER_SNAPSHOT, &[&repository_id, &public_id]).await?;
    Ok(row.get(0))
}

async fn revoke_identity(pool: &Pool, identity: &Identity) -> Result<()> {
    revoke_token(pool, identity, identity.token_id)
        .await
        .map_err(|error| anyhow!("actor token revocation failed: {error}"))
}

async fn issue_identity(pool: &Pool, username: &str) -> Result<Identity> {
    let issued = product_db::issue_token(pool, username, false, false).await?;
    let secret = issued["token"].as_str().ok_or_else(|| anyhow!("issued token has no secret"))?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|_| anyhow!("issued token header refused"))?,
    );
    auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("restored token authentication failed: {}", error.1))
}
