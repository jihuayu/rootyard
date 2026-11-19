//! Read-only hosted witness for the staged public-reclaim discovery seam.
//!
//! This case reuses the real P0/P1/P2 slot-one fixture and terminal mirror to
//! create genuine migration-141 holds, one-shot consume receipts and
//! migration-142 pack registrations for the retired slot-zero and current
//! slot-one attempts. It then opens an explicit `READ ONLY` `REPEATABLE READ`
//! transaction and asks the sealed production discovery seam for the two
//! selected attempts.
//!
//! The witness proves only observability:
//! * both private attempt lanes and their exact plan/event evidence are visible;
//! * every selected hold is `Registered` with the real M142 registration/pack;
//! * the retained Blob objects still exist by exact stored locator;
//! * wrong isolation or a writable transaction is refused before any attempt or
//!   hold state is read;
//! * the reader changes no wrapper, attempt, operation, event, hold, receipt,
//!   publication, artifact, membership, gate or ref row.
//!
//! It intentionally does not assert quiescence, completion, deletion authority
//! or a live GC outcome. The production witness remains unwired.
//!
//! Explicit hosted invocation requires an owned disposable PostgreSQL 17
//! database, an owned disposable S3-compatible (Garage) bucket/prefix and the
//! stock Git binary:
//!
//! ```text
//! ROOTYARD_TEST_OWNED_DISPOSABLE_POSTGRES=1 \
//! ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB=1 \
//! ROOTYARD_TEST_DATABASE_URL=postgresql://... \
//! ROOTYARD_BLOB_DRIVER=opendal ROOTYARD_BLOB_SERVICE=s3 \
//! ROOTYARD_BLOB_ENDPOINT=... ROOTYARD_BLOB_BUCKET=... ROOTYARD_BLOB_REGION=... \
//! ROOTYARD_BLOB_ACCESS_KEY_ID=... ROOTYARD_BLOB_SECRET_ACCESS_KEY=... \
//! ROOTYARD_BLOB_ROOT=public-reclaim-witness-<unique> ROOTYARD_TEST_GIT=/absolute/git \
//! cargo test --locked --no-default-features --lib \
//!   ref_store::pg::slot_one::tests::native::reclaim::public_reclaim_discovery_reads_both_real_slots_read_only \
//!   -- --ignored --exact --test-threads=1
//! ```

use super::{
    Retired, common, db, git,
    readback::operation_event_id,
    retirement::retire_p0,
    rotation::{mirror_p2_terminal_and_prove_replay, rotate_and_commit},
    setup::{require_owned_disposable_fixture, require_postgres_17},
};
use anyhow::{Result, anyhow, bail, ensure};
use rootyard::blob_store::{BlobLocator, opendal::BlobStore};
use rootyard::ref_store::{
    OperationState,
    pg::{
        PgRefStore,
        public_reclaim::{
            PublicReclaimArtifactRole, PublicReclaimHoldDisposition, PublicReclaimLookup, PublicReclaimTestView,
            is_stable_snapshot_refusal,
        },
        slot_one::SlotOneRotationReceipt,
    },
};
use serde_json::Value;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires real PostgreSQL 17, S3/Garage Blob and native Git"]
async fn public_reclaim_discovery_reads_both_real_slots_read_only() -> Result<()> {
    require_owned_disposable_fixture()?;
    let db = db::Db::setup().await?;
    let outcome: Result<()> = async {
        require_postgres_17(&db).await?;
        let store = common::open_store()?;
        let git = git::git_binary()?;
        let retired = retire_p0(&db, &store, &git).await?;
        let (_, rotation, gate) = rotate_and_commit(&db, &store, &git, &retired).await?;
        ensure!(
            gate.revision() == retired.gate.revision() + 1,
            "P2 did not advance the gate exactly one revision"
        );
        mirror_p2_terminal_and_prove_replay(&db, &retired, &rotation).await?;
        assert_read_only_witness(&db, &store, &retired, &rotation).await
    }
    .await;
    db.finish(outcome).await
}

struct ExpectedHold {
    attempt_slot: i16,
    operation_id: Uuid,
    request_id: Uuid,
    hold_id: Uuid,
    hold_slot: i16,
    role: PublicReclaimArtifactRole,
    registration_id: Uuid,
    pack_id: Uuid,
    provider: String,
    backend_identity: String,
    storage_attempt_id: Uuid,
    content_sha256: String,
    content_length: u64,
    locator: BlobLocator,
}

async fn expected_holds(
    db: &db::Db,
    repository_id: Uuid,
    public_id: Uuid,
    private_ids: &[Uuid],
) -> Result<Vec<ExpectedHold>> {
    let ids = private_ids.to_vec();
    let rows = db
        .pool
        .get()
        .await?
        .query(
            "SELECT pa.public_id,pa.slot,h.operation_id,pa.plan_digest,h.request_id,h.hold_id,h.slot,
                    h.provider,h.backend_identity,a.role,a.registration_id,a.pack_id,c.consume_request_id,
                    h.storage_tenant_id,h.authority_id,h.authority_generation,h.attempt_id,h.namespace,
                    h.sha256,h.content_length,p.plan_operation_id,h.operation_digest,
                    p.parent_digest,p.backend_identity,a.consume_request_id
               FROM artifact_holds h
               JOIN artifact_hold_consume_receipts c
                 ON c.hold_id=h.hold_id AND c.request_id=h.request_id
               JOIN ref_store_core_pack_artifacts a
                 ON a.acquire_request_id=h.request_id AND a.hold_id=h.hold_id
               JOIN ref_store_core_pack_publications p ON p.registration_id=a.registration_id
               JOIN ref_store_private_attempts pa
                 ON pa.repository_id=h.repository_id AND pa.private_id=h.operation_id AND pa.public_id=$2
              WHERE h.repository_id=$1 AND h.operation_id=ANY($3::uuid[])
              ORDER BY pa.slot,h.request_id,h.slot",
            &[&repository_id, &public_id, &ids],
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let expected_public: Uuid = row.get(0);
        let attempt_slot: i16 = row.get(1);
        let operation_id: Uuid = row.get(2);
        let plan_digest: String = row.get(3);
        let request_id: Uuid = row.get(4);
        let hold_id: Uuid = row.get(5);
        let hold_slot = i16::try_from(row.get::<_, i32>(6))?;
        let provider: String = row.get(7);
        let backend_identity: String = row.get(8);
        let role_text: String = row.get(9);
        let registration_id: Uuid = row.get(10);
        let pack_id: Uuid = row.get(11);
        let consume_request_id: Uuid = row.get(12);
        let storage_tenant_id: Uuid = row.get(13);
        let authority_id: Uuid = row.get(14);
        let authority_generation: i64 = row.get(15);
        let attempt_id: Uuid = row.get(16);
        let namespace: String = row.get(17);
        let sha256: String = row.get(18);
        let content_length = u64::try_from(row.get::<_, i64>(19))?;
        let plan_operation_id: Uuid = row.get(20);
        let operation_digest: String = row.get(21);
        let publication_parent: String = row.get(22);
        let publication_backend: String = row.get(23);
        let artifact_consume: Uuid = row.get(24);
        ensure!(expected_public == public_id, "hold row names another public operation");
        ensure!(plan_digest == operation_digest, "hold operation digest differs from its M152 attempt");
        ensure!(plan_operation_id == operation_id, "M142 publication names another private operation");
        ensure!(publication_parent == plan_digest, "M142 publication parent digest differs from its plan");
        ensure!(publication_backend == backend_identity, "M142 publication backend differs from its hold");
        ensure!(artifact_consume == consume_request_id, "M142 artifact consume request differs from its receipt");
        ensure!(!registration_id.is_nil() && !pack_id.is_nil(), "hold has a nil registration/pack identity");
        ensure!(!consume_request_id.is_nil(), "hold has a nil consume request");
        let role = match role_text.as_str() {
            "pack" => PublicReclaimArtifactRole::Pack,
            "idx" => PublicReclaimArtifactRole::Index,
            _ => bail!("hold has an unexpected M142 artifact role"),
        };
        ensure!(
            (role == PublicReclaimArtifactRole::Pack) == (hold_slot == 0),
            "hold slot differs from its M142 artifact role"
        );
        let locator = BlobLocator::new(
            storage_tenant_id,
            authority_id,
            authority_generation,
            attempt_id,
            &namespace,
            &sha256,
            content_length,
        )?;
        out.push(ExpectedHold {
            attempt_slot,
            operation_id,
            request_id,
            hold_id,
            hold_slot,
            role,
            registration_id,
            pack_id,
            provider,
            backend_identity,
            storage_attempt_id: attempt_id,
            content_sha256: sha256,
            content_length,
            locator,
        });
    }
    Ok(out)
}

/// Full read-only row snapshots used to prove the reader performed no mutation.
async fn reader_state(db: &db::Db, repository_id: Uuid, public_id: Uuid) -> Result<Value> {
    let row = db
        .pool
        .get()
        .await?
        .query_one(
            r#"SELECT jsonb_build_object(
                 'refs',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.ref_name),'[]'::jsonb)
                           FROM ref_store_core_refs t WHERE t.repository_id=$1),
                 'gate',(SELECT to_jsonb(t) FROM ref_store_core_gates t WHERE t.repository_id=$1),
                 'wrapper',(SELECT to_jsonb(t) FROM ref_store_public_operations t
                             WHERE t.repository_id=$1 AND t.public_id=$2),
                 'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.slot),'[]'::jsonb)
                               FROM ref_store_private_attempts t WHERE t.repository_id=$1 AND t.public_id=$2),
                 'operations',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.operation_id),'[]'::jsonb)
                                 FROM ref_store_operations t WHERE t.repository_id=$1),
                 'events',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.event_id),'[]'::jsonb)
                             FROM ref_store_core_events t WHERE t.repository_id=$1),
                 'hold_requests',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.request_id),'[]'::jsonb)
                                    FROM artifact_hold_requests t WHERE t.repository_id=$1),
                 'holds',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.hold_id),'[]'::jsonb)
                            FROM artifact_holds t WHERE t.repository_id=$1),
                 'receipts',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.hold_id),'[]'::jsonb)
                               FROM artifact_hold_consume_receipts t WHERE t.repository_id=$1),
                 'publications',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.registration_id),'[]'::jsonb)
                                   FROM ref_store_core_pack_publications t WHERE t.repository_id=$1),
                 'artifacts',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.registration_id,t.role),'[]'::jsonb)
                                FROM ref_store_core_pack_artifacts t WHERE t.repository_id=$1),
                 'memberships',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.pack_id),'[]'::jsonb)
                                  FROM ref_store_core_pack_memberships t WHERE t.repository_id=$1)
               )"#,
            &[&repository_id, &public_id],
        )
        .await?;
    Ok(row.get(0))
}

async fn assert_wrong_mode_refused(
    db: &db::Db,
    request: &rootyard::ref_store::pg::public_attempt::PublicAttemptRequest,
    isolation: IsolationLevel,
    read_only: bool,
) -> Result<()> {
    let mut client = db.pool.get().await?;
    let tx = tokio_postgres::Client::build_transaction(&mut *client)
        .isolation_level(isolation)
        .read_only(read_only)
        .start()
        .await?;
    let result = PgRefStore.discover_public_reclaim(&tx, request, db::deadline()).await;
    tx.rollback().await?;
    match result {
        Err(error) if is_stable_snapshot_refusal(&error) => Ok(()),
        Err(error) => Err(anyhow!("wrong-mode discovery raised an unexpected error: {error:?}")),
        Ok(_) => bail!("wrong-mode discovery produced a success witness"),
    }
}

async fn read_discovery(
    db: &db::Db,
    request: &rootyard::ref_store::pg::public_attempt::PublicAttemptRequest,
) -> Result<PublicReclaimTestView> {
    let mut client = db.pool.get().await?;
    let tx = tokio_postgres::Client::build_transaction(&mut *client)
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let result = PgRefStore.discover_public_reclaim(&tx, request, db::deadline()).await;
    tx.rollback().await?;
    let lookup = result.map_err(|error| anyhow!("sealed discovery failed: {error:?}"))?;
    match lookup {
        PublicReclaimLookup::Found(found) => Ok(found.test_view()),
        other => Err(anyhow!("sealed discovery did not return a bounded success witness: {other:?}")),
    }
}

async fn assert_read_only_witness(
    db: &db::Db,
    store: &BlobStore,
    retired: &Retired,
    p2: &SlotOneRotationReceipt,
) -> Result<()> {
    let before = reader_state(db, retired.repository.id, retired.public.public_id).await?;
    let private_ids = vec![retired.admission.private_id, p2.private_id];
    let expected = expected_holds(db, retired.repository.id, retired.public.public_id, &private_ids).await?;
    ensure!(expected.len() == 4, "expected exactly two P0 and two P2 retained holds, got {}", expected.len());
    ensure!(
        expected.iter().filter(|hold| hold.operation_id == retired.admission.private_id).count() == 2,
        "retired slot-zero does not have exactly one retained pack/idx pair"
    );
    ensure!(
        expected.iter().filter(|hold| hold.operation_id == p2.private_id).count() == 2,
        "current slot-one does not have exactly one retained pack/idx pair"
    );
    ensure!(
        expected.iter().all(|hold| hold.backend_identity == retired.public.backend_identity),
        "a retained hold names another physical backend"
    );

    // Reject a writable repeatable-read transaction and a read-only transaction
    // at the wrong isolation before the successful snapshot below.
    assert_wrong_mode_refused(db, &retired.public, IsolationLevel::RepeatableRead, false).await?;
    assert_wrong_mode_refused(db, &retired.public, IsolationLevel::ReadCommitted, true).await?;

    let p2_event = operation_event_id(db, retired.repository.id, p2.private_id)
        .await?
        .ok_or_else(|| anyhow!("P2 committed operation has no core event"))?;
    let view = read_discovery(db, &retired.public).await?;
    let after = reader_state(db, retired.repository.id, retired.public.public_id).await?;
    ensure!(before == after, "read-only discovery changed durable publication/hold/ref state");

    for hold in &expected {
        let head = store
            .head(&hold.locator, db::deadline())
            .await
            .map_err(|error| anyhow!("retained object head failed: {error}"))?;
        ensure!(
            head == Some(hold.content_length),
            "retained object length differs for hold {}",
            hold.hold_id
        );
    }

    assert_view_matches(&view, &expected, retired, p2, p2_event)?;
    Ok(())
}

fn assert_view_matches(
    view: &PublicReclaimTestView,
    expected: &[ExpectedHold],
    retired: &Retired,
    p2: &SlotOneRotationReceipt,
    p2_event: Uuid,
) -> Result<()> {
    ensure!(view.public_id == retired.public.public_id, "discovery public identity differs");
    ensure!(view.state == OperationState::Committed, "discovery wrapper is not committed");
    ensure!(view.slots.len() == 2, "discovery did not return exactly two attempt slots");
    let slot_zero = view
        .slots
        .iter()
        .find(|slot| slot.slot == 0)
        .ok_or_else(|| anyhow!("discovery omitted retired slot zero"))?;
    let slot_one =
        view.slots.iter().find(|slot| slot.slot == 1).ok_or_else(|| anyhow!("discovery omitted current slot one"))?;
    ensure!(
        slot_zero.private_id == retired.admission.private_id,
        "discovery retired private id differs from P0"
    );
    ensure!(slot_zero.state == OperationState::Rejected, "discovery retired attempt is not rejected");
    ensure!(slot_zero.plan_digest == retired.admission.plan_digest, "discovery retired plan digest differs");
    ensure!(slot_zero.proof_digest == retired.admission.proof_digest, "discovery retired proof digest differs");
    ensure!(slot_zero.base_revision == retired.admission.base_revision, "discovery retired base revision differs");
    ensure!(
        slot_zero.event_id == Some(retired.retirement.event_id),
        "discovery retired event id differs from the selected retirement"
    );
    ensure!(
        slot_zero.event_revision == Some(retired.retirement.event_revision),
        "discovery retired event revision differs from the selected retirement"
    );
    ensure!(slot_one.private_id == p2.private_id, "discovery current private id differs from P2");
    ensure!(slot_one.state == OperationState::Committed, "discovery current attempt is not committed");
    ensure!(slot_one.plan_digest == p2.plan_digest, "discovery current plan digest differs");
    ensure!(slot_one.proof_digest == p2.proof_digest, "discovery current proof digest differs");
    ensure!(slot_one.base_revision == p2.base_revision, "discovery current base revision differs");
    ensure!(slot_one.event_id == Some(p2_event), "discovery current event id differs from the P2 terminal");
    ensure!(
        slot_one.event_revision == Some(p2.base_revision + 1),
        "discovery current event revision differs from the P2 mirror"
    );
    for slot in view.slots.iter() {
        let expected_len = expected.iter().filter(|hold| hold.attempt_slot == slot.slot).count();
        ensure!(slot.holds.len() == expected_len, "discovery hold count differs for attempt slot {}", slot.slot);
    }
    for expected_hold in expected {
        let slot = view
            .slots
            .iter()
            .find(|slot| slot.slot == expected_hold.attempt_slot)
            .ok_or_else(|| anyhow!("discovery omitted an expected attempt slot"))?;
        let hold = slot
            .holds
            .iter()
            .find(|hold| hold.hold_id == expected_hold.hold_id)
            .ok_or_else(|| anyhow!("discovery omitted an expected retained hold"))?;
        ensure!(hold.request_id == expected_hold.request_id, "discovery hold request id differs");
        ensure!(hold.slot == expected_hold.hold_slot, "discovery hold slot differs");
        ensure!(hold.role == Some(expected_hold.role), "discovery hold role differs");
        ensure!(
            hold.disposition
                == PublicReclaimHoldDisposition::Registered {
                    registration_id: expected_hold.registration_id,
                    pack_id: expected_hold.pack_id,
                },
            "discovery hold is not the real registered pair"
        );
        ensure!(hold.backend_identity == expected_hold.backend_identity, "discovery hold backend differs");
        ensure!(hold.provider == expected_hold.provider, "discovery hold provider differs");
        ensure!(hold.storage_attempt_id == expected_hold.storage_attempt_id, "discovery hold storage attempt differs");
        ensure!(hold.content_sha256 == expected_hold.content_sha256, "discovery hold digest differs");
        ensure!(hold.content_length == expected_hold.content_length, "discovery hold length differs");
        let expected_path = expected_hold.locator.path();
        ensure!(
            hold.locator_path.as_deref() == Some(expected_path.as_str()),
            "discovery hold locator path differs"
        );
    }
    Ok(())
}
