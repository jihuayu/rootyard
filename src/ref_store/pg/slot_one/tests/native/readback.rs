//! Durable operation/ref/publication/attempt readback and A5 snapshot checks.

use super::db::deadline;
use super::{REF_RETRY, REF_SIDE, Retired, SLOT_ZERO_LANE, db, pack};
use anyhow::{Result, anyhow, bail, ensure};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::{
    CapturedRef, IssuerLane, OperationLookup, OperationRecord, OperationState,
    core::pack_commit::{PackCommitPlan, PackCommitTerminal},
    pg::{
        PgRefStore,
        public_attempt::{PublicAttempt, PublicAttemptEvidence, PublicAttemptRequest},
        public_terminal::PublicAttemptRetirement,
        slot_one::SlotOneRotationReceipt,
        slot_zero::SlotZeroReceipt,
    },
};
use uuid::Uuid;

pub(super) async fn operation_record(db: &db::Db, repository_id: Uuid, operation_id: Uuid) -> Result<OperationRecord> {
    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    let lookup = PgRefStore
        .get(&tx, repository_id, operation_id, deadline())
        .await
        .map_err(|_| anyhow!("operation lookup failed"))?;
    tx.rollback().await?;
    match lookup {
        OperationLookup::Known(record) => Ok(record),
        _ => bail!("operation is not visible"),
    }
}

pub(super) async fn stored_ref(db: &db::Db, repository_id: Uuid, name: &str) -> Result<Option<String>> {
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

pub(super) async fn operation_event_id(db: &db::Db, repository_id: Uuid, operation_id: Uuid) -> Result<Option<Uuid>> {
    let row = db
        .pool
        .get()
        .await?
        .query_opt(
            "SELECT event_id FROM ref_store_core_events WHERE repository_id=$1 AND operation_id=$2",
            &[&repository_id, &operation_id],
        )
        .await?;
    Ok(row.map(|row| row.get(0)))
}

/// Independently prove the legal slot-zero retirement boundary and derive the
/// private evidence the gateway handoff consumes.
///
/// The public resolver intentionally refuses a slot-zero private rejection whose
/// wrapper is still pending, so this fixture must not ask it for a `Rejected`
/// answer. Instead this reads the durable private attempt, operation, event and
/// pending wrapper in one statement and checks every field against the admission
/// receipt and the retirement selected by the production mirror. It writes
/// nothing and never relaxes the resolver's own consistency checks.
pub(super) async fn private_retirement_evidence(
    db: &db::Db,
    public: &PublicAttemptRequest,
    admission: &SlotZeroReceipt,
    retirement: &PublicAttemptRetirement,
) -> Result<PublicAttemptEvidence> {
    let row = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT a.slot,a.private_id,a.plan_digest,a.proof_digest,a.base_revision,
                    o.lane,o.sequence,o.state,
                    e.event_id,e.revision,e.outcome,
                    w.current_slot,w.state,w.event_id,w.retired_event_id,w.cancelled_private_id
               FROM ref_store_private_attempts a
               JOIN ref_store_operations o
                 ON o.repository_id=a.repository_id AND o.operation_id=a.private_id
               JOIN ref_store_core_events e
                 ON e.repository_id=a.repository_id AND e.operation_id=a.private_id
               JOIN ref_store_public_operations w
                 ON w.repository_id=a.repository_id AND w.public_id=a.public_id
              WHERE a.repository_id=$1 AND a.public_id=$2 AND a.slot=0",
            &[&public.repository_id, &public.public_id],
        )
        .await?;
    let slot: i16 = row.get(0);
    let private_id: Uuid = row.get(1);
    let plan_digest: String = row.get(2);
    let proof_digest: String = row.get(3);
    let base_revision: i64 = row.get(4);
    let lane: String = row.get(5);
    let sequence: i64 = row.get(6);
    let state: String = row.get(7);
    let event_id: Uuid = row.get(8);
    let event_revision: i64 = row.get(9);
    let outcome: String = row.get(10);
    let wrapper_slot: i16 = row.get(11);
    let wrapper_state: String = row.get(12);
    let wrapper_event_id: Option<Uuid> = row.get(13);
    let wrapper_retired_event_id: Option<Uuid> = row.get(14);
    let wrapper_cancelled_private_id: Option<Uuid> = row.get(15);

    ensure!(slot == 0, "retirement private attempt is not slot zero");
    ensure!(private_id == admission.private_id, "retirement private attempt id differs from admission");
    ensure!(plan_digest == admission.plan_digest.as_hex(), "retirement private plan digest differs from admission");
    ensure!(proof_digest == admission.proof_digest.as_hex(), "retirement private proof digest differs from admission");
    ensure!(base_revision == admission.base_revision, "retirement private base revision differs from admission");
    ensure!(lane == SLOT_ZERO_LANE, "retirement private operation is not on the slot-zero lane");
    ensure!(sequence == admission.sequence, "retirement private sequence differs from admission");
    ensure!(state == OperationState::Rejected.as_str(), "retirement private operation is not rejected");
    ensure!(event_id == retirement.event_id, "retirement private event differs from the selected retirement");
    ensure!(
        event_revision == retirement.event_revision,
        "retirement private event revision differs from the selected retirement"
    );
    ensure!(outcome == OperationState::Rejected.as_str(), "retirement private event is not a rejection");
    ensure!(
        wrapper_slot == 0
            && wrapper_state == OperationState::Pending.as_str()
            && wrapper_event_id.is_none()
            && wrapper_retired_event_id.is_none()
            && wrapper_cancelled_private_id.is_none(),
        "legal retirement boundary wrapper is not pending slot zero without a public event"
    );

    Ok(PublicAttemptEvidence {
        public_id: public.public_id,
        current: PublicAttempt {
            slot,
            private_id,
            plan_digest: admission.plan_digest,
            proof_digest: admission.proof_digest,
            base_revision,
            lane: IssuerLane::new(lane).map_err(|_| anyhow!("retirement private lane is not canonical"))?,
            sequence,
            state: OperationState::Rejected,
            event_id: Some(event_id),
            event_revision: Some(event_revision),
        },
        retired: None,
    })
}

pub(super) async fn public_attempt_event_count(db: &db::Db, repository_id: Uuid, public_id: Uuid) -> Result<i64> {
    let row = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT count(*)
               FROM ref_store_core_events e
              WHERE e.repository_id=$1
                AND e.operation_id IN (
                    SELECT a.private_id
                      FROM ref_store_private_attempts a
                     WHERE a.repository_id=$1 AND a.public_id=$2
                )",
            &[&repository_id, &public_id],
        )
        .await?;
    Ok(row.get(0))
}

pub(super) async fn assert_a5_after_rotation(
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
pub(super) struct PublicationRow {
    pub(super) plan_operation_id: Uuid,
    pub(super) parent_digest: String,
    pub(super) pack_id: Uuid,
    pub(super) registration_id: Uuid,
    pub(super) gate_revision: i64,
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

pub(super) async fn publication_for(db: &db::Db, repository_id: Uuid, operation_id: Uuid) -> Result<PublicationRow> {
    let mut matching =
        publication_rows(db, repository_id).await?.into_iter().filter(|row| row.plan_operation_id == operation_id);
    let row = matching.next().ok_or_else(|| anyhow!("publication row is missing for the operation"))?;
    ensure!(matching.next().is_none(), "operation has more than one publication row");
    Ok(row)
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct AttemptRow {
    slot: i16,
    private_id: Uuid,
    plan_digest: String,
    proof_digest: String,
    base_revision: i64,
}

pub(super) async fn attempt_rows(db: &db::Db, repository_id: Uuid, public_id: Uuid) -> Result<Vec<AttemptRow>> {
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

pub(super) async fn assert_no_registry_promotion(
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
