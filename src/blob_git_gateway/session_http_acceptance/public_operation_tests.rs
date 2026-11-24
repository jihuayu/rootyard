//! Owned PostgreSQL/Blob HTTP proof for the public operation GET route.
//!
//! One ignored case creates a random, disposable database whose `public` schema
//! is migrated (migration 152 names `public.cluster_authority`), starts the real
//! production router over the real Blob store, admits a pending public/private
//! pair through the actual slot-zero planner/adaptor, and drives the existing
//! authenticated GET endpoint as a network client. No wrapper row or JSON
//! response is fabricated.
use anyhow::{Result, ensure};
use reqwest::{StatusCode, header};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    fixtures::{
        actor::{self, Actor},
        db::{Db, deadline},
    },
    support::{Gateway, open_store, test_tokens},
};
use crate::{
    blob_git_gateway::NATIVE_ACCEPTANCE_SERIAL,
    ref_store::{
        CommitMode, GitObjectFormat, IssuerLane, OperationIdentity, OperationState, PgRefStore, RequestDigest,
        core::{
            GitOid, HeadUpdate, RefName, RefPrecondition, RefUpdate,
            pack_commit::{
                MembershipDigest, PackCommitError, PackCommitExpectation, PackCommitPlan, PackCommitScope, PackMode,
            },
        },
        pg::slot_zero::{SlotZeroAdmissionRequest, SlotZeroPreview},
    },
};

#[tokio::test]
#[ignore = "requires real PostgreSQL with CREATEDB, S3-compatible Blob and native Git"]
async fn public_operation_get_is_owned_pending_and_private_safe() -> Result<()> {
    let _serial = NATIVE_ACCEPTANCE_SERIAL.lock().await;
    let db = Db::setup_public_owned().await?;
    let outcome = case(&db).await;
    db.finish(outcome).await
}

async fn case(db: &Db) -> Result<()> {
    let store = open_store()?;
    let tokens = test_tokens(store.backend_identity())?;
    let gateway = Gateway::start(db, store, tokens).await?;
    let owner = actor::owner(&db.pool).await?;

    let name = super::support::unique_name("public-op");
    gateway.create_repository(&owner, &name).await?;
    gateway.provision_decision_realm(db, &owner, &name).await?;
    let serving = super::support::serving(db, &gateway, &owner, &name, true).await?;
    let public_id = Uuid::new_v4();
    let private_id = Uuid::new_v4();
    ensure!(public_id != private_id, "public and private ids aliased");

    let client = reqwest::Client::new();
    let base = gateway.base(&owner.username, &name);
    let public_path = format!("{base}/operations/{public_id}");

    // The future public id is genuinely absent before the real admission.
    let absent = client.get(&public_path).bearer_auth(&owner.token).send().await?;
    ensure!(absent.status() == StatusCode::NOT_FOUND, "absent public id GET was not 404");
    let absent_body: Value = absent.json().await?;
    ensure!(absent_body["error"] == json!("not found"), "absent public-id refusal changed");
    ensure_public_safe(&absent_body, &[public_id, private_id], "absent public-id refusal")?;

    admit_pending_public(db, &gateway, &owner, &serving, public_id, private_id).await?;

    // The original issuer sees the exact admitted public identity as pending.
    let answer = client.get(&public_path).bearer_auth(&owner.token).send().await?;
    ensure!(answer.status() == StatusCode::OK, "original issuer public GET was not 200");
    ensure!(
        answer.headers().get(header::CACHE_CONTROL).and_then(|value| value.to_str().ok()) == Some("no-store"),
        "public operation GET did not send Cache-Control: no-store"
    );
    let body: Value = answer.json().await?;
    ensure!(body["operation_id"] == json!(public_id.to_string()), "GET returned another public operation id");
    ensure!(body["state"] == json!("pending"), "fresh public operation GET was not pending");
    ensure!(body["terminal"].is_null(), "pending public operation GET carried a terminal");
    ensure_public_safe(&body, &[private_id], "pending public operation GET")?;

    // A private attempt identifier is an opaque 404, indistinguishable from an
    // unknown public UUID on this route.
    let private = client.get(format!("{base}/operations/{private_id}")).bearer_auth(&owner.token).send().await?;
    ensure!(private.status() == StatusCode::NOT_FOUND, "private identifier GET was not an opaque 404");
    let private_body: Value = private.json().await?;
    ensure!(private_body["error"] == json!("not found"), "private identifier refusal changed");
    ensure_public_safe(&private_body, &[public_id, private_id], "private identifier refusal")?;

    let hidden_cancel =
        client.post(format!("{base}/operations/{private_id}/cancel")).bearer_auth(&owner.token).send().await?;
    ensure!(hidden_cancel.status() == StatusCode::NOT_FOUND, "private identifier cancellation was not an opaque 404");
    ensure_public_safe(&hidden_cancel.json().await?, &[public_id, private_id], "private cancellation refusal")?;

    let expected = json!({
        "operation_id": public_id,
        "state": "cancelled",
        "terminal": {"state": "cancelled", "reason": "cancel_requested"},
    });
    let cancel_path = format!("{public_path}/cancel");
    for _ in 0..2 {
        let cancel = client.post(&cancel_path).bearer_auth(&owner.token).send().await?;
        ensure!(cancel.status() == StatusCode::OK, "public cancellation HTTP {}", cancel.status());
        let terminal: Value = cancel.json().await?;
        ensure!(terminal == expected, "public cancellation returned an unexpected terminal");
        ensure_public_safe(&terminal, &[private_id], "public cancellation terminal")?;
    }
    let readback = client.get(&public_path).bearer_auth(&owner.token).send().await?;
    ensure!(readback.status() == StatusCode::OK, "cancelled public readback HTTP {}", readback.status());
    ensure!(readback.json::<Value>().await? == expected, "cancelled public readback differs");
    let durable = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT w.cancelled_private_id=$3, o.state='cancelled', c.operation_id=$3,
                w.event_id IS NULL, g.revision=$4
         FROM ref_store_public_operations w
         JOIN ref_store_operations o ON o.repository_id=w.repository_id AND o.operation_id=w.cancelled_private_id
         JOIN ref_store_cancellations c ON c.repository_id=o.repository_id AND c.operation_id=o.operation_id
         JOIN ref_store_core_gates g ON g.repository_id=w.repository_id
         WHERE w.repository_id=$1 AND w.public_id=$2",
            &[&serving.gate.repository_id(), &public_id, &private_id, &serving.gate.revision()],
        )
        .await?;
    for index in 0..5 {
        ensure!(durable.get::<_, bool>(index), "public cancellation database proof failed");
    }

    Ok(())
}

async fn admit_pending_public(
    db: &Db,
    gateway: &Gateway,
    owner: &Actor,
    serving: &crate::ref_store::serving::ServingRepository,
    public_id: Uuid,
    private_id: Uuid,
) -> Result<()> {
    let gate = &serving.gate;
    let lane = IssuerLane::new("slot-zero-http").map_err(anyhow::Error::from)?;
    let request = SlotZeroAdmissionRequest {
        repository_id: gate.repository_id(),
        admission_owner_id: gate.tenant_id(),
        issuer_id: owner.identity.id,
        lane,
        public_id,
        private_id,
        wire_digest: RequestDigest::of(
            "issue42-public-operation-get-wire",
            &[public_id.as_bytes(), private_id.as_bytes()],
        ),
        request_mode: CommitMode::Atomic,
        backend_identity: gateway.store.backend_identity().as_hex().to_owned(),
        object_format: gate.object_format(),
        history_incarnation: gate.history_incarnation(),
        authority_epoch: gate.authority_epoch(),
        group_epoch: gate.group_epoch(),
        restore_incarnation: serving.cluster_incarnation,
    };
    let facts = PlanFacts {
        repository_id: request.repository_id,
        tenant_id: request.admission_owner_id,
        object_format: request.object_format,
        history_incarnation: request.history_incarnation,
        authority_epoch: request.authority_epoch,
        group_epoch: request.group_epoch,
        gate_digest: *gate.digest(),
        mode: request.request_mode,
    };
    let mut client = db.pool.get().await?;
    let tx = tokio_postgres::Client::transaction(&mut client).await?;
    let (tx, result) = PgRefStore
        .admit_slot_zero_in_tx(tx, &request, |preview| build_plan(&request, preview, facts), deadline())
        .await?
        .into_parts();
    let receipt = result?;
    ensure!(!receipt.replayed, "fresh public slot-zero admission replayed");
    ensure!(receipt.public_id == public_id && receipt.private_id == private_id, "admission receipt ids differ");
    ensure!(receipt.state == OperationState::Pending, "fresh public slot-zero admission was not pending");
    tx.commit().await?;

    let row = client
        .query_one(
            "SELECT w.current_slot,w.state,w.event_id,
                    EXISTS(SELECT FROM ref_store_attempt_retirements r
                            WHERE (r.repository_id,r.public_id)=(w.repository_id,w.public_id))
               FROM ref_store_public_operations w WHERE w.repository_id=$1 AND w.public_id=$2",
            &[&request.repository_id, &public_id],
        )
        .await?;
    ensure!(row.get::<_, i16>(0) == 0, "fresh public wrapper was not current slot zero");
    ensure!(row.get::<_, String>(1) == "pending", "fresh public wrapper was not pending");
    ensure!(row.get::<_, Option<Uuid>>(2).is_none(), "fresh pending wrapper carried an event");
    ensure!(!row.get::<_, bool>(3), "fresh pending wrapper carried a retired event");
    Ok(())
}

#[derive(Clone, Copy)]
struct PlanFacts {
    repository_id: Uuid,
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    gate_digest: RequestDigest,
    mode: CommitMode,
}

fn build_plan(
    request: &SlotZeroAdmissionRequest,
    preview: SlotZeroPreview,
    facts: PlanFacts,
) -> Result<PackCommitPlan, PackCommitError> {
    let digest = RequestDigest::of(
        "issue42-public-operation-get-plan",
        &[request.public_id.as_bytes(), request.private_id.as_bytes()],
    );
    let identity = OperationIdentity::new(
        request.repository_id,
        request.issuer_id,
        request.lane.clone(),
        preview.sequence(),
        request.private_id,
        digest,
    )
    .map_err(PackCommitError::from)?;
    let scope = PackCommitScope::new(
        facts.repository_id,
        facts.tenant_id,
        facts.tenant_id,
        facts.object_format,
        facts.history_incarnation,
        facts.authority_epoch,
        facts.group_epoch,
    )?;
    let expected = PackCommitExpectation::new(preview.base_revision(), facts.gate_digest, PackMode::MetadataOnly)?;
    let refs = vec![RefUpdate::new(
        RefName::new("refs/heads/main").map_err(PackCommitError::from)?,
        RefPrecondition::Absent,
        GitOid::target_value(facts.object_format, &"a".repeat(facts.object_format.oid_hex_len()))
            .map_err(PackCommitError::from)?,
    )];
    PackCommitPlan::new_with_mode(
        scope,
        identity,
        expected,
        HeadUpdate::Keep,
        refs,
        MembershipDigest::of(&[]),
        Vec::new(),
        Vec::new(),
        facts.mode,
    )
}

fn ensure_public_safe(body: &Value, ids: &[Uuid], label: &str) -> Result<()> {
    let rendered = body.to_string();
    for id in ids {
        ensure!(!rendered.contains(&id.to_string()), "{label} disclosed a private/public operation id");
    }
    for field in ["private_id", "wire_digest", "plan_digest", "proof_digest", "input_binding"] {
        ensure!(!rendered.contains(field), "{label} disclosed {field}");
    }
    Ok(())
}
