//! Seed body of the current-format20/schema144 roots+decisions offline backup
//! drill (parent-owned migrated database, real S3, real trusted Git).
//!
//! 1. A4 `verify_new`/`verify_advance`: two real native verified pack commits
//!    (gate revision 2 then 3), so the source snapshot holds two registered
//!    packs and the first commit is no longer a direct ref.
//! 2. A5 `create_snapshot`: one real `pack_verified` snapshot + pin at revision 3.
//! 3. Roots through `PgRetentionRoots`: active snapshot root, registered then
//!    released root (generation 2) and a prepared-then-released-before-register
//!    tombstone whose delayed register is refused with `RootReleased`.
//! 4. The A5 source pin is released and the active root is materialized from the
//!    retained rows only (the engine re-reads the external S3 pack/idx bytes and
//!    the fixture independently re-downloads and hashes the same locators).
//! 5. Decisions through the real staged facade
//!    `PgAuthorizedCommit::{prepare,select,verify,commit}`:
//!    * one `AcceptedSubset` decision with one accepted and one stale-preimage
//!      ref (all per-ref verdicts persisted) reaches `CONSUMED` and writes the
//!      selected ref in the same transaction;
//!    * one `Atomic` decision is installed then cancelled (`CANCELLED`);
//!    * one operation is cancelled before any install (`decision_id = NULL`).
use anyhow::{Result, anyhow};
use deadpool_postgres::Pool;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::core::retention_root::{PgRetentionRoots, RootError, RootSelector};
use serde_json::{Value, json};
use uuid::Uuid;

use super::db::{self, Db, deadline};
use super::{decisions, marker, pack, roots};

pub async fn seed(db: &Db, store: &BlobStore, fixture: &marker::Fixture) -> Result<()> {
    let mut verified = pack::verify_new(db, store, &fixture.git, fixture.format).await?;
    let first_commit = verified.commit_oid.clone();
    pack::verify_advance(db, store, &mut verified, 2, b"roots decisions drill advance\n").await?;
    let advance_commit = verified.commit_oid.clone();
    let source = pack::create_snapshot(db, &verified, 900).await?;
    let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
    let root_adapter = PgRetentionRoots::new(store.clone(), fixture.git.clone())
        .map_err(|error| anyhow!("retention roots adapter rejected the Blob/Git configuration: {error:?}"))?;

    let mut scenarios: Vec<marker::RootScenario> = Vec::new();
    scenarios.push(seed_active_root(db, &root_adapter, scope, &source).await?);
    scenarios.push(seed_released_root(db, &root_adapter, scope, &source).await?);
    scenarios.push(seed_tombstone_root(db, &root_adapter, scope, &source).await?);

    // Source pin release: the retained roots are now the only protection.
    pack::release_pin(&db.pool, source.scope, source.pin_id)
        .await
        .map_err(|error| anyhow!("A5 source pin release failed: {error}"))?;

    // --- real decision pipeline ---------------------------------------------------
    let actor = decisions::owner_actor(&db.pool, verified.tenant).await?;
    let protocol = decisions::provision(&db.pool, verified.repo, verified.tenant, &verified.gate).await?;
    let adapter = decisions::adapter(store, &fixture.git)?;

    // (1) accepted subset: one stale pre-image rejected, one new ref accepted.
    let accepted = marker::branch_update(fixture.format, "refs/heads/release", None, Some(&advance_commit))?;
    let rejected =
        marker::branch_update(fixture.format, "refs/heads/main", Some(&first_commit), Some(&advance_commit))?;
    let (plan, _operation_id) = decisions::pending_plan(
        db,
        &verified,
        3,
        vec![accepted, rejected],
        rootyard::ref_store::core::CommitMode::AcceptedSubset,
    )
    .await?;
    let planned_refs = plan.refs().iter().map(|update| update.name().as_str().to_owned()).collect::<Vec<_>>();
    let prepared = decisions::prepare(&adapter, &db.pool, plan).await?;
    if prepared.planned_refs != 2 || prepared.gate_revision != verified.gate.revision() {
        return Err(anyhow!("authorized stage-1 capture did not describe the two-ref drill plan"));
    }
    let prepared_json = json!({
        "operation_id": prepared.operation_id.to_string(),
        "gate_revision": prepared.gate_revision,
        "planned_refs": prepared.planned_refs,
        "mode": prepared.mode,
        "head_ref": prepared.head_ref,
    });
    let installed =
        decisions::select(&adapter, &db.pool, prepared, &actor, decisions::mode("accepted_subset")?).await?;
    if installed.planned_refs != 2 || installed.accepted_refs != 1 || installed.all_rejected {
        return Err(anyhow!("the accepted-subset decision did not keep exactly one accepted ref"));
    }
    let decision_id = installed.decision_id;
    let selection_digest = installed.selection_digest.clone();
    let consumed = decisions::consume(&adapter, &db.pool, installed).await?;
    if !consumed.committed || consumed.replayed || consumed.decision_id != decision_id {
        return Err(anyhow!("the authorized commit did not consume the installed decision"));
    }
    if consumed.selection_digest != selection_digest || consumed.revision != verified.gate.revision() + 1 {
        return Err(anyhow!("the consumed decision did not bind its selection/gate revision"));
    }
    verified.gate = db::gate_version(&db.pool, verified.repo, verified.tenant).await?;
    let consumed_rows = decision_rows_json(&db.pool, decision_id).await?;
    if consumed_rows["state"] != Value::String("CONSUMED".to_owned())
        || consumed_rows["verdicts"].as_array().map(Vec::len) != Some(2)
    {
        return Err(anyhow!("the consumed decision did not persist both per-ref verdicts"));
    }

    // (2) installed then cancelled (OPEN -> CANCELLED).
    let second = marker::branch_update(fixture.format, "refs/heads/protected", None, Some(&advance_commit))?;
    let (plan, second_operation) =
        decisions::pending_plan(db, &verified, 4, vec![second], rootyard::ref_store::core::CommitMode::Atomic).await?;
    let second_identity = plan.identity().clone();
    let prepared = decisions::prepare(&adapter, &db.pool, plan).await?;
    let installed = decisions::select(&adapter, &db.pool, prepared, &actor, decisions::mode("atomic")?).await?;
    let cancelled_decision_id = installed.decision_id;
    drop(installed);
    let cancelled = decisions::cancel(&adapter, &db.pool, &actor, &second_identity, marker::CANCELLED_REASON).await?;
    if !cancelled.cancelled || cancelled.decision_id != Some(cancelled_decision_id) {
        return Err(anyhow!("the post-install cancel did not close the installed OPEN decision"));
    }
    let cancelled_rows = decision_rows_json(&db.pool, cancelled_decision_id).await?;

    // (3) cancel before any install (decision-less decision tombstone).
    let third = marker::branch_update(fixture.format, "refs/heads/abandoned", None, Some(&advance_commit))?;
    let (plan, tombstone_operation) =
        decisions::pending_plan(db, &verified, 5, vec![third], rootyard::ref_store::core::CommitMode::Atomic).await?;
    let tombstone_identity = plan.identity().clone();
    decisions::prepare(&adapter, &db.pool, plan).await?;
    let tombstone =
        decisions::cancel(&adapter, &db.pool, &actor, &tombstone_identity, marker::CANCELLED_REASON).await?;
    if !tombstone.cancelled || tombstone.decision_id.is_some() {
        return Err(anyhow!("cancel-before-install did not mint the decision-less tombstone"));
    }
    let cancellation = cancellation_row(&db.pool, verified.repo, tombstone_operation).await?;

    let base = json!({
        "marker": marker::MARKER,
        "kind": marker::MANIFEST_KIND,
        "mode": "seed",
        "scope": {
            "repository_id": verified.repo.to_string(),
            "tenant_id": verified.tenant.to_string(),
            "owner_id": verified.tenant.to_string(),
            "actor_id": actor.user_id.to_string(),
            "object_format": fixture.format.as_str(),
            "source_snapshot_id": source.snapshot_id.to_string(),
            "source_pin_id": source.pin_id.to_string(),
            "source_snapshot_request_id": source.request_id.to_string(),
        },
        "source": {
            "first_commit_oid": first_commit,
            "head_oid": advance_commit,
            "head_ref": "refs/heads/main",
            "registered_pack_count": marker::pack_count(&verified),
            "source_pin_released": true,
        },
        "protocol": marker::protocol_json(&protocol),
        "decisions": {
            "installed": 2,
            "consumed": 1,
            "cancelled": 1,
            "cancel_before_install": 1,
            "pending_plan_refs": planned_refs,
            "prepared": prepared_json,
            "consumed_decision": {
                "operation_id": consumed.operation_id.to_string(),
                "decision_id": decision_id.to_string(),
                "selection_digest": consumed.selection_digest,
                "terminal_revision": consumed.revision,
                "terminal_head_ref": consumed.head_ref,
                "terminal_refs": consumed.refs,
                "committed": consumed.committed,
                "replayed": consumed.replayed,
            },
            "cancelled_decision": {
                "operation_id": second_operation.to_string(),
                "decision_id": cancelled_decision_id.to_string(),
                "outcome": cancelled.outcome,
            },
            "cancel_before_install": {
                "operation_id": tombstone.operation_id.to_string(),
                "decision_id": Value::Null,
                "outcome": tombstone.outcome,
                "cancellation": cancellation,
            },
            "rows": [consumed_rows, cancelled_rows],
        },
    });
    marker::finish_marker(db, store, fixture, base, verified.repo, verified.tenant, &scenarios).await?;
    Ok(())
}

async fn seed_active_root(
    db: &Db,
    adapter: &PgRetentionRoots,
    scope: rootyard::ref_store::core::retention_root::RootsScope,
    source: &pack::SourceSnapshot,
) -> Result<marker::RootScenario> {
    let scenario = marker::RootScenario {
        label: "active",
        root_id: Uuid::new_v4(),
        operation_id: Uuid::new_v4(),
        prepare_request_id: Uuid::new_v4(),
        register_request_id: Some(Uuid::new_v4()),
        release_request_id: None,
        release_digest: None,
        register_digest: String::new(),
        state: "active",
    };
    let candidate = prepare_candidate(adapter, db, scope, source, &scenario).await?;
    if candidate.pack_count() != 2 || candidate.ref_count() != 1 {
        return Err(anyhow!("the active root candidate does not cover two registered packs and one ref"));
    }
    let register_digest = candidate.register_digest().as_hex();
    let receipt = roots::register(
        adapter,
        &db.pool,
        candidate,
        scenario.register_request_id.expect("active register request id"),
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("active root register refused: {error:?}"))?;
    if receipt.state() != "active" || receipt.replayed() {
        return Err(anyhow!("fresh active root register did not produce a new active receipt"));
    }
    Ok(marker::RootScenario { register_digest, ..scenario })
}

async fn seed_released_root(
    db: &Db,
    adapter: &PgRetentionRoots,
    scope: rootyard::ref_store::core::retention_root::RootsScope,
    source: &pack::SourceSnapshot,
) -> Result<marker::RootScenario> {
    let scenario = marker::RootScenario {
        label: "released",
        root_id: Uuid::new_v4(),
        operation_id: Uuid::new_v4(),
        prepare_request_id: Uuid::new_v4(),
        register_request_id: Some(Uuid::new_v4()),
        release_request_id: Some(Uuid::new_v4()),
        release_digest: Some(roots::release_digest("released")),
        register_digest: String::new(),
        state: "released",
    };
    let candidate = prepare_candidate(adapter, db, scope, source, &scenario).await?;
    let register_digest = candidate.register_digest().as_hex();
    roots::register(
        adapter,
        &db.pool,
        candidate,
        scenario.register_request_id.expect("released register request id"),
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("released root register refused: {error:?}"))?;
    let receipt = roots::release(
        adapter,
        &db.pool,
        scope,
        scenario.root_id,
        scenario.release_request_id.expect("released release request id"),
        &register_digest,
        scenario.release_digest.as_deref().expect("released digest"),
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("released root release refused: {error:?}"))?;
    if receipt.state() != "released" {
        return Err(anyhow!("a registered root did not reach the released state"));
    }
    Ok(marker::RootScenario { register_digest, ..scenario })
}

async fn seed_tombstone_root(
    db: &Db,
    adapter: &PgRetentionRoots,
    scope: rootyard::ref_store::core::retention_root::RootsScope,
    source: &pack::SourceSnapshot,
) -> Result<marker::RootScenario> {
    let scenario = marker::RootScenario {
        label: "tombstone",
        root_id: Uuid::new_v4(),
        operation_id: Uuid::new_v4(),
        prepare_request_id: Uuid::new_v4(),
        register_request_id: Some(Uuid::new_v4()),
        release_request_id: Some(Uuid::new_v4()),
        release_digest: Some(roots::release_digest("tombstone")),
        register_digest: String::new(),
        state: "released",
    };
    let candidate = prepare_candidate(adapter, db, scope, source, &scenario).await?;
    let register_digest = candidate.register_digest().as_hex();
    roots::release(
        adapter,
        &db.pool,
        scope,
        scenario.root_id,
        scenario.release_request_id.expect("tombstone release request id"),
        &register_digest,
        scenario.release_digest.as_deref().expect("tombstone digest"),
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("release-before-register tombstone refused: {error:?}"))?;
    let delayed = roots::register(
        adapter,
        &db.pool,
        candidate,
        scenario.register_request_id.expect("tombstone register request id"),
        deadline(),
    )
    .await;
    match delayed {
        Ok(_) => return Err(anyhow!("a released-before-register root id was registered a second time")),
        Err(RootError::RootReleased { .. }) => {}
        Err(other) => return Err(anyhow!("delayed tombstone register was refused unexpectedly: {other:?}")),
    }
    Ok(marker::RootScenario { register_digest, ..scenario })
}

async fn prepare_candidate(
    adapter: &PgRetentionRoots,
    db: &Db,
    scope: rootyard::ref_store::core::retention_root::RootsScope,
    source: &pack::SourceSnapshot,
    scenario: &marker::RootScenario,
) -> Result<rootyard::ref_store::core::retention_root::RootCandidate> {
    roots::prepare(
        adapter,
        &db.pool,
        scope,
        source,
        scenario.root_id,
        scenario.operation_id,
        RootSelector::Snapshot,
        scenario.prepare_request_id,
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("{} root prepare refused: {error:?}", scenario.label))
}

async fn cancellation_row(pool: &Pool, repo: Uuid, operation_id: Uuid) -> Result<Value> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT decision_id,request_digest,actor_id,reason FROM ref_store_decision_cancellations
             WHERE repository_id=$1 AND operation_id=$2",
            &[&repo, &operation_id],
        )
        .await?
        .ok_or_else(|| anyhow!("the cancel-before-install tombstone row is missing"))?;
    let decision: Option<Uuid> = row.get(0);
    if decision.is_some() {
        return Err(anyhow!("cancel-before-install unexpectedly bound a decision id"));
    }
    Ok(json!({
        "decision_id": Value::Null,
        "request_digest": row.get::<_, String>(1),
        "actor_id": row.get::<_, Uuid>(2).to_string(),
        "reason": row.get::<_, String>(3),
    }))
}

/// Read-only historical read of one decision row and all its per-ref verdicts.
/// Only non-secret semantic columns are surfaced; the PG-only credential
/// identity stays in the protected decision row and is never copied here.
async fn decision_rows_json(pool: &Pool, decision_id: Uuid) -> Result<Value> {
    let client = pool.get().await?;
    let header = client
        .query_opt(
            "SELECT state, action, coalesce(merge_pull_number,0), coalesce(merge_version,0)
             FROM ref_store_publication_decisions WHERE decision_id=$1",
            &[&decision_id],
        )
        .await?
        .ok_or_else(|| anyhow!("the decision row is missing"))?;
    let verdicts = client
        .query(
            "SELECT ref_name, verdict, reject_code FROM ref_store_decision_refs
             WHERE decision_id=$1 ORDER BY ref_name",
            &[&decision_id],
        )
        .await?
        .iter()
        .map(|row| {
            json!({
                "ref_name": row.get::<_, String>(0),
                "verdict": row.get::<_, String>(1),
                "reject_code": row.get::<_, Option<String>>(2),
            })
        })
        .collect::<Vec<_>>();
    drop(client);
    Ok(json!({
        "decision_id": decision_id.to_string(),
        "state": header.get::<_, String>(0),
        "action": header.get::<_, String>(1),
        "merge_pull_number": header.get::<_, i64>(2),
        "merge_version": header.get::<_, i64>(3),
        "verdicts": verdicts,
    }))
}
