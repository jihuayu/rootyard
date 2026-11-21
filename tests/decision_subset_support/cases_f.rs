//! A4 restore-capture fence and target-audit wake witness (issue #111).
//!
//! This uses the owned real PostgreSQL/S3/native-Git serving fixture, not the
//! unserved decision lane: `verify_new_serving` provisions an actual ready
//! `pg_refstore` repository through production provisioning. The case then:
//!
//! * captures the authorized serving incarnation, stages an A4 publication,
//!   injects a deterministic restore rotation before the final auth and proves
//!   the typed refusal rolls back with no terminal/ref/event/outbox/wake;
//! * commits a captured-and-matched A4 publication and proves the core
//!   terminal/ref/event and exact target-audit outbox committed together;
//! * commits through the generic facade and proves the pre-wake-bridge path
//!   still writes core state but no target audit/wake;
//! * replays the matched terminal under another rotation and proves no
//!   restamp, no new outbox and no new effect;
//! * runs the standalone scoped subscriber and proves it leases only the exact
//!   target evidence while an unrelated legacy audit row stays pending.
use super::assert as facts;
use super::fixture::{commit_receipt, prepare, select_as, update, verify};
use crate::retention_roots_support::common::open_store;
use crate::retention_roots_support::db::{Db, deadline, gate_version, rotate_cluster};
use crate::retention_roots_support::git::git_binary;
use crate::retention_roots_support::pack::draft;
use crate::retention_roots_support::serving::verify_new_serving;
use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::Pool;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db::{Identity, Repository};
use rootyard::events;
use rootyard::ref_store::core::pack_commit::{AuthorizedCommitError, PackCommitError, PgAuthorizedCommit};
use rootyard::ref_store::{GitObjectFormat, RefStoreError};
use uuid::Uuid;

const SHA1: GitObjectFormat = GitObjectFormat::Sha1;

/// Closed diagnostics for the ignored A4 native case. A returned failure carries
/// exactly one of these labels and never a source error body, SQL text, path,
/// repository identity or event payload.
#[derive(Clone, Copy)]
enum A4Phase {
    OwnedSetup,
    FixtureSetup,
    AdapterSetup,
    Baseline,
    AuthorizedLookup,
    MismatchPlan,
    MismatchPrepare,
    MismatchSelect,
    MismatchVerify,
    MismatchRotation,
    MismatchCommit,
    MismatchRollback,
    MatchPlan,
    MatchPrepare,
    MatchSelect,
    MatchVerify,
    MatchCommit,
    MatchEffects,
    GenericPlan,
    GenericPrepare,
    GenericSelect,
    GenericVerify,
    GenericCommit,
    GenericEffects,
    ReplaySnapshot,
    ReplayRotation,
    ReplayCommit,
    ReplayEffects,
    SubscriberDecoy,
    SubscriberPoll,
    SubscriberEffects,
    Cleanup,
}

impl A4Phase {
    const fn label(self) -> &'static str {
        match self {
            Self::OwnedSetup => "owned.setup",
            Self::FixtureSetup => "fixture.setup",
            Self::AdapterSetup => "adapter.setup",
            Self::Baseline => "baseline.snapshot",
            Self::AuthorizedLookup => "authorized.lookup",
            Self::MismatchPlan => "mismatch.plan",
            Self::MismatchPrepare => "mismatch.prepare",
            Self::MismatchSelect => "mismatch.select",
            Self::MismatchVerify => "mismatch.verify",
            Self::MismatchRotation => "mismatch.rotation",
            Self::MismatchCommit => "mismatch.commit",
            Self::MismatchRollback => "mismatch.rollback",
            Self::MatchPlan => "match.plan",
            Self::MatchPrepare => "match.prepare",
            Self::MatchSelect => "match.select",
            Self::MatchVerify => "match.verify",
            Self::MatchCommit => "match.commit",
            Self::MatchEffects => "match.effects",
            Self::GenericPlan => "generic.plan",
            Self::GenericPrepare => "generic.prepare",
            Self::GenericSelect => "generic.select",
            Self::GenericVerify => "generic.verify",
            Self::GenericCommit => "generic.commit",
            Self::GenericEffects => "generic.effects",
            Self::ReplaySnapshot => "replay.snapshot",
            Self::ReplayRotation => "replay.rotation",
            Self::ReplayCommit => "replay.commit",
            Self::ReplayEffects => "replay.effects",
            Self::SubscriberDecoy => "subscriber.decoy",
            Self::SubscriberPoll => "subscriber.poll",
            Self::SubscriberEffects => "subscriber.effects",
            Self::Cleanup => "cleanup",
        }
    }
}

fn phase_error(phase: A4Phase) -> anyhow::Error {
    anyhow!("A4_CAPTURE_FENCE phase={}", phase.label())
}

trait ClosedPhase<T> {
    fn phase(self, phase: A4Phase) -> Result<T>;
}

impl<T, E> ClosedPhase<T> for std::result::Result<T, E> {
    fn phase(self, phase: A4Phase) -> Result<T> {
        self.map_err(|_| phase_error(phase))
    }
}

/// Capture the incarnation through the same authorized serving lookup the
/// gateway uses; this is a server-side durable read, never a caller value.
async fn authorized_capture(pool: &Pool, actor: &Identity, repository: &Repository, store: &BlobStore) -> Result<Uuid> {
    let serving = rootyard::ref_store::serving::lookup(
        pool,
        actor,
        &repository.owner,
        &repository.name,
        true,
        store.backend_identity(),
        deadline(),
    )
    .await
    .phase(A4Phase::AuthorizedLookup)?;
    ensure!(serving.repository.id == repository.id, "authorized capture returned another repository");
    ensure!(!serving.cluster_incarnation.is_nil(), "authorized capture returned a nil incarnation");
    Ok(serving.cluster_incarnation)
}

async fn count_for_operation(pool: &Pool, sql: &str, repository: Uuid, operation: Uuid, phase: A4Phase) -> Result<i64> {
    Ok(pool.get().await.phase(phase)?.query_one(sql, &[&repository, &operation]).await.phase(phase)?.get(0))
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn a4_capture_fences_restore_and_only_matched_capture_wakes_target_audit() -> Result<()> {
    let db = Db::setup().await.phase(A4Phase::OwnedSetup)?;
    let store = open_store().phase(A4Phase::OwnedSetup)?;
    let git = git_binary().phase(A4Phase::OwnedSetup)?;
    let outcome = async {
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "issue111-target-wake").await.phase(A4Phase::FixtureSetup)?;
        let adapter = PgAuthorizedCommit::new(store.clone(), git.clone()).phase(A4Phase::AdapterSetup)?;
        let repo = verified.repo;
        let tenant = verified.tenant;
        let oid = verified.commit_oid.clone();
        let refs_before = facts::refs(&db.pool, repo).await.phase(A4Phase::Baseline)?;
        let revision_before = facts::gate_revision(&db.pool, repo).await.phase(A4Phase::Baseline)?;
        let audit_before: i64 = db
            .pool
            .get()
            .await
            .phase(A4Phase::Baseline)?
            .query_one("SELECT count(*) FROM audit_events", &[])
            .await
            .phase(A4Phase::Baseline)?
            .get(0);
        let pending_before = events::pending_count(&db.pool).await.phase(A4Phase::Baseline)?;

        // 1. Authorized capture -> staged A4 selection/verification -> restore
        //    rotation -> final commit. The rotation lands after the trusted
        //    capture and before the final authorization transaction.
        let captured_mismatch =
            authorized_capture(&db.pool, &actor, &repository, &store).await.phase(A4Phase::AuthorizedLookup)?;
        let mismatch_plan = draft(
            &db,
            repo,
            tenant,
            2,
            &verified.gate,
            vec![update(SHA1, "refs/heads/wake-mismatch", None, Some(&oid)).phase(A4Phase::MismatchPlan)?],
            &[],
        )
        .await
        .phase(A4Phase::MismatchPlan)?
        .plan;
        let mismatch_op = mismatch_plan.identity().operation_id();
        let prepared = prepare(&adapter, &db.pool, mismatch_plan).await.phase(A4Phase::MismatchPrepare)?;
        let selection = select_as(&adapter, &db.pool, prepared, &actor).await.phase(A4Phase::MismatchSelect)?;
        ensure!(!selection.is_all_rejected(), "the mismatch publication was rejected before the fence");
        let mismatch_verified = verify(&adapter, selection).await.phase(A4Phase::MismatchVerify)?;
        let rotated = rotate_cluster(&db.pool).await.phase(A4Phase::MismatchRotation)?;
        ensure!(rotated != captured_mismatch, "restore rotation did not change the incarnation");
        let error = match adapter
            .commit_with_expected_cluster_incarnation(&db.pool, &mismatch_verified, captured_mismatch, deadline())
            .await
        {
            Ok(_) => return Err(phase_error(A4Phase::MismatchCommit)),
            Err(error) => error,
        };
        ensure!(
            matches!(
                error,
                AuthorizedCommitError::Pack(PackCommitError::RefStore(RefStoreError::RestoreIncarnationMismatch))
            ),
            "A4_CAPTURE_FENCE phase=mismatch.commit unexpected refusal"
        );
        // A `VerifiedAuthorizedPublication` owns its native facts workspace and
        // therefore one process-wide materialized-view permit until dropped. The
        // failed mismatch capture is only checked for its typed refusal and its
        // durable rollback, while the matched capture is deliberately retained
        // for the later exact replay. Release the failed capture here so the
        // generic fact pass below stays within the bounded view budget instead
        // of waiting on a third permit; the generic call itself remains the real
        // prepare/select/verify/commit pipeline.
        drop(mismatch_verified);

        // The whole final transaction rolled back before auth/terminal writes.
        let operation = facts::operation(&db.pool, repo, mismatch_op).await.phase(A4Phase::MismatchRollback)?;
        ensure!(operation.state == "pending" && operation.terminal.is_none(), "mismatch wrote a terminal");
        ensure!(
            facts::refs(&db.pool, repo).await.phase(A4Phase::MismatchRollback)? == refs_before,
            "mismatch changed refs"
        );
        ensure!(
            facts::gate_revision(&db.pool, repo).await.phase(A4Phase::MismatchRollback)? == revision_before,
            "mismatch changed the gate revision"
        );
        let core_events = count_for_operation(
            &db.pool,
            "SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1 AND operation_id=$2",
            repo,
            mismatch_op,
            A4Phase::MismatchRollback,
        )
        .await?;
        ensure!(core_events == 0, "mismatch wrote {core_events} core events");
        let audit_rows = count_for_operation(
            &db.pool,
            "SELECT count(*) FROM git_operations WHERE repository_id=$1 AND id=$2",
            repo,
            mismatch_op,
            A4Phase::MismatchRollback,
        )
        .await?;
        ensure!(audit_rows == 0, "mismatch wrote {audit_rows} target audit rows");
        let outbox_rows = count_for_operation(
            &db.pool,
            "SELECT count(*) FROM outbox_events WHERE repository_id=$1 AND operation_id=$2",
            repo,
            mismatch_op,
            A4Phase::MismatchRollback,
        )
        .await?;
        ensure!(outbox_rows == 0, "mismatch wrote {outbox_rows} outbox events");
        let decision = facts::decision(&db.pool, repo, mismatch_op)
            .await
            .phase(A4Phase::MismatchRollback)?
            .ok_or_else(|| anyhow!("A4_CAPTURE_FENCE phase=mismatch.rollback decision missing"))?;
        ensure!(
            decision.state != "CONSUMED" && decision.consume_receipt_id.is_none(),
            "mismatch consumed the decision before final auth"
        );
        let audit_after: i64 = db
            .pool
            .get()
            .await
            .phase(A4Phase::MismatchRollback)?
            .query_one("SELECT count(*) FROM audit_events", &[])
            .await
            .phase(A4Phase::MismatchRollback)?
            .get(0);
        ensure!(audit_after == audit_before, "mismatch changed audit_events");
        ensure!(
            events::pending_count(&db.pool).await.phase(A4Phase::MismatchRollback)? == pending_before,
            "mismatch left a wakeable delivery"
        );

        // 2. Matching capture: the authorized lookup observes the rotated
        //    anchor and the final transaction stamps exactly that UUID.
        let captured_match =
            authorized_capture(&db.pool, &actor, &repository, &store).await.phase(A4Phase::AuthorizedLookup)?;
        ensure!(captured_match == rotated, "matching capture did not observe the rotated anchor");
        let match_plan = draft(
            &db,
            repo,
            tenant,
            3,
            &verified.gate,
            vec![update(SHA1, "refs/heads/wake-match", None, Some(&oid)).phase(A4Phase::MatchPlan)?],
            &[],
        )
        .await
        .phase(A4Phase::MatchPlan)?
        .plan;
        let match_op = match_plan.identity().operation_id();
        let prepared = prepare(&adapter, &db.pool, match_plan).await.phase(A4Phase::MatchPrepare)?;
        let selection = select_as(&adapter, &db.pool, prepared, &actor).await.phase(A4Phase::MatchSelect)?;
        ensure!(!selection.is_all_rejected(), "the matching publication was rejected before commit");
        let match_verified = verify(&adapter, selection).await.phase(A4Phase::MatchVerify)?;
        let receipt = adapter
            .commit_with_expected_cluster_incarnation(&db.pool, &match_verified, captured_match, deadline())
            .await
            .phase(A4Phase::MatchCommit)?;
        ensure!(
            receipt.is_committed() && !receipt.replayed && receipt.audit_enqueued,
            "matching capture did not produce a fresh committed audit-enqueued terminal"
        );
        let gate_after_match = gate_version(&db.pool, repo, tenant).await.phase(A4Phase::MatchEffects)?;
        ensure!(
            gate_after_match.revision() == receipt.terminal.revision,
            "matching capture did not advance the real gate"
        );
        ensure!(
            facts::refs(&db.pool, repo).await.phase(A4Phase::MatchEffects)?.get("refs/heads/wake-match") == Some(&oid),
            "matching capture did not persist the applied ref"
        );
        let core_events = count_for_operation(
            &db.pool,
            "SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1 AND operation_id=$2",
            repo,
            match_op,
            A4Phase::MatchEffects,
        )
        .await?;
        ensure!(core_events == 1, "matching capture wrote {core_events} core events");
        let row = db
            .pool
            .get()
            .await
            .phase(A4Phase::MatchEffects)?
            .query_opt(
                "SELECT outcome,evidence FROM git_operations WHERE repository_id=$1 AND id=$2",
                &[&repo, &match_op],
            )
            .await
            .phase(A4Phase::MatchEffects)?
            .ok_or_else(|| anyhow!("A4_CAPTURE_FENCE phase=match.effects audit row missing"))?;
        let outcome: String = row.get(0);
        let evidence: serde_json::Value = row.get(1);
        let repo_hex = repo.to_string();
        let operation_hex = match_op.to_string();
        ensure!(outcome == "recorded", "target audit outcome differs");
        ensure!(evidence["kind"].as_str() == Some(events::TARGET_AUDIT_KIND), "target audit kind differs");
        ensure!(evidence["authority"].as_str() == Some("pg_refstore"), "target audit authority differs");
        ensure!(evidence["delivery"].as_str() == Some(events::TARGET_AUDIT_CONSUMER), "target audit delivery differs");
        ensure!(evidence["source"].as_str() == Some("ref_store_core_events"), "target audit source differs");
        ensure!(evidence["repository_id"].as_str() == Some(repo_hex.as_str()), "target audit repository differs");
        ensure!(
            evidence["core_operation_id"].as_str() == Some(operation_hex.as_str()),
            "target audit operation differs"
        );
        ensure!(evidence["core_revision"].as_i64() == Some(receipt.terminal.revision), "target audit revision differs");
        ensure!(evidence["core_outcome"].as_str() == Some("committed"), "target audit core outcome differs");
        let stored_incarnation: String = db
            .pool
            .get()
            .await
            .phase(A4Phase::MatchEffects)?
            .query_one("SELECT evidence->>'restore_incarnation' FROM git_operations WHERE id=$1", &[&match_op])
            .await
            .phase(A4Phase::MatchEffects)?
            .get(0);
        ensure!(
            stored_incarnation == captured_match.to_string(),
            "target audit did not stamp the captured-and-matched incarnation"
        );
        let outbox_rows = count_for_operation(
            &db.pool,
            "SELECT count(*) FROM outbox_events WHERE repository_id=$1 AND operation_id=$2",
            repo,
            match_op,
            A4Phase::MatchEffects,
        )
        .await?;
        ensure!(outbox_rows == 1, "matching capture wrote {outbox_rows} outbox events");
        let consumers: Vec<String> = db
            .pool
            .get()
            .await
            .phase(A4Phase::MatchEffects)?
            .query(
                "SELECT DISTINCT d.consumer FROM event_deliveries d JOIN outbox_events e USING(event_id) \
                 WHERE e.operation_id=$1 ORDER BY 1",
                &[&match_op],
            )
            .await
            .phase(A4Phase::MatchEffects)?
            .iter()
            .map(|row| row.get(0))
            .collect();
        ensure!(consumers == vec![events::TARGET_AUDIT_CONSUMER.to_owned()], "audit outbox has legacy consumers");
        let projection: i64 = db
            .pool
            .get()
            .await
            .phase(A4Phase::MatchEffects)?
            .query_one("SELECT count(*) FROM repository_ref_projection WHERE repository_id=$1", &[&repo])
            .await
            .phase(A4Phase::MatchEffects)?
            .get(0);
        ensure!(projection == 0, "matching capture wrote a legacy ref projection");
        ensure!(
            events::pending_count(&db.pool).await.phase(A4Phase::MatchEffects)? == 1,
            "matching capture did not enqueue exactly one wake"
        );

        // 3. Generic commit keeps the pre-wake-bridge behavior: the durable
        //    core terminal/ref/event still commit, but no target audit row and
        //    no wakeable delivery are created.
        let generic_plan = draft(
            &db,
            repo,
            tenant,
            4,
            &gate_after_match,
            vec![update(SHA1, "refs/heads/wake-generic", None, Some(&oid)).phase(A4Phase::GenericPlan)?],
            &[],
        )
        .await
        .phase(A4Phase::GenericPlan)?
        .plan;
        let generic_op = generic_plan.identity().operation_id();
        let prepared = prepare(&adapter, &db.pool, generic_plan).await.phase(A4Phase::GenericPrepare)?;
        let selection = select_as(&adapter, &db.pool, prepared, &actor).await.phase(A4Phase::GenericSelect)?;
        ensure!(!selection.is_all_rejected(), "the generic publication was rejected before commit");
        let generic_verified = verify(&adapter, selection).await.phase(A4Phase::GenericVerify)?;
        let generic_receipt =
            commit_receipt(&adapter, &db.pool, &generic_verified).await.phase(A4Phase::GenericCommit)?;
        ensure!(
            generic_receipt.is_committed() && !generic_receipt.audit_enqueued,
            "generic commit unexpectedly opted into the target audit wake"
        );
        ensure!(
            facts::refs(&db.pool, repo).await.phase(A4Phase::GenericEffects)?.get("refs/heads/wake-generic")
                == Some(&oid),
            "generic commit did not persist its core ref"
        );
        let generic_audit = count_for_operation(
            &db.pool,
            "SELECT count(*) FROM git_operations WHERE repository_id=$1 AND id=$2",
            repo,
            generic_op,
            A4Phase::GenericEffects,
        )
        .await?;
        ensure!(generic_audit == 0, "generic commit wrote {generic_audit} target audit rows");
        let generic_outbox = count_for_operation(
            &db.pool,
            "SELECT count(*) FROM outbox_events WHERE repository_id=$1 AND operation_id=$2",
            repo,
            generic_op,
            A4Phase::GenericEffects,
        )
        .await?;
        ensure!(generic_outbox == 0, "generic commit wrote {generic_outbox} outbox events");
        ensure!(
            events::pending_count(&db.pool).await.phase(A4Phase::GenericEffects)? == 1,
            "generic commit changed the wake queue"
        );

        // 4. Exact replay under another rotation returns the persisted
        //    terminal, never restamps the audit evidence and never enqueues.
        let audit_row_before = count_for_operation(
            &db.pool,
            "SELECT count(*) FROM git_operations WHERE repository_id=$1 AND id=$2",
            repo,
            match_op,
            A4Phase::ReplaySnapshot,
        )
        .await?;
        let outbox_before = count_for_operation(
            &db.pool,
            "SELECT count(*) FROM outbox_events WHERE repository_id=$1 AND operation_id=$2",
            repo,
            match_op,
            A4Phase::ReplaySnapshot,
        )
        .await?;
        let audit_events_before: i64 = db
            .pool
            .get()
            .await
            .phase(A4Phase::ReplaySnapshot)?
            .query_one("SELECT count(*) FROM audit_events", &[])
            .await
            .phase(A4Phase::ReplaySnapshot)?
            .get(0);
        let replay_rotation = rotate_cluster(&db.pool).await.phase(A4Phase::ReplayRotation)?;
        ensure!(replay_rotation != captured_match, "replay rotation did not change the incarnation");
        let replay = adapter
            .commit_with_expected_cluster_incarnation(&db.pool, &match_verified, captured_match, deadline())
            .await
            .phase(A4Phase::ReplayCommit)?;
        ensure!(
            replay.replayed && replay.is_committed() && !replay.audit_enqueued,
            "replay did not return the persisted terminal without a new wake"
        );
        ensure!(replay.terminal == receipt.terminal, "replay returned another terminal");
        ensure!(
            count_for_operation(
                &db.pool,
                "SELECT count(*) FROM git_operations WHERE repository_id=$1 AND id=$2",
                repo,
                match_op,
                A4Phase::ReplayEffects,
            )
            .await?
                == audit_row_before,
            "replay wrote another target audit row"
        );
        ensure!(
            count_for_operation(
                &db.pool,
                "SELECT count(*) FROM outbox_events WHERE repository_id=$1 AND operation_id=$2",
                repo,
                match_op,
                A4Phase::ReplayEffects,
            )
            .await?
                == outbox_before,
            "replay wrote another outbox event"
        );
        let replay_incarnation: String = db
            .pool
            .get()
            .await
            .phase(A4Phase::ReplayEffects)?
            .query_one("SELECT evidence->>'restore_incarnation' FROM git_operations WHERE id=$1", &[&match_op])
            .await
            .phase(A4Phase::ReplayEffects)?
            .get(0);
        ensure!(replay_incarnation == captured_match.to_string(), "replay restamped the mutable current incarnation");
        ensure!(
            db.pool
                .get()
                .await
                .phase(A4Phase::ReplayEffects)?
                .query_one("SELECT count(*) FROM audit_events", &[])
                .await
                .phase(A4Phase::ReplayEffects)?
                .get::<_, i64>(0)
                == audit_events_before,
            "replay emitted an audit effect"
        );
        ensure!(
            events::pending_count(&db.pool).await.phase(A4Phase::ReplayEffects)? == 1,
            "replay changed the wake queue"
        );

        // 5. The standalone scoped subscriber leases exact target evidence;
        //    an unrelated legacy audit row remains pending.
        let decoy = events::OperationRecord {
            id: Uuid::new_v4(),
            repository_id: repo,
            actor_id: actor.id,
            token_id: actor.token_id,
            service_principal_id: None,
            actor_name: actor.username.clone(),
            sequence: 900,
            storage_generation: repository.storage_generation,
            outcome: "recorded".to_owned(),
            evidence: serde_json::json!({"kind":"legacy_push"}),
            admission: None,
        };
        let decoy_change = events::RefEventInput {
            transaction_sequence: 1,
            ref_name: "refs/heads/legacy-decoy".to_owned(),
            old_oid: "0".repeat(40),
            new_oid: oid.clone(),
        };
        let mut client = db.pool.get().await.phase(A4Phase::SubscriberDecoy)?;
        let tx = client.transaction().await.phase(A4Phase::SubscriberDecoy)?;
        events::publish_in_tx(&tx, &decoy, std::slice::from_ref(&decoy_change))
            .await
            .phase(A4Phase::SubscriberDecoy)?;
        tx.commit().await.phase(A4Phase::SubscriberDecoy)?;
        let audit_before_worker: i64 = db
            .pool
            .get()
            .await
            .phase(A4Phase::SubscriberEffects)?
            .query_one("SELECT count(*) FROM audit_events", &[])
            .await
            .phase(A4Phase::SubscriberEffects)?
            .get(0);
        ensure!(
            events::pending_count(&db.pool).await.phase(A4Phase::SubscriberEffects)? == 3,
            "decoy did not add exactly two deliveries"
        );
        let consumed = events::worker_once_with_lease_scoped(
            &db.pool,
            events::TARGET_AUDIT_CONSUMER,
            Some(events::TARGET_AUDIT_KIND),
            actor.id,
            100,
            60,
        )
        .await
        .phase(A4Phase::SubscriberPoll)?;
        ensure!(consumed == 1, "target subscriber consumed {consumed} events, expected exactly one");
        ensure!(
            db.pool
                .get()
                .await
                .phase(A4Phase::SubscriberEffects)?
                .query_one("SELECT count(*) FROM audit_events", &[])
                .await
                .phase(A4Phase::SubscriberEffects)?
                .get::<_, i64>(0)
                == audit_before_worker + 1,
            "target subscriber did not deliver exactly the A4 audit event"
        );
        ensure!(
            events::pending_count(&db.pool).await.phase(A4Phase::SubscriberEffects)? == 2,
            "legacy decoy deliveries were consumed"
        );
        let decoy_audit: i64 = db
            .pool
            .get()
            .await
            .phase(A4Phase::SubscriberEffects)?
            .query_one(
                "SELECT count(*) FROM audit_events a JOIN outbox_events e USING(event_id) WHERE e.operation_id=$1",
                &[&decoy.id],
            )
            .await
            .phase(A4Phase::SubscriberEffects)?
            .get(0);
        ensure!(decoy_audit == 0, "scoped subscriber delivered the legacy decoy");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    match outcome {
        // Real cleanup runs first; only its failure is mapped to the fixed phase.
        Ok(()) => db.finish(Ok(())).await.phase(A4Phase::Cleanup),
        // `finish` discards teardown detail and returns this original fixed body
        // failure unchanged, so it is never appended with raw cleanup text.
        Err(error) => db.finish(Err(error)).await,
    }
}
