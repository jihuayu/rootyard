//! Decision/subset integration cases (real PG/S3/native Git).
use super::assert as facts;
use super::auth;
use super::common::{accepted, code, seeded};
use super::fixture::{self};
use super::metadata;
use crate::retention_roots_support::db::deadline;
use crate::retention_roots_support::pack::verify_advance;
use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::core::{CommitMode, CommitRefsRequest, PgRefStoreCore};
use rootyard::ref_store::{GitObjectFormat, HeadUpdate, IssuerLane};
use uuid::Uuid;

const SHA1: GitObjectFormat = GitObjectFormat::Sha1;

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn cancel_before_install_persists_both_tombstones_and_blocks_late_select() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let plan = world
            .plan_with_head(vec![fixture::update(fmt, "refs/heads/side", None, Some(&commit))?], 2, HeadUpdate::Keep)
            .await?;
        let identity = plan.identity().clone();
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        fixture::cancel(&world.adapter, &world.db.pool, &world.actor, &identity, "cancel before install").await?;
        let operation = facts::operation(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
        ensure!(operation.state == "cancelled", "138 cancellation did not win");
        ensure!(
            facts::decision_cancellations(&world.db.pool, world.verified.repo, identity.operation_id()).await? == 1,
            "decision tombstone missing"
        );
        ensure!(
            fixture::prepare(&world.adapter, &world.db.pool, plan).await.is_err(),
            "late install/select revived a cancelled operation"
        );
        let refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        ensure!(refs == before_refs, "cancelled operation wrote refs");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn cancel_commit_race_has_exactly_one_terminal_and_unauthorized_cancel_is_denied() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let plan = world
            .plan_with_head(vec![fixture::update(fmt, "refs/heads/side", None, Some(&commit))?], 2, HeadUpdate::Keep)
            .await?;
        let identity = plan.identity().clone();
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        let selection = fixture::select(&world.adapter, &world.db.pool, prepared, &world.actor).await?;
        let verified = fixture::verify(&world.adapter, selection).await?;
        let cancel = fixture::cancel(&world.adapter, &world.db.pool, &world.actor, &identity, "race");
        let commit_call = fixture::commit(&world.adapter, &world.db.pool, &verified);
        let (_cancel, _commit) = tokio::join!(cancel, commit_call);
        let operation = facts::operation(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
        ensure!(
            matches!(operation.state.as_str(), "committed" | "cancelled"),
            "race produced no single terminal: {}",
            operation.state
        );
        let tombstones =
            facts::decision_cancellations(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
        let refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        if operation.state == "committed" {
            ensure!(tombstones == 0 && refs.get("refs/heads/side") == Some(&commit), "committed race lost its ref");
        } else {
            ensure!(tombstones == 1 && refs == before_refs, "cancelled race wrote refs");
        }

        // A real API user with no role at all may not cancel a fresh operation.
        let stranger = auth::stranger(&world.db.pool).await?;
        let other = world
            .plan_with_head(vec![fixture::update(fmt, "refs/heads/side2", None, Some(&commit))?], 3, HeadUpdate::Keep)
            .await?;
        let other_identity = other.identity().clone();
        let denied = fixture::cancel(&world.adapter, &world.db.pool, &stranger, &other_identity, "not mine").await;
        ensure!(denied.is_err(), "unauthorized actor cancelled an operation");
        ensure!(
            facts::decision_cancellations(&world.db.pool, world.verified.repo, other_identity.operation_id()).await?
                == 0,
            "unauthorized cancel wrote a tombstone"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn decision_fence_refuses_legacy_metadata_and_a4_fresh_writes_but_replays_the_old_terminal() -> Result<()> {
    let mut world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let plan = world
            .plan_with_head(vec![fixture::update(fmt, "refs/heads/side", None, Some(&commit))?], 2, HeadUpdate::Keep)
            .await?;
        world.commit(plan).await?;
        let revision = world.refresh_gate().await?.revision();
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;

        // Fresh legacy metadata write is refused by the irreversible fence.
        let gate = world.verified.gate.clone();
        let request = CommitRefsRequest::new(
            world.verified.repo,
            world.verified.tenant,
            world.verified.tenant,
            IssuerLane::new("legacy-metadata")?,
            1,
            Uuid::new_v4(),
            fmt,
            gate.history_incarnation(),
            gate.authority_epoch(),
            gate.group_epoch(),
            revision,
            HeadUpdate::Keep,
            CommitMode::AcceptedSubset,
            vec![fixture::update(fmt, "refs/heads/legacy", None, Some(&commit))?],
        )?;
        let mut client = world.db.pool.get().await?;
        let legacy = PgRefStoreCore.commit_refs(&mut client, &request, deadline()).await;
        drop(client);
        ensure!(legacy.is_err(), "legacy metadata write bypassed the decision fence");

        // Fresh A4 write (new upload/registration + verified commit) is refused too.
        let fresh = verify_advance(&world.db, &world.store, &mut world.verified, 3, b"after fence\n").await;
        ensure!(fresh.is_err(), "fresh A4 write bypassed the decision fence");
        facts::assert_unchanged(&world.db.pool, world.verified.repo, &before_refs, revision).await?;

        // The old exact 138 terminal still replays byte-for-byte as history.
        let replay = fixture::prepare_replay(&world.adapter, &world.db.pool, world.verified.plan.clone()).await?;
        ensure!(replay.replayed && replay.is_committed(), "old exact terminal replay changed");

        // A plan captured at a stale gate revision is refused before any decision.
        let stale = world
            .plan_with_head(vec![fixture::update(fmt, "refs/heads/stale", None, Some(&commit))?], 4, HeadUpdate::Keep)
            .await?;
        let advancing = world
            .plan_with_head(vec![fixture::update(fmt, "refs/heads/advance", None, Some(&commit))?], 5, HeadUpdate::Keep)
            .await?;
        world.commit(advancing).await?;
        world.refresh_gate().await?;
        ensure!(
            fixture::prepare(&world.adapter, &world.db.pool, stale).await.is_err(),
            "stale-gate plan bypassed the live gate digest/revision recheck"
        );
        // Reusing the same issuer lane/sequence for a different operation is a
        // durable identity conflict and writes no pending row.
        let conflict = world
            .plan_with_head(vec![fixture::update(fmt, "refs/heads/other", None, Some(&commit))?], 5, HeadUpdate::Keep)
            .await;
        ensure!(conflict.is_err(), "two different operations reused one issuer sequence");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn all_rejected_prefix_and_head_dependency_refusals_leave_no_ref_revision() -> Result<()> {
    let mut world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.verified.repo).await?;
        let before_memberships = facts::membership_count(&world.db.pool, world.verified.repo).await?;
        let plan = world
            .plan_with_head(
                vec![
                    fixture::main_update(fmt, Some(&fixture::missing_oid(fmt)), Some(&commit))?,
                    fixture::update(fmt, "refs/heads/side", Some(&fixture::missing_oid(fmt)), Some(&commit))?,
                ],
                2,
                HeadUpdate::Keep,
            )
            .await?;
        let identity = plan.identity().clone();
        let receipt = world.commit_receipt(plan).await?;
        ensure!(!receipt.is_committed(), "all-rejected commit was not durably rejected");
        facts::assert_durable_rejection(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
        facts::assert_unchanged_with_membership(
            &world.db.pool,
            world.verified.repo,
            &before_refs,
            before_revision,
            Some(before_memberships),
        )
        .await?;

        // Atomic keeps the historical whole-batch prefix refusal and creates no
        // pending operation. AcceptedSubset intentionally accepts the plan and
        // applies the namespace rule in original order below.
        let operations = facts::operation_count(&world.db.pool, world.verified.repo).await?;
        let prefix_refs = vec![
            fixture::update(fmt, "refs/heads/a", None, Some(&commit))?,
            fixture::update(fmt, "refs/heads/a/b", None, Some(&commit))?,
        ];
        let atomic_prefix = world.plan(prefix_refs.clone(), 3, CommitMode::Atomic, HeadUpdate::Keep).await;
        ensure!(atomic_prefix.is_err(), "Atomic plan accepted prefix-conflicting refs");
        ensure!(
            facts::operation_count(&world.db.pool, world.verified.repo).await? == operations,
            "refused Atomic prefix plan created a pending operation"
        );

        // Actual accepted-subset runtime: prepare/select/verify/commit the whole
        // original-order batch, then check the per-ref namespace decision.
        let before_prefix_memberships = facts::membership_count(&world.db.pool, world.verified.repo).await?;
        let prefix_plan = world.plan_with_head(prefix_refs, 3, HeadUpdate::Keep).await?;
        let prefix_identity = prefix_plan.identity().clone();
        let prefix_receipt = world.commit_receipt(prefix_plan).await?;
        ensure!(prefix_receipt.is_committed(), "accepted-subset prefix plan was not committed");
        let prefix_refs_after = facts::refs(&world.db.pool, world.verified.repo).await?;
        ensure!(
            prefix_refs_after.get("refs/heads/a") == Some(&commit),
            "accepted prefix parent `refs/heads/a` was not created"
        );
        ensure!(
            !prefix_refs_after.contains_key("refs/heads/a/b"),
            "prefix-conflicting child `refs/heads/a/b` was created"
        );
        let prefix_decision = facts::decision(&world.db.pool, world.verified.repo, prefix_identity.operation_id())
            .await?
            .ok_or_else(|| anyhow!("prefix decision row missing"))?;
        ensure!(
            prefix_decision.state == "CONSUMED" && prefix_decision.mode == "accepted_subset",
            "prefix decision state/mode differs"
        );
        let prefix_verdicts = facts::verdicts(&world.db.pool, prefix_decision.decision_id).await?;
        ensure!(accepted(&prefix_verdicts, "refs/heads/a"), "prefix parent verdict was not accept");
        ensure!(
            code(&prefix_verdicts, "refs/heads/a/b")? == "prefix_conflict",
            "prefix child verdict was not prefix_conflict"
        );
        ensure!(
            facts::gate_revision(&world.db.pool, world.verified.repo).await? == before_revision + 1,
            "accepted prefix subset did not advance the gate exactly once"
        );
        ensure!(
            facts::membership_count(&world.db.pool, world.verified.repo).await? == before_prefix_memberships,
            "accepted prefix subset changed pack membership"
        );

        // The prefix commit moved refs and gate; re-baseline before the dangling
        // HEAD retarget so any refused effect is measured from the new state.
        world.refresh_gate().await?;
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.verified.repo).await?;

        // HEAD retarget to a branch that is not in the final map refuses safely.
        let head_plan = world
            .plan_with_head(
                vec![fixture::update(fmt, "refs/heads/side", None, Some(&commit))?],
                4,
                HeadUpdate::retarget("refs/heads/ghost")?,
            )
            .await?;
        let head_identity = head_plan.identity().clone();
        let refused = world.commit_receipt(head_plan).await;
        if let Ok(receipt) = &refused {
            ensure!(!receipt.is_committed(), "dangling HEAD retarget was committed");
        }
        if let Some(operation) =
            facts::operation_opt(&world.db.pool, world.verified.repo, head_identity.operation_id()).await?
        {
            ensure!(operation.state != "committed", "dangling HEAD retarget wrote a committed terminal");
        }
        facts::assert_unchanged(&world.db.pool, world.verified.repo, &before_refs, before_revision).await?;

        // A valid sibling batch still commits; the retained parent value is
        // unchanged while the new sibling is applied.
        world.refresh_gate().await?;
        let sibling = world
            .plan_with_head(
                vec![
                    fixture::main_update(fmt, Some(&commit), Some(&commit))?,
                    fixture::update(fmt, "refs/heads/sibling", None, Some(&commit))?,
                ],
                5,
                HeadUpdate::Keep,
            )
            .await?;
        world.commit(sibling).await?;
        let refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        ensure!(refs.get("refs/heads/main") == Some(&commit), "retained parent changed");
        ensure!(refs.get("refs/heads/sibling") == Some(&commit), "valid sibling missing");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated metadata decision facade"]
async fn metadata_commit_refs_request_uses_authorized_facade_not_legacy_plan() -> Result<()> {
    let world = metadata::world().await?;
    let outcome = async {
        let oid = metadata::sample_oid(SHA1, 0x11);
        let request =
            world.request(vec![fixture::update(SHA1, "refs/heads/main", None, Some(&oid))?], 1, "metadata-subset")?;
        let operation_id = request.identity().operation_id();
        let prepared = world.prepare(request).await?;
        ensure!(prepared.selection_digest().as_hex().len() == 64, "metadata selection digest is not sha256 hex");
        let receipt = world.commit(&prepared).await?;
        ensure!(receipt.is_committed(), "authorized metadata commit did not commit a valid creation");
        let refs = facts::refs(&world.db.pool, world.repo).await?;
        ensure!(refs.get("refs/heads/main") == Some(&oid), "authorized metadata creation missing");
        let decision = facts::decision(&world.db.pool, world.repo, operation_id)
            .await?
            .ok_or_else(|| anyhow!("metadata decision row missing"))?;
        ensure!(decision.state == "CONSUMED", "metadata decision was not consumed");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.db.finish(outcome).await
}
