//! Decision/subset integration cases (real PG/S3/native Git).
use super::assert as facts;
use super::auth;
use super::common::{accepted, code, seeded};
use super::fixture::{self};
use super::policy;
use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::core::CommitMode;
use rootyard::ref_store::core::pack_commit::PgAuthorizedCommit;
use rootyard::ref_store::{GitObjectFormat, HeadUpdate};

const SHA1: GitObjectFormat = GitObjectFormat::Sha1;

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn mixed_batch_bad_cas_and_valid_new_ref_commits_only_the_good_ref_and_replays_exactly() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let plan = world
            .plan_with_head(
                vec![
                    fixture::main_update(fmt, Some(&fixture::missing_oid(fmt)), Some(&commit))?,
                    fixture::update(fmt, "refs/heads/side", None, Some(&commit))?,
                ],
                2,
                HeadUpdate::Keep,
            )
            .await?;
        let replay_plan = plan.clone();
        let identity = plan.identity().clone();
        let parent = *plan.parent_digest();
        let gate_before = world.verified.gate.clone();
        world.commit(plan).await?;

        let refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        ensure!(refs.get("refs/heads/main") == Some(&commit), "bad-CAS ref changed");
        ensure!(refs.get("refs/heads/side") == Some(&commit), "valid new ref was not created");
        ensure!(
            facts::gate_revision(&world.db.pool, world.verified.repo).await? == gate_before.revision() + 1,
            "revision"
        );
        let decision = facts::decision(&world.db.pool, world.verified.repo, identity.operation_id())
            .await?
            .ok_or_else(|| anyhow!("decision row missing"))?;
        ensure!(decision.mode == "accepted_subset" && decision.state == "CONSUMED", "decision state/mode differs");
        ensure!(decision.command_digest == parent.as_hex(), "decision did not bind the original parent digest");
        ensure!(decision.operation_id == identity.operation_id(), "decision operation identity differs");
        ensure!(decision.base_revision == gate_before.revision(), "decision base revision differs");
        auth::assert_stored_token_digest(&world.db.pool, decision.decision_id, &world.actor.token).await?;
        let verdicts = facts::verdicts(&world.db.pool, decision.decision_id).await?;
        ensure!(code(&verdicts, "refs/heads/main")? == "old_oid_mismatch", "bad CAS code");
        ensure!(accepted(&verdicts, "refs/heads/side"), "good ref verdict missing");
        let operation = facts::operation(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
        ensure!(operation.state == "committed" && facts::terminal_kind(&operation)? == "committed", "terminal");
        ensure!(operation.request_digest == parent.as_hex(), "terminal did not keep the original digest");

        let usage = facts::usage_decisions(&world.db.pool, world.verified.repo).await?;
        let replay = fixture::prepare_replay(&world.adapter, &world.db.pool, replay_plan).await?;
        ensure!(replay.replayed && replay.is_committed(), "exact replay did not return the committed terminal");
        ensure!(facts::usage_decisions(&world.db.pool, world.verified.repo).await? == usage, "replay charged quota");
        facts::assert_unchanged(&world.db.pool, world.verified.repo, &refs, gate_before.revision() + 1).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn atomic_multi_update_bad_cas_is_durably_rejected_without_ref_or_revision_change() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.verified.repo).await?;
        let before_memberships = facts::membership_count(&world.db.pool, world.verified.repo).await?;
        let plan = world
            .plan(
                vec![
                    fixture::main_update(fmt, Some(&fixture::missing_oid(fmt)), Some(&commit))?,
                    fixture::update(fmt, "refs/heads/side", None, Some(&commit))?,
                    fixture::update(fmt, "refs/heads/other", None, Some(&commit))?,
                ],
                2,
                CommitMode::Atomic,
                HeadUpdate::Keep,
            )
            .await?
            .0;
        let identity = plan.identity().clone();
        let receipt = world.commit_receipt(plan).await?;
        ensure!(!receipt.is_committed(), "atomic bad-CAS commit was not durably rejected");
        let operation = facts::operation(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
        ensure!(operation.state == "rejected" && facts::terminal_kind(&operation)? == "rejected", "atomic terminal");
        facts::assert_unchanged(&world.db.pool, world.verified.repo, &before_refs, before_revision).await?;
        ensure!(
            facts::membership_count(&world.db.pool, world.verified.repo).await? == before_memberships,
            "atomic rejection changed membership"
        );
        let decision = facts::decision(&world.db.pool, world.verified.repo, identity.operation_id())
            .await?
            .ok_or_else(|| anyhow!("atomic decision row missing"))?;
        ensure!(decision.mode == "atomic" && decision.state == "REJECTED", "atomic decision state differs");
        let verdicts = facts::verdicts(&world.db.pool, decision.decision_id).await?;
        ensure!(verdicts.len() == 3 && verdicts.iter().all(|row| row.1 == "reject"), "all verdicts must reject");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn missing_new_target_is_per_ref_and_valid_sibling_still_commits() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let missing = fixture::missing_oid(fmt);
        let plan = world
            .plan_with_head(
                vec![
                    fixture::update(fmt, "refs/heads/absent", None, Some(&missing))?,
                    fixture::update(fmt, "refs/heads/side", None, Some(&commit))?,
                ],
                2,
                HeadUpdate::Keep,
            )
            .await?;
        let identity = plan.identity().clone();
        world.commit(plan).await?;
        let refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        ensure!(refs.get("refs/heads/side") == Some(&commit), "valid sibling was not committed");
        ensure!(!refs.contains_key("refs/heads/absent"), "missing target created a ref");
        let decision = facts::decision(&world.db.pool, world.verified.repo, identity.operation_id())
            .await?
            .ok_or_else(|| anyhow!("missing-target decision row missing"))?;
        let verdicts = facts::verdicts(&world.db.pool, decision.decision_id).await?;
        ensure!(
            matches!(code(&verdicts, "refs/heads/absent")?, "ref_not_writable" | "missing_target"),
            "missing NEW target was not a per-ref rejection"
        );
        ensure!(accepted(&verdicts, "refs/heads/side"), "valid sibling verdict missing");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn branch_pointing_at_tree_or_blob_is_rejected_per_ref_and_valid_sibling_commits() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let (tree, blob) = fixture::object_ids(&world.verified.fixture, &commit).await?;
        let plan = world
            .plan_with_head(
                vec![
                    fixture::update(fmt, "refs/heads/tree-tip", None, Some(&tree))?,
                    fixture::update(fmt, "refs/heads/blob-tip", None, Some(&blob))?,
                    fixture::update(fmt, "refs/heads/side", None, Some(&commit))?,
                ],
                2,
                HeadUpdate::Keep,
            )
            .await?;
        let identity = plan.identity().clone();
        world.commit(plan).await?;
        let decision = facts::decision(&world.db.pool, world.verified.repo, identity.operation_id())
            .await?
            .ok_or_else(|| anyhow!("decision row missing"))?;
        let verdicts = facts::verdicts(&world.db.pool, decision.decision_id).await?;
        let tree_code = code(&verdicts, "refs/heads/tree-tip")?;
        ensure!(tree_code == "bad_object_type", "tree branch type expected bad_object_type, got {tree_code}");
        let blob_code = code(&verdicts, "refs/heads/blob-tip")?;
        ensure!(blob_code == "bad_object_type", "blob branch type expected bad_object_type, got {blob_code}");
        ensure!(accepted(&verdicts, "refs/heads/side"), "valid commit sibling missing");
        let refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        ensure!(refs.get("refs/heads/side") == Some(&commit), "valid sibling not committed");
        ensure!(!refs.contains_key("refs/heads/tree-tip") && !refs.contains_key("refs/heads/blob-tip"), "types");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn missing_shared_pack_bytes_fail_the_whole_operation_without_refs() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let plan = world
            .plan_with_head(vec![fixture::update(fmt, "refs/heads/side", None, Some(&commit))?], 2, HeadUpdate::Keep)
            .await?;
        let identity = plan.identity().clone();
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.verified.repo).await?;
        let before_memberships = facts::membership_count(&world.db.pool, world.verified.repo).await?;
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        // A second real Blob store over an absent root: the registered pack
        // bytes are genuinely missing, never a synthesized failure flag.
        let broken = PgAuthorizedCommit::new(fixture::absent_store()?, world.git.clone())
            .map_err(|error| anyhow!("absent-root adapter refused: {error:?}"))?;
        let refused = fixture::select(&broken, &world.db.pool, prepared, &world.actor).await;
        ensure!(refused.is_err(), "missing shared pack bytes were selected instead of refused");
        ensure!(
            facts::decision(&world.db.pool, world.verified.repo, identity.operation_id()).await?.is_none(),
            "global integrity failure persisted a decision"
        );
        facts::assert_unchanged_with_membership(
            &world.db.pool,
            world.verified.repo,
            &before_refs,
            before_revision,
            Some(before_memberships),
        )
        .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn protected_branch_approval_rule_rejects_main_and_accepts_unprotected_sibling() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        policy::branch_rule(
            &world.db.pool,
            world.verified.tenant,
            world.verified.repo,
            policy::Rule::approvals("refs/heads/main", 1),
        )
        .await?;
        let plan = world
            .plan_with_head(
                vec![
                    fixture::main_update(fmt, Some(&commit), Some(&commit))?,
                    fixture::update(fmt, "refs/heads/side", None, Some(&commit))?,
                ],
                2,
                HeadUpdate::Keep,
            )
            .await?;
        let identity = plan.identity().clone();
        world.commit(plan).await?;
        let decision = facts::decision(&world.db.pool, world.verified.repo, identity.operation_id())
            .await?
            .ok_or_else(|| anyhow!("decision row missing"))?;
        let verdicts = facts::verdicts(&world.db.pool, decision.decision_id).await?;
        ensure!(
            matches!(code(&verdicts, "refs/heads/main")?, "missing_approvals" | "policy_denied"),
            "protected branch was not denied"
        );
        ensure!(accepted(&verdicts, "refs/heads/side"), "unprotected sibling was not accepted");
        let refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        ensure!(refs.get("refs/heads/main") == Some(&commit), "protected main changed");
        ensure!(refs.get("refs/heads/side") == Some(&commit), "unprotected sibling missing");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}
