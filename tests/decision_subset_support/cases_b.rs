//! Decision/subset integration cases (real PG/S3/native Git).
use super::assert as facts;
use super::auth;
use super::common::seeded;
use super::fixture::{self};
use super::policy;
use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::{GitObjectFormat, HeadUpdate};

const SHA1: GitObjectFormat = GitObjectFormat::Sha1;

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn revoked_api_token_between_select_and_commit_durably_rejects_decision() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.verified.repo).await?;
        let plan = world
            .plan_with_head(vec![fixture::update(fmt, "refs/heads/side", None, Some(&commit))?], 2, HeadUpdate::Keep)
            .await?;
        let identity = plan.identity().clone();
        let before_memberships = facts::membership_count(&world.db.pool, world.verified.repo).await?;
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        let selection = fixture::select(&world.adapter, &world.db.pool, prepared, &world.actor).await?;
        auth::revoke_token(&world.db.pool, world.actor.token_id).await?;
        let verified = fixture::verify(&world.adapter, selection).await?;
        let receipt = fixture::commit_receipt(&world.adapter, &world.db.pool, &verified).await?;
        ensure!(!receipt.is_committed(), "revoked-token commit was not durably rejected");
        facts::assert_durable_rejection(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
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
async fn collaborator_rbac_revoke_between_select_and_commit_durably_rejects_decision() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let member = auth::collaborator(&world.db.pool, world.verified.tenant, world.verified.repo, "write").await?;
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.verified.repo).await?;
        let lane = format!("member-{}", member.user_id.simple());
        let plan = world
            .plan_with_head_as(
                vec![fixture::update(fmt, "refs/heads/side", None, Some(&commit))?],
                1,
                HeadUpdate::Keep,
                member.user_id,
                &lane,
            )
            .await?;
        let identity = plan.identity().clone();
        let before_memberships = facts::membership_count(&world.db.pool, world.verified.repo).await?;
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        let selection = fixture::select(&world.adapter, &world.db.pool, prepared, &member).await?;
        auth::remove_collaborator(&world.db.pool, world.verified.repo, member.user_id).await?;
        let verified = fixture::verify(&world.adapter, selection).await?;
        let receipt = fixture::commit_receipt(&world.adapter, &world.db.pool, &verified).await?;
        ensure!(!receipt.is_committed(), "collaborator-revoked commit was not durably rejected");
        facts::assert_durable_rejection(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
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
async fn restricted_pat_scope_narrowing_is_denied_at_select_without_a_decision() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let member = auth::collaborator(&world.db.pool, world.verified.tenant, world.verified.repo, "write").await?;
        auth::restrict_token(&world.db.pool, member.token_id, world.verified.repo, &["contents_read"]).await?;
        let lane = format!("member-{}", member.user_id.simple());
        let plan = world
            .plan_with_head_as(
                vec![fixture::update(fmt, "refs/heads/side", None, Some(&commit))?],
                1,
                HeadUpdate::Keep,
                member.user_id,
                &lane,
            )
            .await?;
        let identity = plan.identity().clone();
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        let refused = fixture::select(&world.adapter, &world.db.pool, prepared, &member).await;
        ensure!(refused.is_err(), "contents_read-only token selected ContentsWrite");
        ensure!(
            facts::decision(&world.db.pool, world.verified.repo, identity.operation_id()).await?.is_none(),
            "denied scope still persisted a decision"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn phantom_branch_rule_inserted_after_select_refuses_commit_and_keeps_refs() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.verified.repo).await?;
        let plan = world
            .plan_with_head(vec![fixture::main_update(fmt, Some(&commit), Some(&commit))?], 2, HeadUpdate::Keep)
            .await?;
        let identity = plan.identity().clone();
        let before_memberships = facts::membership_count(&world.db.pool, world.verified.repo).await?;
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        let selection = fixture::select(&world.adapter, &world.db.pool, prepared, &world.actor).await?;
        policy::branch_rule(
            &world.db.pool,
            world.verified.tenant,
            world.verified.repo,
            policy::Rule::approvals("refs/heads/main", 1),
        )
        .await?;
        let verified = fixture::verify(&world.adapter, selection).await?;
        let receipt = fixture::commit_receipt(&world.adapter, &world.db.pool, &verified).await?;
        ensure!(!receipt.is_committed(), "phantom branch rule did not durably reject the commit");
        facts::assert_durable_rejection(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
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
async fn trusted_check_withdrawal_after_select_refuses_commit() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let hook = policy::webhook(&world.db.pool, world.verified.tenant, world.verified.repo).await?;
        policy::trusted_context(&world.db.pool, world.verified.tenant, world.verified.repo, "ci/build", hook).await?;
        policy::check_run(&world.db.pool, world.verified.tenant, world.verified.repo, &commit, "ci/build", hook)
            .await?;
        policy::branch_rule(
            &world.db.pool,
            world.verified.tenant,
            world.verified.repo,
            policy::Rule { required_checks: &["ci/build"], ..policy::Rule::approvals("refs/heads/main", 0) },
        )
        .await?;
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.verified.repo).await?;
        let plan = world
            .plan_with_head(vec![fixture::main_update(fmt, Some(&commit), Some(&commit))?], 2, HeadUpdate::Keep)
            .await?;
        let identity = plan.identity().clone();
        let before_memberships = facts::membership_count(&world.db.pool, world.verified.repo).await?;
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        let selection = fixture::select(&world.adapter, &world.db.pool, prepared, &world.actor).await?;
        policy::withdraw_trusted_context(&world.db.pool, world.verified.repo, "ci/build").await?;
        let verified = fixture::verify(&world.adapter, selection).await?;
        let receipt = fixture::commit_receipt(&world.adapter, &world.db.pool, &verified).await?;
        ensure!(!receipt.is_committed(), "withdrawn trusted check did not durably reject the commit");
        facts::assert_durable_rejection(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
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
async fn one_second_token_expiry_on_the_database_clock_refuses_commit_without_backdating() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let fmt = SHA1;
        let commit = world.verified.commit_oid.clone();
        let plan = world
            .plan_with_head(vec![fixture::update(fmt, "refs/heads/side", None, Some(&commit))?], 2, HeadUpdate::Keep)
            .await?;
        let identity = plan.identity().clone();
        let before_memberships = facts::membership_count(&world.db.pool, world.verified.repo).await?;
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.verified.repo).await?;
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        // Start the real DB-clock expiry only once planning/facts/prepare are done, so the
        // 2s window is spent by select, not by setup: the decision must be selected while the
        // token is valid and then become invalid before commit.
        auth::expire_after_millis(&world.db.pool, world.actor.token_id, 2_000).await?;
        let expiry = auth::token_expiry(&world.db.pool, world.actor.token_id)
            .await?
            .ok_or_else(|| anyhow!("token expiry was not stored"))?;
        let selection = fixture::select(&world.adapter, &world.db.pool, prepared, &world.actor).await?;
        let decision = facts::decision(&world.db.pool, world.verified.repo, identity.operation_id())
            .await?
            .ok_or_else(|| anyhow!("decision row missing"))?;
        let (created, not_after) = facts::decision_window(&world.db.pool, decision.decision_id).await?;
        ensure!(not_after - created <= 30_000 && not_after <= expiry, "decision deadline exceeds the 30s/token cap");
        fixture::wait_db_clock_millis(&world.db.pool, expiry + 300).await?;
        let verified = fixture::verify(&world.adapter, selection).await?;
        let receipt = fixture::commit_receipt(&world.adapter, &world.db.pool, &verified).await?;
        ensure!(!receipt.is_committed(), "expired decision did not durably reject");
        facts::assert_durable_rejection(&world.db.pool, world.verified.repo, identity.operation_id()).await?;
        facts::assert_unchanged_with_membership(
            &world.db.pool,
            world.verified.repo,
            &before_refs,
            before_revision,
            Some(before_memberships),
        )
        .await?;
        ensure!(
            auth::token_expiry(&world.db.pool, world.actor.token_id).await? == Some(expiry),
            "expiry was mutated/backdated instead of waiting on the DB clock"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}
