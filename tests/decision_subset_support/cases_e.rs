//! Publication-producer identity at `select` (issue #169).
//!
//! A `PackCommitPlan` scope names the repository tenant and, separately, the
//! publication producer (`PackCommitScope::owner_id`). A real collaborator with
//! `write`, acting as producer and issuer, is a production-legitimate producer
//! owner different from the tenant: `select` must authorize it through the live
//! RBAC/scope rows instead of equating producer and repository owner. The
//! tenant binding itself stays strict. The full positive A3/A4/decision seed
//! remains the `format22` native path (`tests/format22_support/seed.rs`), not
//! these unit-level cases.
use super::assert as facts;
use super::auth;
use super::common::seeded;
use super::fixture;
use crate::retention_roots_support::db::deadline;
use crate::retention_roots_support::pack::{Draft, PackCommitError, PackCommitRejectCode};
use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::core::pack_commit::{
    AuthorizedCommitError, PackCommitPlan, PackCommitScope, PackMembershipEntry, PgPackCommit,
};
use rootyard::ref_store::pg::PgRefStore;
use rootyard::ref_store::{GitObjectFormat, HeadUpdate, OperationState};
use std::collections::BTreeMap;
use uuid::Uuid;

const SHA1: GitObjectFormat = GitObjectFormat::Sha1;

/// A second real repository on the unserved fixture lane (real `users`,
/// `repositories` and gate rows) owned by its own tenant, plus the first-pack
/// draft the shared builder produces for it. Only the scope's `tenant_id` is
/// replaced below; nothing else about the draft is re-derived.
async fn foreign_draft(world: &fixture::World) -> Result<(Uuid, Draft)> {
    let (tenant, repo) = world.db.business(SHA1).await?;
    let gate = world.db.gate(repo, tenant, SHA1).await?;
    let repository = crate::retention_roots_support::git::GitRepo::new(world.git.clone(), SHA1).await?;
    let commit = repository.build_commit("file.txt", b"another tenant\n", "another main").await?;
    repository.update_ref("refs/heads/main", &commit).await?;
    let files = repository.pack_all("another").await?;
    let draft = crate::retention_roots_support::pack::draft(
        &world.db,
        repo,
        tenant,
        1,
        &gate,
        vec![crate::retention_roots_support::pack::main_update(SHA1, None, &commit)?],
        &files,
    )
    .await?;
    Ok((tenant, draft))
}

/// Register the operation with the A4 step (on an equivalent transaction, then
/// rolled back), then return the typed outcome of the production
/// `PgPackCommit.begin_pending` that follows it on the same exact plan.
async fn begin_pending_after_registration(world: &fixture::World, plan: &PackCommitPlan) -> Result<PackCommitError> {
    let mut client = world.db.pool.get().await?;
    let tx = client.transaction().await?;
    tx.batch_execute(
        "SET LOCAL statement_timeout = '30s'; SET LOCAL lock_timeout = '5s';\
         SET LOCAL idle_in_transaction_session_timeout = '60s'",
    )
    .await?;
    let begun = PgRefStore.begin(&tx, plan.identity(), deadline()).await;
    tx.rollback().await?;
    let begun = begun.map_err(|error| anyhow!("the A4 operation registration refused: {error}"))?;
    ensure!(begun.created && begun.record.state() == OperationState::Pending, "registration is not a fresh pending");
    PgPackCommit.begin_pending(&mut client, plan, deadline()).await.map_err(|error| anyhow!("begin_pending: {error}"))
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn non_tenant_producer_collaborator_selects_with_producer_owner_different_from_tenant() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let member = auth::collaborator(&world.db.pool, world.verified.tenant, world.verified.repo, "write").await?;
        ensure!(member.user_id != world.verified.tenant, "the producer collaborator is the repository tenant");
        let commit = world.verified.commit_oid.clone();
        let lane = format!("producer-{}", member.user_id.simple());
        let plan = world
            .plan_with_head_as_producer(
                vec![fixture::update(SHA1, "refs/heads/side", None, Some(&commit))?],
                1,
                HeadUpdate::Keep,
                member.user_id,
                &lane,
                member.user_id,
            )
            .await?;
        ensure!(
            plan.tenant_id() == world.verified.tenant && plan.owner_id() == member.user_id,
            "the plan does not carry the repository tenant as tenant and the collaborator as producer"
        );
        let operation_id = plan.identity().operation_id();
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        let selection = fixture::select(&world.adapter, &world.db.pool, prepared, &member).await?;
        ensure!(!selection.is_all_rejected(), "a written collaborator producer was not admitted");
        let row = facts::decision(&world.db.pool, world.verified.repo, operation_id)
            .await?
            .ok_or_else(|| anyhow!("the authorized producer select persisted no decision"))?;
        ensure!(
            row.actor_id == member.user_id && row.token_id == member.token_id,
            "the decision does not name the producer collaborator's exact actor/token"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn plan_claiming_another_tenant_is_refused_by_begin_pending_and_prepare() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let (tenant, draft) = foreign_draft(&world).await?;
        ensure!(tenant != world.verified.tenant, "the second repository belongs to the world tenant");
        let built = draft.plan.scope().clone();
        let repo = built.repository_id();
        let mut client = world.db.pool.get().await?;
        let baseline = PgPackCommit.capture_baseline(&mut client, repo, tenant, deadline()).await?;
        drop(client);
        let original = draft.plan.identity().clone();
        let expected = draft.plan.expected().clone();
        let claimed = PackCommitScope::new(
            repo,
            world.verified.tenant,
            built.owner_id(),
            built.object_format(),
            built.history_incarnation(),
            built.authority_epoch(),
            built.group_epoch(),
        )?;
        let plan = PackCommitPlan::new_with_mode(
            claimed,
            original.clone(),
            expected,
            HeadUpdate::Keep,
            draft.plan.refs().to_vec(),
            baseline.membership_digest(),
            baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?,
            Vec::new(),
            baseline.mode(),
        )?;
        ensure!(
            plan.tenant_id() == world.verified.tenant && plan.repository_id() == repo,
            "the plan does not claim the world tenant on the real second repository"
        );
        // Positive control: the same plan under its real tenant (the
        // fixture's own produced `operation_id`) is admitted, so the refusal
        // below is caused by the claimed tenant alone.
        let (_, control) = crate::retention_roots_support::pack::draft(
            &world.db,
            repo,
            tenant,
            2,
            &world.db.gate(repo, tenant, SHA1).await?,
            draft.plan.refs().to_vec(),
            &[],
        )
        .await?;
        let preview = PgPackCommit.begin_pending(&mut client, &control.plan, deadline()).await;
        ensure!(preview.is_ok(), "the same plan under its real tenant was refused: {preview:?}");
        ensure!(
            facts::operation_opt(&world.db.pool, repo, control.plan.identity().operation_id()).await?.is_some(),
            "the control plan did not durably register"
        );

        let refused = begin_pending_after_registration(&world, &plan).await?;
        match refused {
            PackCommitError::Rejected(rejection) => {
                ensure!(rejection.code == PackCommitRejectCode::TenantMismatch, "another refusal: {rejection:?}")
            }
            other => return Err(anyhow!("begin_pending refused for another reason: {other}")),
        }
        let operation = original.operation_id();
        ensure!(
            facts::operation_opt(&world.db.pool, repo, operation).await?.is_none(),
            "the refused begin_pending left a durable operation row"
        );
        ensure!(
            facts::decision(&world.db.pool, repo, operation).await?.is_none(),
            "the refused begin_pending left a decision"
        );
        facts::assert_unchanged(&world.db.pool, repo, &BTreeMap::new(), 1).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated decision/subset pipeline"]
async fn unauthorized_actor_cannot_select_a_producers_plan() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let member = auth::collaborator(&world.db.pool, world.verified.tenant, world.verified.repo, "write").await?;
        let commit = world.verified.commit_oid.clone();
        // (a) The producer collaborator's own plan, selected by another real
        // session: the issuer/actor check refuses it.
        let lane = format!("issuer-{}", member.user_id.simple());
        let plan = world
            .plan_with_head_as_producer(
                vec![fixture::update(SHA1, "refs/heads/side", None, Some(&commit))?],
                1,
                HeadUpdate::Keep,
                member.user_id,
                &lane,
                member.user_id,
            )
            .await?;
        let operation = plan.identity().operation_id();
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        let mismatched = fixture::select_as(&world.adapter, &world.db.pool, prepared, &world.actor.identity)
            .await
            .err()
            .ok_or_else(|| anyhow!("another session selected the producer's plan"))?;
        ensure!(
            mismatched.to_string().contains("issuer_mismatch"),
            "the mismatched issuer was not refused: {mismatched}"
        );
        ensure!(
            facts::decision(&world.db.pool, world.verified.repo, operation).await?.is_none(),
            "the mismatched-issuer refusal still persisted a decision"
        );
        // (b) A real user with no repository role that is itself the plan
        // issuer: the live RBAC resolution, not the issuer check, refuses it.
        let stranger = auth::stranger(&world.db.pool).await?;
        ensure!(stranger.user_id != member.user_id && stranger.user_id != world.verified.tenant, "not a stranger");
        let lane = format!("issuer-{}", stranger.user_id.simple());
        let plan = world
            .plan_with_head_as_producer(
                vec![fixture::update(SHA1, "refs/heads/side", None, Some(&commit))?],
                1,
                HeadUpdate::Keep,
                stranger.user_id,
                &lane,
                member.user_id,
            )
            .await?;
        ensure!(plan.owner_id() == member.user_id, "the producer is not the distinct collaborator");
        let operation = plan.identity().operation_id();
        let prepared = fixture::prepare(&world.adapter, &world.db.pool, plan).await?;
        let before_refs = facts::refs(&world.db.pool, world.verified.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.verified.repo).await?;
        let denied = fixture::select(&world.adapter, &world.db.pool, prepared, &stranger)
            .await
            .err()
            .ok_or_else(|| anyhow!("a no-role issuer selected its own plan"))?;
        ensure!(
            matches!(denied, AuthorizedCommitError::Denied("role_denied")),
            "the no-role issuer was refused otherwise: {denied}"
        );
        ensure!(
            facts::decision(&world.db.pool, world.verified.repo, operation).await?.is_none(),
            "the role-denied refusal still persisted a decision"
        );
        facts::assert_unchanged(&world.db.pool, world.verified.repo, &before_refs, before_revision).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.finish(outcome).await
}
