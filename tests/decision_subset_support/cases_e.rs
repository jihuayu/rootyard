//! Publication-producer identity at `select` (issue #169).
//!
//! A `PackCommitPlan` scope names the repository tenant and, separately, the
//! publication producer (`PackCommitScope::owner_id`). A real collaborator with
//! `write`, acting as producer and issuer, is a production-legitimate producer
//! owner different from the tenant: `select` must authorize it through the live
//! RBAC/scope rows instead of equating producer and repository owner. The
//! tenant binding itself stays strict. The full positive A3/A4/decision seed
//! remains the `format22` native path (`tests/format22_support/seed.rs`), not
//! these ignored PG integration cases.
use super::assert as facts;
use super::auth;
use super::common::seeded;
use super::fixture;
use crate::retention_roots_support::db::deadline;
use crate::retention_roots_support::pack::Draft;
use anyhow::{anyhow, ensure, Result};
use rootyard::ref_store::core::pack_commit::{
    PackCommitError, PackCommitPlan, PackCommitRejectCode, PackCommitScope, PackMembershipEntry, PgPackCommit,
};
use rootyard::ref_store::{GitObjectFormat, HeadUpdate, IssuerLane, OperationIdentity, OperationState, RequestDigest};
use uuid::Uuid;

const SHA1: GitObjectFormat = GitObjectFormat::Sha1;

/// A second real repository on the unserved fixture lane (real `users`,
/// `repositories` and gate rows) owned by its own tenant, plus the first-pack
/// draft the shared builder produces for it together with its durable Pending
/// operation. Only the scope's `tenant_id` is replaced below; nothing else
/// about the draft is re-derived.
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
        std::slice::from_ref(&files),
    )
    .await?;
    Ok((tenant, draft))
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
async fn plan_claiming_another_tenant_is_refused_by_begin_pending() -> Result<()> {
    let world = seeded().await?;
    let outcome = async {
        let (tenant, draft) = foreign_draft(&world).await?;
        ensure!(tenant != world.verified.tenant, "the second repository belongs to the world tenant");
        let built = draft.plan.scope().clone();
        let repo = built.repository_id();
        let original = draft.plan.identity().clone();
        let operation = original.operation_id();
        let before_refs = facts::refs(&world.db.pool, repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, repo).await?;
        ensure!(
            draft.token.tenant_id() == tenant && draft.token.operation_id() == operation,
            "the foreign draft token does not name its own tenant and operation"
        );
        // Same-tenant positive control: the migration-138 Pending operation that
        // `PgPackCommit.begin_pending` created for the real draft (not an A4
        // publication registration), produced under the second repository's
        // tenant, is still exactly Pending and has no decision. The bad plan
        // below is a separate operation, never an edit of this one.
        let control = facts::operation(&world.db.pool, repo, operation).await?;
        ensure!(
            control.state == OperationState::Pending.as_str() && control.terminal.is_none(),
            "the foreign draft registration is not exactly pending: {control:?}"
        );
        ensure!(
            facts::decision(&world.db.pool, repo, operation).await?.is_none(),
            "the foreign draft registration already wrote a decision"
        );
        // The bad plan is a fresh operation in its own lane, issued by the real
        // foreign tenant user at a higher sequence. Its identity carries the
        // foreign repository and the fixture's placeholder digest; the plan
        // builder then rebinds the canonical digest over the complete plan, so
        // the only thing wrong with it is the claimed tenant: begin_pending
        // must reach the tenant check instead of a digest conflict.
        let bad_lane = IssuerLane::new("pack-foreign-claim")?;
        let bad_operation = Uuid::new_v4();
        let foreign = OperationIdentity::new(
            repo,
            tenant,
            bad_lane.clone(),
            2,
            bad_operation,
            RequestDigest::from_bytes([0; 32]),
        )?;
        let mut client = world.db.pool.get().await?;
        let baseline = PgPackCommit.capture_baseline(&mut client, repo, tenant, deadline()).await?;
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
            foreign,
            expected,
            HeadUpdate::Keep,
            draft.plan.refs().to_vec(),
            baseline.membership_digest(),
            baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?,
            Vec::new(),
            draft.plan.commit_mode(),
        )?;
        ensure!(
            plan.tenant_id() == world.verified.tenant
                && plan.repository_id() == repo
                && plan.identity().operation_id() == bad_operation
                && plan.identity().lane() == &bad_lane
                && plan.identity().sequence() == 2
                && plan.identity().issuer_id() == tenant
                && plan.identity().digest() != &RequestDigest::from_bytes([0; 32]),
            "the plan does not claim the world tenant on the real second repository as a fresh foreign operation"
        );
        let refused = PgPackCommit.begin_pending(&mut client, &plan, deadline()).await;
        drop(client);
        match refused {
            Err(PackCommitError::Rejected(rejection)) => {
                ensure!(rejection.code == PackCommitRejectCode::TenantMismatch, "another refusal: {rejection:?}")
            }
            other => return Err(anyhow!("begin_pending refused for another reason: {other:?}")),
        }
        ensure!(
            facts::operation_opt(&world.db.pool, repo, bad_operation).await?.is_none(),
            "the refused begin_pending registered the bad-tenant operation"
        );
        ensure!(
            facts::decision(&world.db.pool, repo, bad_operation).await?.is_none(),
            "the refused begin_pending wrote a decision for the bad-tenant operation"
        );
        let after = facts::operation(&world.db.pool, repo, operation).await?;
        ensure!(after == control, "the refused begin_pending changed the original pending operation: {after:?}");
        ensure!(
            facts::decision(&world.db.pool, repo, operation).await?.is_none(),
            "the refused begin_pending wrote a decision"
        );
        facts::assert_unchanged(&world.db.pool, repo, &before_refs, before_revision).await?;
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
        // `fixture::select_as` wraps the typed refusal in `anyhow`; assert only the
        // stable safe denial literal it renders, never raw internals.
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
        // `fixture::select` wraps the typed refusal in `anyhow`; assert only the
        // stable safe denial literal it renders, never raw internals.
        ensure!(denied.to_string().contains("role_denied"), "the no-role issuer was refused otherwise: {denied}");
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
