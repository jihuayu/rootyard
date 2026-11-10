//! Authorized metadata-only accepted-subset cases.
//!
//! Real unserved `metadata_only` gate + explicit protocol provisioning + real
//! authenticated API identity. Effects are metadata ref rows only; these cases
//! never fabricate a `PackCommitPlan`, native fact or proof.
use super::assert as facts;
use super::auth;
use super::fixture;
use super::metadata;
use crate::retention_roots_support::db::deadline;
use anyhow::{Result, ensure};
use rootyard::ref_store::core::{CommitMode, CommitRefsRequest, PgRefStoreCore};
use rootyard::ref_store::{GitObjectFormat, HeadUpdate, IssuerLane};
use uuid::Uuid;

const SHA1: GitObjectFormat = GitObjectFormat::Sha1;

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated metadata decision facade"]
async fn metadata_accepted_subset_applies_only_valid_ref_sets_fence_and_replays_exactly() -> Result<()> {
    let world = metadata::world().await?;
    let outcome = async {
        let oid = metadata::sample_oid(SHA1, 0x22);
        let bad = metadata::sample_oid(SHA1, 0xab);
        let request = world.request(
            vec![
                fixture::update(SHA1, "refs/heads/stale", Some(bad.as_str()), Some(oid.as_str()))?,
                fixture::update(SHA1, "refs/heads/main", None, Some(oid.as_str()))?,
            ],
            1,
            "metadata-subset",
        )?;
        let replay_request = request.clone();
        let operation_id = request.identity().operation_id();
        let before_revision = facts::gate_revision(&world.db.pool, world.repo).await?;
        let prepared = world.prepare(request).await?;
        let receipt = world.commit(&prepared).await?;
        ensure!(receipt.is_committed(), "metadata accepted-subset did not commit the valid ref");
        let refs = facts::refs(&world.db.pool, world.repo).await?;
        ensure!(refs.get("refs/heads/main") == Some(&oid), "valid metadata main creation missing");
        ensure!(!refs.contains_key("refs/heads/stale"), "bad-CAS metadata ref was applied");
        ensure!(facts::gate_revision(&world.db.pool, world.repo).await? == before_revision + 1, "metadata revision");
        facts::assert_durable_consumed(&world.db.pool, world.repo, operation_id).await?;
        // The irreversible fence is now set: a fresh legacy metadata write is
        // refused, while this operation's exact terminal still replays.
        let fresh = CommitRefsRequest::new(
            world.repo,
            world.tenant,
            world.tenant,
            IssuerLane::new("legacy-after-fence")?,
            1,
            Uuid::new_v4(),
            world.gate.object_format(),
            world.gate.history_incarnation(),
            world.gate.authority_epoch(),
            world.gate.group_epoch(),
            before_revision + 1,
            HeadUpdate::Keep,
            CommitMode::AcceptedSubset,
            vec![fixture::update(SHA1, "refs/heads/legacy", None, Some(oid.as_str()))?],
        )?;
        let mut client = world.db.pool.get().await?;
        let legacy = PgRefStoreCore.commit_refs(&mut client, &fresh, deadline()).await;
        drop(client);
        ensure!(legacy.is_err(), "fresh legacy metadata write bypassed the metadata decision fence");
        ensure!(facts::refs(&world.db.pool, world.repo).await? == refs, "fenced legacy write changed refs");

        let replay = world.replay(replay_request).await?;
        ensure!(replay.replayed && replay.is_committed(), "exact metadata terminal replay changed");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated metadata decision facade"]
async fn metadata_revoked_token_final_commit_durably_rejects_without_ref_or_revision_effect() -> Result<()> {
    let world = metadata::world().await?;
    let outcome = async {
        let oid = metadata::sample_oid(SHA1, 0x33);
        let request = world.request(
            vec![fixture::update(SHA1, "refs/heads/main", None, Some(oid.as_str()))?],
            1,
            "metadata-subset",
        )?;
        let operation_id = request.identity().operation_id();
        let before_refs = facts::refs(&world.db.pool, world.repo).await?;
        let before_revision = facts::gate_revision(&world.db.pool, world.repo).await?;
        let prepared = world.prepare(request).await?;
        auth::revoke_token(&world.db.pool, world.actor.token_id).await?;
        let result = world.commit(&prepared).await;
        if let Ok(receipt) = &result {
            ensure!(!receipt.is_committed(), "revoked-token metadata commit reported committed");
        }
        facts::assert_durable_rejection(&world.db.pool, world.repo, operation_id).await?;
        facts::assert_unchanged(&world.db.pool, world.repo, &before_refs, before_revision).await?;
        ensure!(
            !facts::refs(&world.db.pool, world.repo).await?.contains_key("refs/heads/main"),
            "metadata ref written"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated metadata decision facade"]
async fn metadata_reserved_terminal_finishes_at_quota_and_fresh_install_refuses_atomically() -> Result<()> {
    use rootyard::ref_store::core::pack_commit::AuthorizedCommitError;
    use rootyard::ref_store::core::{MetadataDecisionPreparation, PgAuthorizedMetadata};
    let world = metadata::world().await?;
    let outcome = async {
        let oid = metadata::sample_oid(SHA1, 0x44);
        let request =
            world.request(vec![fixture::update(SHA1, "refs/heads/main", None, Some(&oid))?], 1, "metadata-quota")?;
        let replay_request = request.clone();
        let operation_id = request.identity().operation_id();
        let prepared = world.prepare(request).await?;
        let before = facts::gate_revision(&world.db.pool, world.repo).await?;
        // Explicit fault injection after real admission reserved both terminal
        // copies. A full counter must never trap an admitted operation OPEN.
        world
            .db
            .pool
            .get()
            .await?
            .execute(
                "UPDATE ref_store_decision_repo_usage SET logical_bytes=33554432 WHERE repository_id=$1",
                &[&world.repo],
            )
            .await?;
        let receipt = world.commit(&prepared).await?;
        ensure!(receipt.is_committed(), "admitted metadata could not finish using reserved terminal bytes");
        facts::assert_durable_consumed(&world.db.pool, world.repo, operation_id).await?;
        let refs = facts::refs(&world.db.pool, world.repo).await?;
        ensure!(refs.get("refs/heads/main") == Some(&oid), "reserved commit lost its ref");
        ensure!(facts::gate_revision(&world.db.pool, world.repo).await? == before + 1, "reserved commit revision");
        let replay = world.replay(replay_request).await?;
        ensure!(replay.replayed && replay.terminal == receipt.terminal, "full-counter replay changed terminal");
        let fresh = CommitRefsRequest::new(
            world.repo,
            world.tenant,
            world.tenant,
            IssuerLane::new("metadata-full")?,
            1,
            Uuid::new_v4(),
            world.gate.object_format(),
            world.gate.history_incarnation(),
            world.gate.authority_epoch(),
            world.gate.group_epoch(),
            before + 1,
            HeadUpdate::Keep,
            CommitMode::AcceptedSubset,
            vec![fixture::update(SHA1, "refs/heads/fresh", None, Some(&oid))?],
        )?;
        let fresh_operation = fresh.identity().operation_id();
        let result: Result<MetadataDecisionPreparation, AuthorizedCommitError> =
            PgAuthorizedMetadata.prepare(&world.db.pool, fresh, &world.actor.identity, deadline()).await;
        ensure!(
            matches!(result, Err(AuthorizedCommitError::QuotaExceeded)),
            "fresh install did not return typed quota refusal"
        );
        ensure!(
            facts::operation_opt(&world.db.pool, world.repo, fresh_operation).await?.is_none(),
            "refused install left pending operation"
        );
        ensure!(
            facts::decision(&world.db.pool, world.repo, fresh_operation).await?.is_none(),
            "refused install left decision"
        );
        ensure!(facts::refs(&world.db.pool, world.repo).await? == refs, "refused install wrote refs");
        let client = world.db.pool.get().await?;
        let bytes: i64 = client
            .query_one("SELECT logical_bytes FROM ref_store_decision_repo_usage WHERE repository_id=$1", &[&world.repo])
            .await?
            .get(0);
        ensure!(bytes == 33554432, "reserved finish, replay or refusal changed full usage");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    world.db.finish(outcome).await
}
