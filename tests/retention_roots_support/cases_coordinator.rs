//! Authorized serving retention-root coordinator source fixtures. These remain
//! ignored real PG/S3/trusted-Git tests; no HTTP route, keyring or runtime PASS is
//! claimed. Sources and roots are established through the real provision,
//! A3/A4/native publication, A5 serving snapshot and core roots paths.
use anyhow::{Context, Result, anyhow, ensure};
use axum::http::StatusCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

use rootyard::ref_store::{
    PinReleaseReason, RequestDigest,
    core::retention_root::{PgRetentionRoots, RootPurpose, RootReadView, RootSelector},
    serving::{
        PgServingRetentionRoots, PgServingSnapshotMetadata, ServingRootCreate, ServingRootIntent, ServingRootRead,
        ServingRootRelease, ServingRootReleaseTarget, ServingSnapshotCreate, ServingSnapshotRead,
        ServingSnapshotRelease,
    },
};

use crate::retention_roots_support::common::{adapter, open_store};
use crate::retention_roots_support::db::{
    Db, deadline, grant_collaborator, repo_usage, revoke_scope, root_counts, serving_actor_with_scopes,
    serving_collaborator, set_collaborator_role, wait_pin_expired,
};
use crate::retention_roots_support::git::{
    GateRelease, GitGate, GitRepo, assert_pack_identity, git_binary, stock_git_accepts_view,
};
use crate::retention_roots_support::pack::{self, create_serving_snapshot};
use crate::retention_roots_support::roots;
use crate::retention_roots_support::serving::verify_new_serving;

const ROOT_ID_DOMAIN: &str = "serving-root-id-v1";

/// Test mirror of the documented repo-scoped root-id namespace only. It does
/// not duplicate any canonical binding/digest helper.
fn root_id_for(repo_id: Uuid, key: &str) -> Uuid {
    let digest = RequestDigest::of(ROOT_ID_DOMAIN, &[repo_id.as_bytes(), key.as_bytes()]);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn create_input(owner: &str, name: &str, snapshot_id: Uuid, key: &str) -> ServingRootCreate {
    ServingRootCreate {
        owner: owner.to_owned(),
        name: name.to_owned(),
        intent: ServingRootIntent {
            source_snapshot_id: snapshot_id,
            selector: RootSelector::Snapshot,
            purpose: RootPurpose::Ci,
            idempotency_key: key.to_owned(),
        },
    }
}

fn read_input(owner: &str, name: &str, root_id: Uuid) -> ServingRootRead {
    ServingRootRead { owner: owner.to_owned(), name: name.to_owned(), root_id }
}

async fn assert_root_view_matches_source(
    view: &RootReadView,
    source: &pack::SourceSnapshot,
    owner: Uuid,
    tenant: Uuid,
    fixture: &GitRepo,
) -> Result<()> {
    ensure!(
        view.scope().owner_id() == owner
            && view.scope().tenant_id() == tenant
            && !view.packs().is_empty()
            && view.packs().len() == source.read.packs().len(),
        "root view owner/tenant/pack shape differs"
    );
    for expected in source.read.packs() {
        let actual = view
            .packs()
            .iter()
            .find(|pack| pack.pack_id() == expected.pack_id())
            .ok_or_else(|| anyhow!("root view omitted a retained pack"))?;
        assert_pack_identity(expected, actual)?;
    }
    stock_git_accepts_view(view, fixture, deadline()).await?;
    let head = view.head_oid_hex().ok_or_else(|| anyhow!("root HEAD is unborn"))?;
    ensure!(fixture.cat_file(head).await?.contains("fixture main"), "root did not materialize real Git bytes");
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn exact_create_replays_after_source_release_expiry_and_root_release() -> Result<()> {
    let db = Db::setup().await.context("coordinator.fixture.db_setup")?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "coord-exact-replay").await.context("coordinator.legacy.setup")?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300)
            .await
            .context("coordinator.legacy.source_create")?;
        let facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let input = create_input(&repository.owner, &repository.name, source.snapshot_id(), "coord-replay");
        let first =
            facade.create(&db.pool, &actor, input.clone(), deadline()).await.context("coordinator.legacy.create")?;
        ensure!(!first.replayed(), "fresh create replayed");
        let root_id = first.root_id();
        let counts = root_counts(&db.pool, verified.repo).await.context("coordinator.legacy.quota_after_create")?;
        let usage = repo_usage(&db.pool, verified.repo).await.context("coordinator.legacy.usage_after_create")?;

        let record = facade
            .metadata(&db.pool, &actor, read_input(&repository.owner, &repository.name, root_id), deadline())
            .await
            .context("coordinator.legacy.metadata_active")?
            .ok_or_else(|| anyhow::anyhow!("fresh root metadata missing"))?;
        ensure!(record.is_active(), "fresh root is not active");

        roots::release_serving_source(
            &PgServingSnapshotMetadata,
            &db.pool,
            &actor,
            &store,
            &repository,
            &source,
            deadline(),
        )
        .await
        .context("coordinator.legacy.source_release")?;
        let replay = facade
            .create(&db.pool, &actor, input.clone(), deadline())
            .await
            .context("coordinator.legacy.create_replay_after_source_release")?;
        ensure!(replay.replayed() && replay.root_id() == root_id, "released-source exact replay differs");
        ensure!(
            root_counts(&db.pool, verified.repo).await.context("coordinator.legacy.quota_after_create_replay")?
                == counts,
            "replay charged root quota"
        );
        ensure!(
            repo_usage(&db.pool, verified.repo).await.context("coordinator.legacy.usage_after_create_replay")? == usage,
            "replay charged usage counters"
        );

        let view = facade
            .materialize(&db.pool, &actor, read_input(&repository.owner, &repository.name, root_id), deadline())
            .await
            .context("coordinator.legacy.materialize_after_source_release")?;
        ensure!(view.refs() == record.refs(), "serving root view refs differ after source release");
        stock_git_accepts_view(&view, &verified.fixture, deadline())
            .await
            .context("coordinator.legacy.git_verify_after_source_release")?;

        let release = ServingRootRelease {
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            target: ServingRootReleaseTarget::Existing { root_id },
            idempotency_key: "coord-replay-release".to_owned(),
            reason: "fixture release".to_owned(),
        };
        let released =
            facade.release(&db.pool, &actor, release, deadline()).await.context("coordinator.legacy.release_active")?;
        ensure!(released.state() == "released", "root release state differs");
        let replay_after_release = facade
            .create(&db.pool, &actor, input.clone(), deadline())
            .await
            .context("coordinator.legacy.create_replay_after_root_release")?;
        ensure!(
            replay_after_release.replayed() && replay_after_release.root_id() == root_id,
            "released-root exact replay differs"
        );
        let released_record = facade
            .metadata(&db.pool, &actor, read_input(&repository.owner, &repository.name, root_id), deadline())
            .await
            .context("coordinator.legacy.metadata_released")?
            .ok_or_else(|| anyhow::anyhow!("released root metadata missing"))?;
        ensure!(released_record.state() == "released", "metadata did not retain released root state");

        // Actual source-pin expiry has the same no-source replay property.
        let expiring = create_serving_snapshot(&db, &store, &actor, &repository, 8)
            .await
            .context("coordinator.legacy.expiring_source_create")?;
        let expiring_input = create_input(&repository.owner, &repository.name, expiring.snapshot_id, "coord-expiry");
        let expiring_receipt = facade
            .create(&db.pool, &actor, expiring_input.clone(), deadline())
            .await
            .context("coordinator.legacy.expiring_create")?;
        wait_pin_expired(&db.pool, expiring.pin_id).await.context("coordinator.legacy.wait_expiry")?;
        let expiring_view = facade
            .materialize(
                &db.pool,
                &actor,
                read_input(&repository.owner, &repository.name, expiring_receipt.root_id()),
                deadline(),
            )
            .await
            .context("coordinator.legacy.expiring_materialize")?;
        ensure!(expiring_view.refs() == expiring.read.refs(), "expired source root view changed refs");
        let expiring_replay = facade
            .create(&db.pool, &actor, expiring_input, deadline())
            .await
            .context("coordinator.legacy.expiring_create_replay")?;
        ensure!(
            expiring_replay.replayed() && expiring_replay.root_id() == expiring_receipt.root_id(),
            "expired-source exact replay differs"
        );

        // Additive actor-owned root lifecycle. Both roots are created through
        // the actor facade while the source A5 pin is live; default existing-root
        // APIs intentionally remain owner-independent for a current Admin.
        let producer = serving_collaborator(&db.pool, verified.repo, verified.tenant, "admin", "owned-root-")
            .await
            .context("coordinator.actor.producer_grant")?;
        ensure!(
            producer.id != actor.id && producer.id != verified.tenant,
            "actor-owned root producer is not a distinct principal"
        );
        let owned_source_create = ServingSnapshotCreate {
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            idempotency_key: "coord-owned-source".into(),
            lease_seconds: 300,
        };
        let owned_source_outcome = PgServingSnapshotMetadata
            .create_actor_owned(&db.pool, &producer, owned_source_create.clone(), store.backend_identity(), deadline())
            .await
            .context("coordinator.actor.source_create")?;
        ensure!(!owned_source_outcome.replayed, "actor-owned source create replayed");
        ensure!(
            owned_source_outcome.receipt.scope().owner_id() == producer.id
                && owned_source_outcome.receipt.scope().tenant_id() == verified.tenant,
            "actor-owned source persisted the wrong owner/tenant"
        );
        let owned_source_read = PgServingSnapshotMetadata
            .read_actor_owned(
                &db.pool,
                &producer,
                ServingSnapshotRead {
                    owner: repository.owner.clone(),
                    name: repository.name.clone(),
                    snapshot_id: owned_source_outcome.receipt.snapshot_id(),
                },
                store.backend_identity(),
                deadline(),
            )
            .await
            .context("coordinator.actor.source_read")?;
        ensure!(
            owned_source_read.scope().owner_id() == producer.id
                && owned_source_read.scope().tenant_id() == verified.tenant
                && !owned_source_read.packs().is_empty(),
            "actor-owned source read owner/pack shape differs"
        );
        let owned_source = pack::SourceSnapshot {
            scope: *owned_source_read.scope(),
            request_id: owned_source_outcome.receipt.request_id(),
            snapshot_id: owned_source_outcome.receipt.snapshot_id(),
            pin_id: owned_source_outcome.receipt.pin_id(),
            read: owned_source_read,
        };

        let mut default_input =
            create_input(&repository.owner, &repository.name, owned_source.snapshot_id, "coord-owned-default");
        default_input.intent.purpose = RootPurpose::Backup;
        let default_root = facade
            .create_actor_owned(&db.pool, &producer, default_input.clone(), deadline())
            .await
            .context("coordinator.actor.default_root_create")?;
        ensure!(
            !default_root.replayed()
                && default_root.state() == "active"
                && default_root.owner_id() == producer.id
                && default_root.tenant_id() == verified.tenant,
            "default-compatibility actor root create receipt differs"
        );
        let default_root_id = default_root.root_id();
        let default_read_input = read_input(&repository.owner, &repository.name, default_root_id);

        let mut actor_input =
            create_input(&repository.owner, &repository.name, owned_source.snapshot_id, "coord-owned-actor");
        actor_input.intent.purpose = RootPurpose::Backup;
        let actor_root = facade
            .create_actor_owned(&db.pool, &producer, actor_input.clone(), deadline())
            .await
            .context("coordinator.actor.actor_root_create")?;
        ensure!(
            !actor_root.replayed()
                && actor_root.state() == "active"
                && actor_root.owner_id() == producer.id
                && actor_root.tenant_id() == verified.tenant,
            "actor-owned root create receipt differs"
        );
        let actor_root_id = actor_root.root_id();
        let actor_read_input = read_input(&repository.owner, &repository.name, actor_root_id);
        let created_counts =
            root_counts(&db.pool, verified.repo).await.context("coordinator.actor.quota_after_roots")?;
        let created_usage = repo_usage(&db.pool, verified.repo).await.context("coordinator.actor.usage_after_roots")?;

        // Release the actor-owned source pin; both root receipts remain retained.
        PgServingSnapshotMetadata
            .release_actor_owned(
                &db.pool,
                &producer,
                ServingSnapshotRelease {
                    owner: repository.owner.clone(),
                    name: repository.name.clone(),
                    snapshot_id: owned_source.snapshot_id,
                    idempotency_key: "coord-owned-source-release".into(),
                    expected_generation: 1,
                    reason: PinReleaseReason::ClientDone,
                },
                store.backend_identity(),
                deadline(),
            )
            .await
            .context("coordinator.actor.source_release")?;

        // Exact create replay is source-pin independent for both actor roots.
        let default_replay = facade
            .create_actor_owned(&db.pool, &producer, default_input.clone(), deadline())
            .await
            .context("coordinator.actor.default_create_replay_after_source_release")?;
        ensure!(
            default_replay.replayed() && default_replay.root_id() == default_root_id,
            "default-compatibility root create replay differs"
        );
        let actor_replay = facade
            .create_actor_owned(&db.pool, &producer, actor_input.clone(), deadline())
            .await
            .context("coordinator.actor.actor_create_replay_after_source_release")?;
        ensure!(
            actor_replay.replayed() && actor_replay.root_id() == actor_root_id,
            "actor-owned root create replay differs"
        );
        ensure!(
            root_counts(&db.pool, verified.repo).await.context("coordinator.actor.quota_after_create_replay")?
                == created_counts
                && repo_usage(&db.pool, verified.repo).await.context("coordinator.actor.usage_after_create_replay")?
                    == created_usage,
            "actor-owned create replay charged root quota or usage"
        );

        // Actor-owned metadata/materialize remain actor-bound.
        let actor_record = facade
            .metadata_actor_owned(&db.pool, &producer, actor_read_input.clone(), deadline())
            .await
            .context("coordinator.actor.actor_metadata_active")?
            .ok_or_else(|| anyhow!("actor-owned root metadata missing"))?;
        ensure!(
            actor_record.owner_id() == producer.id
                && actor_record.tenant_id() == verified.tenant
                && actor_record.purpose() == RootPurpose::Backup
                && actor_record.is_active()
                && actor_record.pack_count() > 0,
            "actor-owned root metadata owner/purpose/shape differs"
        );
        let actor_view = facade
            .materialize_actor_owned(&db.pool, &producer, actor_read_input.clone(), deadline())
            .await
            .context("coordinator.actor.actor_materialize_after_source_release")?;
        assert_root_view_matches_source(&actor_view, &owned_source, producer.id, verified.tenant, &verified.fixture)
            .await
            .context("coordinator.actor.actor_view_verify")?;

        // Default metadata/materialize preserve historical owner-independent
        // existing-root access while retaining the stored producer owner.
        let default_record = facade
            .metadata(&db.pool, &actor, default_read_input.clone(), deadline())
            .await
            .context("coordinator.actor.default_metadata_active")?
            .ok_or_else(|| anyhow!("default compatibility root metadata missing"))?;
        ensure!(
            default_record.owner_id() == producer.id
                && default_record.tenant_id() == verified.tenant
                && default_record.purpose() == RootPurpose::Backup
                && default_record.is_active()
                && default_record.pack_count() > 0,
            "default metadata did not preserve the stored producer owner"
        );
        let default_view = facade
            .materialize(&db.pool, &actor, default_read_input.clone(), deadline())
            .await
            .context("coordinator.actor.default_materialize_after_source_release")?;
        assert_root_view_matches_source(&default_view, &owned_source, producer.id, verified.tenant, &verified.fixture)
            .await
            .context("coordinator.actor.default_view_verify")?;

        // Explicit actor-owned access still rejects a different authorized Admin.
        match facade.metadata_actor_owned(&db.pool, &actor, actor_read_input.clone(), deadline()).await {
            Err(error) if error.0 == StatusCode::NOT_FOUND => {}
            Err(error) => {
                return Err(anyhow!("non-owner actor-owned root metadata returned {} {}", error.0, error.1)
                    .context("coordinator.actor.nonowner_metadata_unexpected_status"));
            }
            Ok(_) => return Err(anyhow!("non-owner actor-owned root metadata unexpectedly returned")),
        }
        match facade.materialize_actor_owned(&db.pool, &actor, actor_read_input.clone(), deadline()).await {
            Err(error) if error.0 == StatusCode::NOT_FOUND => {}
            Err(error) => {
                return Err(anyhow!("non-owner actor-owned root materialize returned {} {}", error.0, error.1)
                    .context("coordinator.actor.nonowner_materialize_unexpected_status"));
            }
            Ok(_) => return Err(anyhow!("non-owner actor-owned root materialize unexpectedly returned")),
        }
        let default_release = ServingRootRelease {
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            target: ServingRootReleaseTarget::Existing { root_id: default_root_id },
            idempotency_key: "coord-owned-default-release".into(),
            reason: "fixture default release of producer-owned root".into(),
        };
        let actor_release = ServingRootRelease {
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            target: ServingRootReleaseTarget::Existing { root_id: actor_root_id },
            idempotency_key: "coord-owned-actor-release".into(),
            reason: "fixture actor-owned root release".into(),
        };
        match facade.release_actor_owned(&db.pool, &actor, actor_release.clone(), deadline()).await {
            Err(error) if error.0 == StatusCode::NOT_FOUND => {}
            Err(error) => {
                return Err(anyhow!("non-owner actor-owned root release returned {} {}", error.0, error.1)
                    .context("coordinator.actor.nonowner_release_unexpected_status"));
            }
            Ok(_) => return Err(anyhow!("non-owner actor-owned root release unexpectedly returned")),
        }
        ensure!(
            root_counts(&db.pool, verified.repo).await.context("coordinator.actor.quota_after_negative_checks")?
                == created_counts
                && repo_usage(&db.pool, verified.repo)
                    .await
                    .context("coordinator.actor.usage_after_negative_checks")?
                    == created_usage,
            "actor-owned refusals charged root quota or usage"
        );

        // Default release Existing must work for a current Admin even though the
        // durable owner is the producer; exact replay returns the same terminal.
        let default_released = facade
            .release(&db.pool, &actor, default_release.clone(), deadline())
            .await
            .context("coordinator.actor.default_root_release")?;
        ensure!(
            default_released.state() == "released"
                && default_released.root_id() == default_root_id
                && default_released.owner_id() == producer.id,
            "default release of producer-owned root state/owner differs"
        );
        let default_released_counts =
            root_counts(&db.pool, verified.repo).await.context("coordinator.actor.quota_after_default_release")?;
        let default_released_usage =
            repo_usage(&db.pool, verified.repo).await.context("coordinator.actor.usage_after_default_release")?;
        let default_release_replay = facade
            .release(&db.pool, &actor, default_release, deadline())
            .await
            .context("coordinator.actor.default_release_replay")?;
        ensure!(
            default_release_replay.replayed()
                && default_release_replay.root_id() == default_root_id
                && default_release_replay.request_digest() == default_released.request_digest()
                && default_release_replay.created_at_unix_micros() == default_released.created_at_unix_micros(),
            "default release replay did not return the same terminal"
        );
        ensure!(
            root_counts(&db.pool, verified.repo)
                .await
                .context("coordinator.actor.quota_after_default_release_replay")?
                == default_released_counts
                && repo_usage(&db.pool, verified.repo)
                    .await
                    .context("coordinator.actor.usage_after_default_release_replay")?
                    == default_released_usage,
            "default release replay charged root quota or usage"
        );
        let default_released_record = facade
            .metadata(&db.pool, &actor, default_read_input.clone(), deadline())
            .await
            .context("coordinator.actor.default_metadata_released")?
            .ok_or_else(|| anyhow!("default released root metadata missing"))?;
        ensure!(
            default_released_record.owner_id() == producer.id && default_released_record.state() == "released",
            "default released metadata did not retain producer owner/state"
        );

        // Explicit actor-owned release works on its actor's root.
        let actor_released = facade
            .release_actor_owned(&db.pool, &producer, actor_release.clone(), deadline())
            .await
            .context("coordinator.actor.actor_root_release")?;
        ensure!(
            actor_released.state() == "released"
                && actor_released.root_id() == actor_root_id
                && actor_released.owner_id() == producer.id,
            "actor-owned root release state/owner differs"
        );
        let actor_released_counts =
            root_counts(&db.pool, verified.repo).await.context("coordinator.actor.quota_after_actor_release")?;
        let actor_released_usage =
            repo_usage(&db.pool, verified.repo).await.context("coordinator.actor.usage_after_actor_release")?;
        let actor_release_replay = facade
            .release_actor_owned(&db.pool, &producer, actor_release, deadline())
            .await
            .context("coordinator.actor.actor_release_replay")?;
        ensure!(
            actor_release_replay.replayed()
                && actor_release_replay.root_id() == actor_root_id
                && actor_release_replay.request_digest() == actor_released.request_digest()
                && actor_release_replay.created_at_unix_micros() == actor_released.created_at_unix_micros(),
            "actor-owned release replay did not return the same terminal"
        );
        let actor_create_after_release = facade
            .create_actor_owned(&db.pool, &producer, actor_input, deadline())
            .await
            .context("coordinator.actor.actor_create_replay_after_root_release")?;
        ensure!(
            actor_create_after_release.replayed() && actor_create_after_release.root_id() == actor_root_id,
            "actor-owned create replay after root release differs"
        );
        ensure!(
            root_counts(&db.pool, verified.repo).await.context("coordinator.actor.quota_after_actor_release_replay")?
                == actor_released_counts
                && repo_usage(&db.pool, verified.repo)
                    .await
                    .context("coordinator.actor.usage_after_actor_release_replay")?
                    == actor_released_usage,
            "actor-owned release/create replay charged root quota or usage"
        );
        let actor_released_record = facade
            .metadata_actor_owned(&db.pool, &producer, actor_read_input.clone(), deadline())
            .await
            .context("coordinator.actor.actor_metadata_released")?
            .ok_or_else(|| anyhow!("actor-owned released root metadata missing"))?;
        ensure!(
            actor_released_record.owner_id() == producer.id && actor_released_record.state() == "released",
            "actor-owned released state/owner differs"
        );

        // Admin role loss is a real RBAC refusal; no ownership fallback.
        let revoked_counts =
            root_counts(&db.pool, verified.repo).await.context("coordinator.actor.quota_before_role_revoke")?;
        let revoked_usage =
            repo_usage(&db.pool, verified.repo).await.context("coordinator.actor.usage_before_role_revoke")?;
        set_collaborator_role(&db.pool, verified.repo, producer.id, "write")
            .await
            .context("coordinator.actor.role_revoke")?;
        match facade.metadata_actor_owned(&db.pool, &producer, actor_read_input.clone(), deadline()).await {
            Err(error) if error.0 == StatusCode::FORBIDDEN => {}
            Err(error) => {
                return Err(anyhow!("role-revoked root metadata returned {} {}", error.0, error.1)
                    .context("coordinator.actor.role_revoked_metadata_unexpected_status"));
            }
            Ok(_) => return Err(anyhow!("role-revoked root metadata unexpectedly returned")),
        }
        match facade.materialize_actor_owned(&db.pool, &producer, actor_read_input, deadline()).await {
            Err(error) if error.0 == StatusCode::FORBIDDEN => {}
            Err(error) => {
                return Err(anyhow!("role-revoked root materialize returned {} {}", error.0, error.1)
                    .context("coordinator.actor.role_revoked_materialize_unexpected_status"));
            }
            Ok(_) => return Err(anyhow!("role-revoked root materialize unexpectedly returned")),
        }
        ensure!(
            root_counts(&db.pool, verified.repo).await.context("coordinator.actor.quota_after_role_revoke")?
                == revoked_counts,
            "role-revoked root metadata charged quota"
        );
        ensure!(
            repo_usage(&db.pool, verified.repo).await.context("coordinator.actor.usage_after_role_revoke")?
                == revoked_usage,
            "role-revoked root materialize charged usage"
        );

        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn changed_create_intent_under_same_key_conflicts_without_charge() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) = verify_new_serving(&db, &store, &git, "coord-changed-intent").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let input = create_input(&repository.owner, &repository.name, source.snapshot_id(), "coord-changed");
        facade.create(&db.pool, &actor, input.clone(), deadline()).await?;
        let counts = root_counts(&db.pool, verified.repo).await?;
        let usage = repo_usage(&db.pool, verified.repo).await?;
        let mut changed = input.clone();
        changed.intent.purpose = RootPurpose::Workspace;
        let error = facade
            .create(&db.pool, &actor, changed, deadline())
            .await
            .expect_err("changed create intent under the same key was accepted");
        ensure!(error.0 == StatusCode::CONFLICT, "changed intent returned the wrong status: {error:?}");
        ensure!(root_counts(&db.pool, verified.repo).await? == counts, "changed intent charged root quota");
        ensure!(repo_usage(&db.pool, verified.repo).await? == usage, "changed intent charged usage");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn late_scope_or_role_loss_after_prepare_rolls_back_create_and_reads_deny() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) = verify_new_serving(&db, &store, &git, "coord-late-auth").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let baseline = root_counts(&db.pool, verified.repo).await?;

        // Restricted write-scope admin: preflight succeeds, then the scope is
        // revoked while native prepare is paused. Final auth must roll back the
        // already-staged root rows/receipt/charge.
        let late_scope =
            serving_actor_with_scopes(&db.pool, verified.repo, &["contents_write"], "coord-late-scope-").await?;
        grant_collaborator(&db.pool, verified.repo, verified.tenant, late_scope.id, "admin").await?;
        let gate = GitGate::new(&git)?;
        let _release_guard = GateRelease(&gate);
        let gated = Arc::new(PgServingRetentionRoots::new(PgRetentionRoots::new(store.clone(), gate.binary())?));
        let input = create_input(&repository.owner, &repository.name, source.snapshot_id(), "coord-late-scope");
        let task_pool = db.pool.clone();
        let task_actor = late_scope.clone();
        let task_input = input.clone();
        let task = tokio::spawn(async move { gated.create(&task_pool, &task_actor, task_input, deadline()).await });
        gate.wait_ready().await?;
        revoke_scope(&db.pool, &late_scope, verified.repo).await?;
        gate.release()?;
        let result = timeout(Duration::from_secs(30), task)
            .await
            .map_err(|_| anyhow::anyhow!("late-scope create did not finish"))??;
        ensure!(result.is_err(), "revoked write scope still created a root");
        ensure!(
            root_counts(&db.pool, verified.repo).await? == baseline,
            "late-scope refusal left staged root rows or charges"
        );

        // Role downgrade after native prepare has the same rollback contract.
        let downgraded = serving_collaborator(&db.pool, verified.repo, verified.tenant, "admin", "coord-role-").await?;
        let gate = GitGate::new(&git)?;
        let _release_guard = GateRelease(&gate);
        let gated = Arc::new(PgServingRetentionRoots::new(PgRetentionRoots::new(store.clone(), gate.binary())?));
        let input = create_input(&repository.owner, &repository.name, source.snapshot_id(), "coord-role");
        let task_pool = db.pool.clone();
        let task_actor = downgraded.clone();
        let task_input = input.clone();
        let task = tokio::spawn(async move { gated.create(&task_pool, &task_actor, task_input, deadline()).await });
        gate.wait_ready().await?;
        set_collaborator_role(&db.pool, verified.repo, downgraded.id, "write").await?;
        gate.release()?;
        let result = timeout(Duration::from_secs(30), task)
            .await
            .map_err(|_| anyhow::anyhow!("role-downgrade create did not finish"))??;
        ensure!(result.is_err(), "downgraded role still created a root");
        ensure!(
            root_counts(&db.pool, verified.repo).await? == baseline,
            "role-downgrade refusal left staged root rows or charges"
        );

        // A valid root for read-scope loss must not return a view.
        let owner_facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let owner_input = create_input(&repository.owner, &repository.name, source.snapshot_id(), "coord-read-scope");
        let owner_receipt = owner_facade.create(&db.pool, &actor, owner_input, deadline()).await?;
        let reader = serving_actor_with_scopes(&db.pool, verified.repo, &["contents_read"], "coord-late-read-").await?;
        grant_collaborator(&db.pool, verified.repo, verified.tenant, reader.id, "admin").await?;
        let gate = GitGate::new(&git)?;
        let _release_guard = GateRelease(&gate);
        let gated = Arc::new(PgServingRetentionRoots::new(PgRetentionRoots::new(store.clone(), gate.binary())?));
        let request = read_input(&repository.owner, &repository.name, owner_receipt.root_id());
        let task_pool = db.pool.clone();
        let task_reader = reader.clone();
        let task = tokio::spawn(async move { gated.materialize(&task_pool, &task_reader, request, deadline()).await });
        gate.wait_ready().await?;
        revoke_scope(&db.pool, &reader, verified.repo).await?;
        gate.release()?;
        let result = timeout(Duration::from_secs(30), task)
            .await
            .map_err(|_| anyhow::anyhow!("late-read-scope materialize did not finish"))??;
        ensure!(result.is_err(), "revoked read scope still returned a root view");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn release_before_register_fences_delayed_create_and_replays_without_source() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) = verify_new_serving(&db, &store, &git, "coord-release-before").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let create_key = "coord-release-before";
        let root_id = root_id_for(verified.repo, create_key);
        let create = create_input(&repository.owner, &repository.name, source.snapshot_id(), create_key);
        let release = ServingRootRelease {
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            target: ServingRootReleaseTarget::Absent { root_id, create: create.intent.clone() },
            idempotency_key: "coord-release-before-key".to_owned(),
            reason: "release before delayed register".to_owned(),
        };

        let gate = GitGate::new(&git)?;
        let _release_guard = GateRelease(&gate);
        let gated = Arc::new(PgServingRetentionRoots::new(PgRetentionRoots::new(store.clone(), gate.binary())?));
        let task_pool = db.pool.clone();
        let task_actor = actor.clone();
        let task_create = create.clone();
        let task = tokio::spawn(async move { gated.create(&task_pool, &task_actor, task_create, deadline()).await });
        gate.wait_ready().await?;
        let tombstone = facade.release(&db.pool, &actor, release.clone(), deadline()).await?;
        ensure!(tombstone.state() == "released", "release-before-register state differs");
        gate.release()?;
        let result = timeout(Duration::from_secs(30), task)
            .await
            .map_err(|_| anyhow::anyhow!("delayed register did not finish"))??;
        let error = result.expect_err("delayed register installed a released root");
        ensure!(error.0 == StatusCode::CONFLICT, "delayed register returned the wrong status: {error:?}");
        let counts = root_counts(&db.pool, verified.repo).await?;
        ensure!(
            counts.heads == 1 && counts.captures == 0 && counts.receipts == 1,
            "release-before-register left a capture or partial root"
        );
        roots::release_serving_source(
            &PgServingSnapshotMetadata,
            &db.pool,
            &actor,
            &store,
            &repository,
            &source,
            deadline(),
        )
        .await?;
        let replay = facade.release(&db.pool, &actor, release, deadline()).await?;
        ensure!(replay.replayed() && replay.state() == "released", "release exact replay differs");
        ensure!(root_counts(&db.pool, verified.repo).await? == counts, "release exact replay charged or rewrote rows");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn concurrent_exact_create_replay_is_source_pin_independent() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) = verify_new_serving(&db, &store, &git, "coord-concurrent-replay").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let input = create_input(&repository.owner, &repository.name, source.snapshot_id(), "coord-concurrent-replay");

        // B misses the early retained-replay lookup, reads the live source, then
        // pauses in actual native prepare with no PostgreSQL transaction held.
        let gate = GitGate::new(&git)?;
        let release_guard = GateRelease(&gate);
        let paused_facade =
            Arc::new(PgServingRetentionRoots::new(PgRetentionRoots::new(store.clone(), gate.binary())?));
        let paused_pool = db.new_pool(1)?;
        let task_pool = paused_pool.clone();
        let task_actor = actor.clone();
        let task_input = input.clone();
        let task =
            tokio::spawn(async move { paused_facade.create(&task_pool, &task_actor, task_input, deadline()).await });
        gate.wait_ready().await?;
        // B's T1 transaction/client is gone while native is paused: the same
        // max-size-one pool can still hand out its only connection.
        let observer = timeout(Duration::from_secs(2), paused_pool.get())
            .await
            .map_err(|_| anyhow::anyhow!("concurrent replay kept a PG client across native IO"))??;
        drop(observer);

        // A uses the normal trusted Git adapter/facade and completes the SAME
        // canonical key/intent while B is paused.
        let normal = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let first = normal.create(&db.pool, &actor, input.clone(), deadline()).await?;
        ensure!(!first.replayed(), "normal concurrent winner was unexpectedly replayed");
        let root_id = first.root_id();
        let created_at = first.created_at_unix_micros();
        let request_digest = first.request_digest();
        let counts = root_counts(&db.pool, verified.repo).await?;
        let usage = repo_usage(&db.pool, verified.repo).await?;

        // Release the original source pin through the real serving path before B
        // resumes. B's core register must resolve the exact existing receipt
        // before any source-liveness check.
        roots::release_serving_source(
            &PgServingSnapshotMetadata,
            &db.pool,
            &actor,
            &store,
            &repository,
            &source,
            deadline(),
        )
        .await?;
        gate.release()?;
        let result = timeout(Duration::from_secs(30), task)
            .await
            .map_err(|_| anyhow::anyhow!("paused concurrent create did not finish"))??;
        let replay = result.expect("concurrent exact create replay was rejected");
        ensure!(replay.replayed(), "concurrent loser did not return an exact replay receipt");
        ensure!(replay.root_id() == root_id, "concurrent replay returned another root");
        ensure!(replay.created_at_unix_micros() == created_at, "concurrent replay returned another receipt body");
        ensure!(replay.request_digest() == request_digest, "concurrent replay request digest differs");
        ensure!(root_counts(&db.pool, verified.repo).await? == counts, "concurrent exact replay rewrote root rows");
        ensure!(repo_usage(&db.pool, verified.repo).await? == usage, "concurrent exact replay charged usage");
        drop(release_guard);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn release_by_intent_releases_existing_root_after_source_pin_release() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) = verify_new_serving(&db, &store, &git, "coord-release-by-intent").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let create = create_input(&repository.owner, &repository.name, source.snapshot_id(), "coord-by-intent");
        let receipt = facade.create(&db.pool, &actor, create.clone(), deadline()).await?;
        roots::release_serving_source(
            &PgServingSnapshotMetadata,
            &db.pool,
            &actor,
            &store,
            &repository,
            &source,
            deadline(),
        )
        .await?;
        let release = ServingRootRelease {
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            target: ServingRootReleaseTarget::ByIntent { create: create.intent.clone() },
            idempotency_key: "coord-by-intent-release".to_owned(),
            reason: "release existing by original intent".to_owned(),
        };
        let released = facade.release(&db.pool, &actor, release.clone(), deadline()).await?;
        ensure!(
            released.state() == "released" && released.root_id() == receipt.root_id(),
            "by-intent existing release differs"
        );
        let counts = root_counts(&db.pool, verified.repo).await?;
        let usage = repo_usage(&db.pool, verified.repo).await?;
        let replay = facade.release(&db.pool, &actor, release, deadline()).await?;
        ensure!(replay.replayed() && replay.state() == "released", "by-intent release replay differs");
        ensure!(root_counts(&db.pool, verified.repo).await? == counts, "by-intent release replay changed root rows");
        ensure!(repo_usage(&db.pool, verified.repo).await? == usage, "by-intent release replay charged usage");
        let record = facade
            .metadata(&db.pool, &actor, read_input(&repository.owner, &repository.name, receipt.root_id()), deadline())
            .await?
            .ok_or_else(|| anyhow::anyhow!("released by-intent root metadata missing"))?;
        ensure!(record.state() == "released", "by-intent root metadata is not released");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn release_by_intent_tombstone_replays_before_source_metadata() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "coord-release-intent-tombstone").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let create = create_input(&repository.owner, &repository.name, source.snapshot_id(), "coord-intent-tombstone");
        let release = ServingRootRelease {
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            target: ServingRootReleaseTarget::ByIntent { create: create.intent.clone() },
            idempotency_key: "coord-intent-tombstone-release".to_owned(),
            reason: "release before any register".to_owned(),
        };
        let first = facade.release(&db.pool, &actor, release.clone(), deadline()).await?;
        ensure!(first.state() == "released", "pre-register by-intent release state differs");
        let counts = root_counts(&db.pool, verified.repo).await?;
        ensure!(
            counts.heads == 1 && counts.captures == 0 && counts.receipts == 1,
            "pre-register by-intent release wrote a capture"
        );
        roots::release_serving_source(
            &PgServingSnapshotMetadata,
            &db.pool,
            &actor,
            &store,
            &repository,
            &source,
            deadline(),
        )
        .await?;
        let replay = facade.release(&db.pool, &actor, release, deadline()).await?;
        ensure!(replay.replayed() && replay.state() == "released", "pre-register release replay differs");
        ensure!(root_counts(&db.pool, verified.repo).await? == counts, "pre-register release replay changed rows");
        ensure!(
            facade
                .metadata(
                    &db.pool,
                    &actor,
                    read_input(&repository.owner, &repository.name, first.root_id()),
                    deadline(),
                )
                .await?
                .is_none(),
            "pre-register by-intent release unexpectedly gained a capture"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn release_by_intent_changed_intent_conflicts_without_touching_root() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "coord-release-intent-conflict").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let create = create_input(&repository.owner, &repository.name, source.snapshot_id(), "coord-intent-conflict");
        let receipt = facade.create(&db.pool, &actor, create.clone(), deadline()).await?;
        let counts = root_counts(&db.pool, verified.repo).await?;
        let usage = repo_usage(&db.pool, verified.repo).await?;
        let mut changed = create.intent.clone();
        changed.purpose = RootPurpose::Workspace;
        let error = facade
            .release(
                &db.pool,
                &actor,
                ServingRootRelease {
                    owner: repository.owner.clone(),
                    name: repository.name.clone(),
                    target: ServingRootReleaseTarget::ByIntent { create: changed },
                    idempotency_key: "coord-intent-conflict-release".to_owned(),
                    reason: "changed original intent".to_owned(),
                },
                deadline(),
            )
            .await
            .expect_err("changed by-intent release was accepted");
        ensure!(error.0 == StatusCode::CONFLICT, "changed by-intent release returned the wrong status: {error:?}");
        ensure!(root_counts(&db.pool, verified.repo).await? == counts, "changed by-intent release changed root rows");
        ensure!(repo_usage(&db.pool, verified.repo).await? == usage, "changed by-intent release charged usage");
        let record = facade
            .metadata(&db.pool, &actor, read_input(&repository.owner, &repository.name, receipt.root_id()), deadline())
            .await?
            .ok_or_else(|| anyhow::anyhow!("existing root disappeared after changed-intent release"))?;
        ensure!(record.is_active(), "changed by-intent release released the existing root");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
