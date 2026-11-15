//! Authorized serving retention-root coordinator source fixtures. These remain
//! ignored real PG/S3/trusted-Git tests; no HTTP route, keyring or runtime PASS is
//! claimed. Sources and roots are established through the real provision,
//! A3/A4/native publication, A5 serving snapshot and core roots paths.
use anyhow::{Result, ensure};
use axum::http::StatusCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

use rootyard::ref_store::{
    RequestDigest,
    core::retention_root::{PgRetentionRoots, RootPurpose, RootSelector},
    serving::{
        PgServingRetentionRoots, PgServingSnapshotMetadata, ServingRootCreate, ServingRootIntent, ServingRootRead,
        ServingRootRelease, ServingRootReleaseTarget,
    },
};

use crate::retention_roots_support::common::{adapter, open_store};
use crate::retention_roots_support::db::{
    Db, deadline, grant_collaborator, repo_usage, revoke_scope, root_counts, serving_actor_with_scopes,
    serving_collaborator, set_collaborator_role, wait_pin_expired,
};
use crate::retention_roots_support::git::{GateRelease, GitGate, git_binary, stock_git_accepts_view};
use crate::retention_roots_support::pack::{create_serving_snapshot, verify_new_serving};
use crate::retention_roots_support::roots;

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

fn create_input(
    owner: &str,
    name: &str,
    snapshot_id: Uuid,
    key: &str,
) -> ServingRootCreate {
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

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn exact_create_replays_after_source_release_expiry_and_root_release() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "coord-exact-replay").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let input = create_input(&repository.owner, &repository.name, source.snapshot_id, "coord-replay");
        let first = facade.create(&db.pool, &actor, input.clone(), deadline()).await?;
        ensure!(!first.replayed(), "fresh create replayed");
        let root_id = first.root_id();
        let counts = root_counts(&db.pool, verified.repo).await?;
        let usage = repo_usage(&db.pool, verified.repo).await?;

        let record = facade
            .metadata(&db.pool, &actor, read_input(&repository.owner, &repository.name, root_id), deadline())
            .await?
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
        .await?;
        let replay = facade.create(&db.pool, &actor, input.clone(), deadline()).await?;
        ensure!(replay.replayed() && replay.root_id() == root_id, "released-source exact replay differs");
        ensure!(root_counts(&db.pool, verified.repo).await? == counts, "replay charged root quota");
        ensure!(repo_usage(&db.pool, verified.repo).await? == usage, "replay charged usage counters");

        let view = facade
            .materialize(
                &db.pool,
                &actor,
                read_input(&repository.owner, &repository.name, root_id),
                deadline(),
            )
            .await?;
        ensure!(view.refs() == record.refs(), "serving root view refs differ after source release");
        stock_git_accepts_view(&view, &verified.fixture, deadline()).await?;

        let release = ServingRootRelease {
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            target: ServingRootReleaseTarget::Existing { root_id },
            idempotency_key: "coord-replay-release".to_owned(),
            reason: "fixture release".to_owned(),
        };
        let released = facade.release(&db.pool, &actor, release, deadline()).await?;
        ensure!(released.state() == "released", "root release state differs");
        let replay_after_release = facade.create(&db.pool, &actor, input.clone(), deadline()).await?;
        ensure!(
            replay_after_release.replayed() && replay_after_release.root_id() == root_id,
            "released-root exact replay differs"
        );
        let released_record = facade
            .metadata(&db.pool, &actor, read_input(&repository.owner, &repository.name, root_id), deadline())
            .await?
            .ok_or_else(|| anyhow::anyhow!("released root metadata missing"))?;
        ensure!(released_record.state() == "released", "metadata did not retain released root state");

        // Actual source-pin expiry has the same no-source replay property.
        let expiring = create_serving_snapshot(&db, &store, &actor, &repository, 8).await?;
        let expiring_input =
            create_input(&repository.owner, &repository.name, expiring.snapshot_id, "coord-expiry");
        let expiring_receipt = facade.create(&db.pool, &actor, expiring_input.clone(), deadline()).await?;
        wait_pin_expired(&db.pool, expiring.pin_id).await?;
        let expiring_view = facade
            .materialize(
                &db.pool,
                &actor,
                read_input(&repository.owner, &repository.name, expiring_receipt.root_id()),
                deadline(),
            )
            .await?;
        ensure!(expiring_view.refs() == expiring.read.refs(), "expired source root view changed refs");
        let expiring_replay = facade.create(&db.pool, &actor, expiring_input, deadline()).await?;
        ensure!(
            expiring_replay.replayed() && expiring_replay.root_id() == expiring_receipt.root_id(),
            "expired-source exact replay differs"
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
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "coord-changed-intent").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let input = create_input(&repository.owner, &repository.name, source.snapshot_id, "coord-changed");
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
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "coord-late-auth").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let baseline = root_counts(&db.pool, verified.repo).await?;

        // Restricted write-scope admin: preflight succeeds, then the scope is
        // revoked while native prepare is paused. Final auth must roll back the
        // already-staged root rows/receipt/charge.
        let late_scope =
            serving_actor_with_scopes(&db.pool, verified.repo, &["contents_write"], "coord-late-scope-").await?;
        grant_collaborator(&db.pool, verified.repo, verified.tenant, late_scope.id, "admin").await?;
        let gate = GitGate::new(&git)?;
        let release_guard = GateRelease(&gate);
        let gated = Arc::new(PgServingRetentionRoots::new(PgRetentionRoots::new(store.clone(), gate.binary())?));
        let input = create_input(&repository.owner, &repository.name, source.snapshot_id, "coord-late-scope");
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
        let release_guard = GateRelease(&gate);
        let gated = Arc::new(PgServingRetentionRoots::new(PgRetentionRoots::new(store.clone(), gate.binary())?));
        let input = create_input(&repository.owner, &repository.name, source.snapshot_id, "coord-role");
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
        let owner_input = create_input(&repository.owner, &repository.name, source.snapshot_id, "coord-read-scope");
        let owner_receipt = owner_facade.create(&db.pool, &actor, owner_input, deadline()).await?;
        let reader =
            serving_actor_with_scopes(&db.pool, verified.repo, &["contents_read"], "coord-late-read-").await?;
        grant_collaborator(&db.pool, verified.repo, verified.tenant, reader.id, "admin").await?;
        let gate = GitGate::new(&git)?;
        let release_guard = GateRelease(&gate);
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
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "coord-release-before").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let create_key = "coord-release-before";
        let root_id = root_id_for(verified.repo, create_key);
        let create = create_input(&repository.owner, &repository.name, source.snapshot_id, create_key);
        let release = ServingRootRelease {
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            target: ServingRootReleaseTarget::Absent {
                root_id,
                create: create.intent.clone(),
            },
            idempotency_key: "coord-release-before-key".to_owned(),
            reason: "release before delayed register".to_owned(),
        };

        let gate = GitGate::new(&git)?;
        let release_guard = GateRelease(&gate);
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
        ensure!(
            root_counts(&db.pool, verified.repo).await? == counts,
            "release exact replay charged or rewrote rows"
        );
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
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "coord-concurrent-replay").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let input = create_input(
            &repository.owner,
            &repository.name,
            source.snapshot_id,
            "coord-concurrent-replay",
        );

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
        let task = tokio::spawn(async move {
            paused_facade.create(&task_pool, &task_actor, task_input, deadline()).await
        });
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
        ensure!(
            root_counts(&db.pool, verified.repo).await? == counts,
            "concurrent exact replay rewrote root rows"
        );
        ensure!(
            repo_usage(&db.pool, verified.repo).await? == usage,
            "concurrent exact replay charged usage"
        );
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
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "coord-release-by-intent").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let facade = PgServingRetentionRoots::new(adapter(&store, &git)?);
        let create = create_input(&repository.owner, &repository.name, source.snapshot_id, "coord-by-intent");
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
        ensure!(released.state() == "released" && released.root_id() == receipt.root_id(), "by-intent existing release differs");
        let counts = root_counts(&db.pool, verified.repo).await?;
        let usage = repo_usage(&db.pool, verified.repo).await?;
        let replay = facade.release(&db.pool, &actor, release, deadline()).await?;
        ensure!(replay.replayed() && replay.state() == "released", "by-intent release replay differs");
        ensure!(root_counts(&db.pool, verified.repo).await? == counts, "by-intent release replay changed root rows");
        ensure!(repo_usage(&db.pool, verified.repo).await? == usage, "by-intent release replay charged usage");
        let record = facade
            .metadata(
                &db.pool,
                &actor,
                read_input(&repository.owner, &repository.name, receipt.root_id()),
                deadline(),
            )
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
        let create = create_input(
            &repository.owner,
            &repository.name,
            source.snapshot_id,
            "coord-intent-tombstone",
        );
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
        ensure!(
            root_counts(&db.pool, verified.repo).await? == counts,
            "pre-register release replay changed rows"
        );
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
        let create = create_input(
            &repository.owner,
            &repository.name,
            source.snapshot_id,
            "coord-intent-conflict",
        );
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
            .metadata(
                &db.pool,
                &actor,
                read_input(&repository.owner, &repository.name, receipt.root_id()),
                deadline(),
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("existing root disappeared after changed-intent release"))?;
        ensure!(record.is_active(), "changed by-intent release released the existing root");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
