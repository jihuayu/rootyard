//! Real PostgreSQL + real S3 + native Git integration tests for durable
//! retention roots (migration 144 / roots API).
//!
//! Every case is `#[ignore]`, hard-fails when PG/S3/Git configuration is
//! missing, creates a random schema through `db::migrate`, establishes its
//! source through the actual A3 protected upload / A4 verified commit / A5
//! pack-verified snapshot path, and only then drives the roots API. No fake
//! proof, capability factory or direct SQL capture insert is used. Root runs
//! these tests with `--ignored`; the target contains 11 runtime cases across
//! this file and the `cases_tail` / `cases_extra` support modules. No PASS is
//! claimed by this file itself.
#![allow(clippy::too_many_arguments)]

#[path = "retention_roots_support/cases_extra.rs"]
mod cases_extra;
#[path = "retention_roots_support/cases_tail.rs"]
mod cases_tail;
mod retention_roots_support;

use anyhow::{Result, anyhow, ensure};
use retention_roots_support::common::{adapter, assert_record_matches_source, missing_oid, one_verified, open_store};
use retention_roots_support::db::{Db, deadline, repo_usage, root_counts, tenant_usage, wait_pin_expired};
use retention_roots_support::git::{assert_pack_identity, git_binary, stock_git_accepts_view};
use retention_roots_support::pack::{create_snapshot, release_pin, verify_advance, verify_new};
use retention_roots_support::roots;
use rootyard::ref_store::GitObjectFormat;
use rootyard::ref_store::core::retention_root::{RootError, RootRef, RootSelector};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn durable_root_survives_source_pin_release_and_bytes_match_stock_git() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, source) = one_verified(&db, &store, &git).await?;
        let roots = adapter(&store, &git)?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let candidate = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            root_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        ensure!(candidate.pack_count() == source.read.pack_count(), "candidate omitted a source pack");
        ensure!(candidate.ref_count() == source.read.ref_count(), "candidate omitted a captured ref");
        let register_digest = candidate.register_digest().as_hex();
        let receipt = roots::register(&roots, &db.pool, candidate, Uuid::new_v4(), deadline()).await?;
        ensure!(
            receipt.state() == "active" && receipt.root_id() == root_id && receipt.generation() == 1,
            "register receipt differs"
        );
        ensure!(receipt.body()["pack_count"].as_i64() == Some(source.read.pack_count()), "receipt pack count differs");
        ensure!(
            receipt.body()["register_digest"].as_str() == Some(register_digest.as_str()),
            "receipt did not bind the candidate digest"
        );

        let reference = RootRef::new(verified.repo, root_id, 1)?;
        let record = roots
            .get(&db.pool, reference, deadline())
            .await?
            .ok_or_else(|| anyhow!("root metadata missing after register"))?;
        assert_record_matches_source(&record, &source.read)?;
        ensure!(record.register_digest_hex() == register_digest, "retained register digest differs");

        let released = release_pin(&db.pool, source.scope, source.pin_id).await?;
        ensure!(!released.replayed, "fresh source pin release replayed");
        let record = roots
            .get(&db.pool, reference, deadline())
            .await?
            .ok_or_else(|| anyhow!("root metadata vanished with its source pin"))?;
        assert_record_matches_source(&record, &source.read)?;

        let view = roots
            .materialize(
                &db.pool,
                roots::read_request(verified.repo, verified.tenant, &verified.gate, root_id)?,
                deadline(),
            )
            .await?;
        ensure!(view.root_id() == root_id && view.generation() == 1, "materialized root identity differs");
        ensure!(view.refs() == record.refs(), "materialized refs differ from retained refs");
        ensure!(view.binding_digest_hex() == record.binding_digest_hex(), "materialized binding differs");
        for expected in source.read.packs() {
            let actual = view
                .packs()
                .iter()
                .find(|pack| pack.pack_id() == expected.pack_id())
                .ok_or_else(|| anyhow!("view omitted a retained pack"))?;
            assert_pack_identity(expected, actual)?;
        }
        stock_git_accepts_view(&view, &verified.fixture, deadline()).await?;
        let body = verified
            .fixture
            .cat_file(view.head_oid_hex().ok_or_else(|| anyhow!("root HEAD is unexpectedly unborn"))?)
            .await?;
        ensure!(body.contains("fixture main"), "stock Git did not read the captured commit body");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn actual_clock_pin_expiry_keeps_active_root_readable_but_refuses_delayed_register() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let verified = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let source = create_snapshot(&db, &verified, 2).await?;
        let roots = adapter(&store, &git)?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let candidate = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            root_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        roots::register(&roots, &db.pool, candidate, Uuid::new_v4(), deadline()).await?;
        // A second sealed candidate is prepared while the pin is still live; it
        // must be refused once the actual database clock passes the expiry.
        let delayed_id = Uuid::new_v4();
        let delayed = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            delayed_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        wait_pin_expired(&db.pool, source.pin_id).await?;
        let view = roots
            .materialize(
                &db.pool,
                roots::read_request(verified.repo, verified.tenant, &verified.gate, root_id)?,
                deadline(),
            )
            .await?;
        ensure!(view.head_oid_hex() == Some(verified.commit_oid.as_str()), "expired-pin root read changed HEAD");
        let error = roots::register(&roots, &db.pool, delayed, Uuid::new_v4(), deadline())
            .await
            .expect_err("delayed register after actual expiry must be refused");
        let text = error.to_string().to_ascii_lowercase();
        ensure!(
            text.contains("expir") || text.contains("pin") || text.contains("lease"),
            "delayed register failed for an unrelated reason: {error}"
        );
        ensure!(
            roots.get(&db.pool, RootRef::new(verified.repo, delayed_id, 1)?, deadline()).await?.is_none(),
            "expired delayed candidate created a capture"
        );
        let counts = root_counts(&db.pool, verified.repo).await?;
        ensure!(
            counts.captures == 1 && counts.heads == 1 && counts.receipts == 1,
            "expired register partially wrote root rows"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn explicit_old_non_ref_oid_is_accepted_from_registered_pack_and_missing_oid_is_refused() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let mut verified = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let old_oid = verified.commit_oid.clone();
        verify_advance(&db, &store, &mut verified, 2, b"advanced root fixture\n").await?;
        let source = create_snapshot(&db, &verified, 300).await?;
        ensure!(source.read.packs().len() == 2, "advanced source did not retain both registered packs");
        ensure!(
            source.read.refs().iter().all(|reference| reference.oid_hex() != old_oid),
            "old commit is still referenced"
        );
        let roots = adapter(&store, &git)?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let candidate = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            root_id,
            Uuid::new_v4(),
            RootSelector::ObjectIds(vec![old_oid.clone()]),
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        ensure!(candidate.root_oids() == [old_oid.clone()], "explicit selector was not preserved");
        roots::register(&roots, &db.pool, candidate, Uuid::new_v4(), deadline()).await?;
        let view = roots
            .materialize(
                &db.pool,
                roots::read_request(verified.repo, verified.tenant, &verified.gate, root_id)?,
                deadline(),
            )
            .await?;
        ensure!(view.root_oids() == [old_oid.clone()], "materialized selector differs");
        ensure!(view.selector_kind().as_str() == "oids", "materialized selector kind is not oids");
        stock_git_accepts_view(&view, &verified.fixture, deadline()).await?;
        verified.fixture.cat_file(&old_oid).await?;

        let missing_id = Uuid::new_v4();
        let missing = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            missing_id,
            Uuid::new_v4(),
            RootSelector::ObjectIds(vec![missing_oid(verified.gate.object_format())]),
            Uuid::new_v4(),
            deadline(),
        )
        .await;
        ensure!(
            matches!(missing, Err(RootError::RootObjectMissing { .. }) | Err(RootError::RootClosureUnproven(_))),
            "missing object id was not refused natively: {missing:?}"
        );
        ensure!(
            roots.get(&db.pool, RootRef::new(verified.repo, missing_id, 1)?, deadline()).await?.is_none(),
            "missing object candidate created metadata"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn release_before_register_binds_exact_digest_and_root_id_is_never_reused() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, source) = one_verified(&db, &store, &git).await?;
        let roots = adapter(&store, &git)?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let candidate = roots::prepare(&roots, &db.pool, scope, &source, root_id, Uuid::new_v4(), RootSelector::Snapshot, Uuid::new_v4(), deadline()).await?;
        let expected = candidate.register_digest().as_hex();
        let release_request = Uuid::new_v4();
        let released = roots::release(&roots, &db.pool, scope, root_id, release_request, &expected, &roots::release_digest("before"), deadline()).await?;
        ensure!(released.state() == "released" && released.root_id() == root_id, "release-before-register receipt differs");
        ensure!(released.body()["released_before_register"].as_bool() == Some(true), "not recorded as release-before-register");
        let error = roots::register(&roots, &db.pool, candidate, Uuid::new_v4(), deadline()).await.expect_err("register after release-before-register must be refused");
        ensure!(matches!(error, RootError::RootReleased { repository_id, root_id: id, generation: 2 } if repository_id == verified.repo && id == root_id), "delayed register was not refused with the released tombstone: {error}");
        // A fresh prepare for the same id, with another operation/request, can
        // never reopen or ABA the root id.
        let again = roots::prepare(&roots, &db.pool, scope, &source, root_id, Uuid::new_v4(), RootSelector::Snapshot, Uuid::new_v4(), deadline()).await?;
        let error = roots::register(&roots, &db.pool, again, Uuid::new_v4(), deadline()).await.expect_err("a released root id must not be reusable");
        ensure!(matches!(error, RootError::RootReleased { .. }) || matches!(error, RootError::RootDigestConflict(_)), "root id reuse did not hit the released tombstone: {error}");
        ensure!(roots.get(&db.pool, RootRef::new(verified.repo, root_id, 1)?, deadline()).await?.is_none(), "released root id gained a capture");
        let counts = root_counts(&db.pool, verified.repo).await?;
        ensure!(counts.captures == 0 && counts.heads == 1 && counts.tombstones == 1 && counts.receipts == 1, "release-before-register wrote partial capture rows");
        let second = roots::release(&roots, &db.pool, scope, root_id, Uuid::new_v4(), &expected, &roots::release_digest("again"), deadline()).await.expect_err("released root id reopened");
        ensure!(matches!(second, RootError::RootReleased { .. }), "second release did not observe terminal state: {second}");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn exact_register_and_release_replay_is_free_and_changed_digest_conflicts() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, source) = one_verified(&db, &store, &git).await?;
        let roots = adapter(&store, &git)?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let prepare_request = Uuid::new_v4();
        let register_request = Uuid::new_v4();
        let candidate = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            root_id,
            operation,
            RootSelector::Snapshot,
            prepare_request,
            deadline(),
        )
        .await?;
        let first = roots::register(&roots, &db.pool, candidate, register_request, deadline()).await?;
        ensure!(!first.replayed() && first.state() == "active", "fresh register did not create an active root");
        let repo_before = repo_usage(&db.pool, verified.repo).await?;
        let tenant_before = tenant_usage(&db.pool, verified.tenant).await?;
        let counts_before = root_counts(&db.pool, verified.repo).await?;
        let replay_candidate = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            root_id,
            operation,
            RootSelector::Snapshot,
            prepare_request,
            deadline(),
        )
        .await?;
        let replay = roots::register(&roots, &db.pool, replay_candidate, register_request, deadline()).await?;
        ensure!(
            replay.replayed() && replay.root_id() == root_id && replay.request_digest() == first.request_digest(),
            "exact register replay returned a different receipt"
        );
        ensure!(
            repo_usage(&db.pool, verified.repo).await? == repo_before
                && tenant_usage(&db.pool, verified.tenant).await? == tenant_before,
            "register replay charged quota twice"
        );
        ensure!(root_counts(&db.pool, verified.repo).await? == counts_before, "register replay inserted rows");

        let other_id = Uuid::new_v4();
        let conflicting = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            other_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            prepare_request,
            deadline(),
        )
        .await?;
        let error = roots::register(&roots, &db.pool, conflicting, register_request, deadline())
            .await
            .expect_err("same request id with a different digest must conflict");
        ensure!(
            matches!(error, RootError::RootDigestConflict(_)),
            "changed register request digest did not conflict: {error}"
        );

        let release_id = Uuid::new_v4();
        let release_digest = roots::release_digest("replay");
        let release = roots::release(
            &roots,
            &db.pool,
            scope,
            root_id,
            release_id,
            &first_fingerprint(&first),
            &release_digest,
            deadline(),
        )
        .await?;
        ensure!(!release.replayed() && release.state() == "released", "fresh release did not release");
        let repo_after = repo_usage(&db.pool, verified.repo).await?;
        let tenant_after = tenant_usage(&db.pool, verified.tenant).await?;
        let counts_after = root_counts(&db.pool, verified.repo).await?;
        let replay = roots::release(
            &roots,
            &db.pool,
            scope,
            root_id,
            release_id,
            &first_fingerprint(&first),
            &release_digest,
            deadline(),
        )
        .await?;
        ensure!(
            replay.replayed() && replay.request_digest() == release.request_digest(),
            "exact release replay returned a different receipt"
        );
        ensure!(
            repo_usage(&db.pool, verified.repo).await? == repo_after
                && tenant_usage(&db.pool, verified.tenant).await? == tenant_after,
            "release replay charged quota twice"
        );
        ensure!(root_counts(&db.pool, verified.repo).await? == counts_after, "release replay inserted rows");
        let conflict = roots::release(
            &roots,
            &db.pool,
            scope,
            root_id,
            release_id,
            &first_fingerprint(&first),
            &roots::release_digest("different"),
            deadline(),
        )
        .await
        .expect_err("same release request id with a different digest must conflict");
        ensure!(
            matches!(conflict, RootError::RootDigestConflict(_)),
            "changed release request digest did not conflict: {conflict}"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

fn first_fingerprint(receipt: &rootyard::ref_store::core::retention_root::RootReceipt) -> String {
    receipt.body()["register_digest"].as_str().unwrap_or_default().to_owned()
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn whole_repository_delete_retains_root_metadata_locators_receipts_and_refuses_new_bytes() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, source) = one_verified(&db, &store, &git).await?;
        let roots = adapter(&store, &git)?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let register_request = Uuid::new_v4();
        let candidate = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            root_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        roots::register(&roots, &db.pool, candidate, register_request, deadline()).await?;
        let reference = RootRef::new(verified.repo, root_id, 1)?;
        let before =
            roots.get(&db.pool, reference, deadline()).await?.ok_or_else(|| anyhow!("root missing before delete"))?;
        let counts_before = root_counts(&db.pool, verified.repo).await?;
        let query = roots::receipt_query(scope, register_request)?;
        let receipt_before = roots
            .query_receipt(&db.pool, query, deadline())
            .await?
            .ok_or_else(|| anyhow!("register receipt missing before delete"))?;

        db.pool.get().await?.execute("DELETE FROM repositories WHERE id=$1", &[&verified.repo]).await?;
        let after = roots
            .get(&db.pool, reference, deadline())
            .await?
            .ok_or_else(|| anyhow!("whole-repo delete removed root metadata"))?;
        assert_record_matches_source(&after, &source.read)?;
        ensure!(
            after.refs() == before.refs() && after.root_oids() == before.root_oids(),
            "delete changed retained refs/oids"
        );
        for expected in before.packs() {
            let actual = after
                .packs()
                .iter()
                .find(|pack| pack.pack_id() == expected.pack_id())
                .ok_or_else(|| anyhow!("delete removed a full pack locator"))?;
            assert_pack_identity(expected, actual)?;
        }
        ensure!(root_counts(&db.pool, verified.repo).await? == counts_before, "delete removed retained root rows");
        let receipt_after = roots
            .query_receipt(&db.pool, query, deadline())
            .await?
            .ok_or_else(|| anyhow!("delete removed root receipt"))?;
        ensure!(
            receipt_after.root_id() == receipt_before.root_id()
                && receipt_after.request_digest() == receipt_before.request_digest(),
            "retained receipt differs after delete"
        );
        let error = roots
            .materialize(
                &db.pool,
                roots::read_request(verified.repo, verified.tenant, &verified.gate, root_id)?,
                deadline(),
            )
            .await
            .expect_err("deleted repository must not grant new root bytes");
        ensure!(
            matches!(error, RootError::RootAuthorityRequired(_)),
            "deleted repository byte read failed for the wrong reason: {error}"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
