//! Native-only HTTP regression for the exact commit-preview cache consumer.
//!
//! Every case drives the production Axum router over loopback TCP using the
//! same owned Pg17/Garage/trusted-Git support as the `#174` session suite. The
//! cache is the real `ServingCache::standalone_memory()` attached exactly as
//! the standalone target attaches it. No handler is called directly and no
//! authority, ref, pack or session fact is fabricated.
//!
//! These cases seed `public.cluster_authority` outside the random per-test
//! schema, and the restore case rotates that global row while a request is
//! paused. `Db::finish` drops only the random schema, never the whole database.
//! Each case therefore requires both ownership markers before `Db::setup`:
//!
//! * `ROOTYARD_TEST_OWNED_DISPOSABLE_POSTGRES=1` attests one dedicated whole
//!   database that the caller disposes after the suite, never a shared schema;
//! * `ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB=1` attests the configured Blob
//!   bucket/namespace is wholly owned and disposed after the run.
//!
//! A missing marker is a hard ownership refusal, not a skip. The restore case's
//! rotation is safe only because that dedicated database is discarded whole.
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};

use super::super::{read_session::AUTHORITY_CHANGED, state::ReadPause};
use super::{
    fixtures::{
        actor::{self, Actor},
        db::Db,
        git::assert_no_compute_views,
    },
    support::{
        COMMIT_FILE, Gateway, PUSHED_REF, add_read_collaborator, contains, ensure_no_disclosure, is_denial, open_store,
        raw_get, remove_collaborator, serving, status_succeeds, test_tokens, unique_name,
    },
};
use crate::cache_wake::ServingCache;

const OWNED_POSTGRES_OPT_IN: &str = "ROOTYARD_TEST_OWNED_DISPOSABLE_POSTGRES";
const OWNED_BLOB_OPT_IN: &str = "ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB";

/// Attest that the caller owns one whole disposable database and Blob prefix.
///
/// `Db::setup` seeds `public.cluster_authority` outside its random schema and
/// `Db::finish` drops only that schema. The PostgreSQL marker is therefore an
/// ownership assertion, never a shared-schema claim.
fn require_owned_disposable_fixture() -> Result<()> {
    let postgres = matches!(std::env::var(OWNED_POSTGRES_OPT_IN).as_deref(), Ok("1"));
    let blob = matches!(std::env::var(OWNED_BLOB_OPT_IN).as_deref(), Ok("1"));
    ensure!(
        postgres && blob,
        "this real cache fixture requires {OWNED_POSTGRES_OPT_IN}=1 and {OWNED_BLOB_OPT_IN}=1: the PostgreSQL target must be one dedicated whole database disposed after the suite (never a shared schema, even if the URL is valid), and the Blob bucket/namespace must be wholly owned and disposed after the run"
    );
    Ok(())
}

/// A fresh production router with the explicit standalone memory cache.
async fn cache_gateway(db: &Db, read_pause: Option<Arc<ReadPause>>) -> Result<Gateway> {
    let store = open_store()?;
    let tokens = test_tokens(store.backend_identity())?;
    let cache = Arc::new(ServingCache::standalone_memory().map_err(|_| anyhow!("standalone memory cache refused"))?);
    Gateway::start_with_cache(db, store, tokens, cache, read_pause).await
}

/// One fresh repository pushed through the real Smart HTTP route.
async fn pushed(gateway: &Gateway, db: &Db, label: &str) -> Result<(Actor, String, String)> {
    let owner = actor::owner(&db.pool).await?;
    let name = unique_name(label);
    gateway.create_repository(&owner, &name).await?;
    gateway.provision_decision_realm(db, &owner, &name).await?;
    let oid = gateway.push_commit(&owner, &name).await?;
    Ok((owner, name, oid))
}

fn commit_url(gateway: &Gateway, owner: &Actor, name: &str, oid: &str) -> String {
    format!("{}/commits/{oid}", gateway.base(&owner.username, name))
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and native Git"]
async fn exact_commit_http_warm_miss_then_actual_hit_is_byte_equal() -> Result<()> {
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    require_owned_disposable_fixture()?;
    let db = Db::setup().await?;
    let outcome = async {
        let gateway = cache_gateway(&db, None).await?;
        let (owner, name, oid) = pushed(&gateway, &db, "commit-cache-hit").await?;
        let client = reqwest::Client::new();
        let url = commit_url(&gateway, &owner, &name, &oid);

        let first = raw_get(&client, &url, &owner.token, None).await?;
        ensure!(first.status == 200, "warm exact-OID GET returned {}", first.status);
        ensure!(contains(&first.body, &oid), "warm body did not name the exact commit");
        let miss = gateway.cache_stats().ok_or_else(|| anyhow!("cache stats are absent"))?;
        ensure!(miss.hits == 0 && miss.misses == 1, "warm request was not exactly one cache miss: {miss:?}");

        let second = raw_get(&client, &url, &owner.token, None).await?;
        ensure!(second.status == 200, "second exact-OID GET returned {}", second.status);
        ensure!(
            first.body.as_bytes() == second.body.as_bytes(),
            "cache-hit JSON body differed byte-for-byte from the warm origin body"
        );
        second.session.admit().context("cache hit did not run the sealed session-proof path")?;
        let hit = gateway.cache_stats().ok_or_else(|| anyhow!("cache stats are absent"))?;
        ensure!(hit.hits == 1 && hit.misses == 1, "second request was not exactly one cache hit: {hit:?}");
        ensure!(hit.backend_errors == 0, "cache backend errored during the hit proof");
        ensure!(hit.corrupt_values == 0, "cache served or repaired a corrupt value during the hit proof");
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and native Git"]
async fn exact_commit_http_hit_still_enforces_final_live_authorization() -> Result<()> {
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    require_owned_disposable_fixture()?;
    let db = Db::setup().await?;
    let outcome = async {
        let pause = Arc::new(ReadPause::new());
        let gateway = cache_gateway(&db, Some(pause.clone())).await?;
        let (owner, name, oid) = pushed(&gateway, &db, "commit-cache-auth").await?;
        let collaborator = actor::stranger(&db.pool).await?;
        let repo = serving(&db, &gateway, &owner, &name, false).await?;
        add_read_collaborator(&db, repo.gate.repository_id(), repo.gate.tenant_id(), collaborator.identity.id).await?;

        let client = reqwest::Client::new();
        let url = commit_url(&gateway, &owner, &name, &oid);
        let warm = raw_get(&client, &url, &collaborator.token, None).await?;
        ensure!(warm.status == 200, "warm collaborator GET returned {}", warm.status);
        let before = gateway.cache_stats().ok_or_else(|| anyhow!("cache stats are absent"))?;

        pause.target(oid.clone());
        let task = {
            let client = client.clone();
            let url = url.clone();
            let token = collaborator.token.clone();
            tokio::spawn(async move { raw_get(&client, &url, &token, None).await })
        };
        pause.wait_reached().await;

        // The request already passed open-time authorization and cache lookup.
        // Revoke the live grant only now, before finalize's encoded-response
        // revalidation, so this is a last-mile authorization fence, not a
        // pre-lookup refusal.
        remove_collaborator(&db, repo.gate.repository_id(), collaborator.identity.id).await?;
        pause.release();

        let denied = task.await.context("paused cache-hit request task")??;
        ensure!(!status_succeeds(denied.status), "a revoked cache-hit grant still returned a success status");
        ensure!(is_denial(denied.status), "cache-hit final authorization refusal status was {}", denied.status);
        ensure_no_disclosure(&denied.body, &[oid.as_str(), PUSHED_REF], "cache-hit final authorization refusal")?;
        ensure!(
            denied.session.token.is_none() && denied.session.revision.is_none(),
            "cache-hit final authorization refusal emitted session headers"
        );
        let after = gateway.cache_stats().ok_or_else(|| anyhow!("cache stats are absent"))?;
        ensure!(after.hits == before.hits + 1, "the final-auth request did not hit the cache before refusal");
        ensure!(after.misses == before.misses, "the final-auth request went back to origin instead of hitting");
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and native Git"]
async fn exact_commit_http_hit_still_enforces_restore_incarnation_fence() -> Result<()> {
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    require_owned_disposable_fixture()?;
    let db = Db::setup().await?;
    let outcome = async {
        let pause = Arc::new(ReadPause::new());
        let gateway = cache_gateway(&db, Some(pause.clone())).await?;
        let (owner, name, oid) = pushed(&gateway, &db, "commit-cache-restore").await?;
        let client = reqwest::Client::new();
        let url = commit_url(&gateway, &owner, &name, &oid);

        let warm = raw_get(&client, &url, &owner.token, None).await?;
        ensure!(warm.status == 200, "warm owner GET returned {}", warm.status);
        let before = gateway.cache_stats().ok_or_else(|| anyhow!("cache stats are absent"))?;

        pause.target(oid.clone());
        let task = {
            let client = client.clone();
            let url = url.clone();
            let token = owner.token.clone();
            tokio::spawn(async move { raw_get(&client, &url, &token, None).await })
        };
        pause.wait_reached().await;

        // Rotate the cluster restore incarnation only after the request passed
        // open-time capture and hit the immutable payload. Finalize's live
        // lookup reads the rotated non-nil anchor and must refuse unconditionally.
        let rotated: uuid::Uuid = db
            .pool
            .get()
            .await?
            .query_one(
                "UPDATE public.cluster_authority SET incarnation = gen_random_uuid(), rotated_at = clock_timestamp() \
                 WHERE singleton = true RETURNING incarnation",
                &[],
            )
            .await?
            .get(0);
        ensure!(!rotated.is_nil(), "rotated public.cluster_authority incarnation must not be nil");
        pause.release();

        let denied = task.await.context("paused cache-hit restore request task")??;
        ensure!(denied.status == 503, "cache-hit restore fence expected 503, got {}", denied.status);
        ensure!(contains(&denied.body, AUTHORITY_CHANGED), "cache-hit restore refusal did not name the anchor change");
        ensure_no_disclosure(&denied.body, &[oid.as_str(), PUSHED_REF], "cache-hit restore refusal")?;
        ensure!(
            denied.session.token.is_none() && denied.session.revision.is_none(),
            "cache-hit restore refusal emitted session headers"
        );
        let after = gateway.cache_stats().ok_or_else(|| anyhow!("cache stats are absent"))?;
        ensure!(after.hits == before.hits + 1, "the restore-fence request did not hit the cache before refusal");
        ensure!(after.misses == before.misses, "the restore-fence request went back to origin instead of hitting");
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and native Git"]
async fn exact_commit_http_cached_oid_is_not_served_after_it_becomes_unreachable() -> Result<()> {
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    require_owned_disposable_fixture()?;
    let db = Db::setup().await?;
    let outcome = async {
        let gateway = cache_gateway(&db, None).await?;
        let owner = actor::owner(&db.pool).await?;
        let name = unique_name("commit-cache-unreachable");
        gateway.create_repository(&owner, &name).await?;
        gateway.provision_decision_realm(&db, &owner, &name).await?;
        let (_work, checkout) = gateway.clone_checkout(&owner, &name).await?;
        let oid = gateway.commit_and_push(&checkout, COMMIT_FILE, "cached origin body\n", "cached origin").await?;

        let client = reqwest::Client::new();
        let old_url = commit_url(&gateway, &owner, &name, &oid);
        let warm = raw_get(&client, &old_url, &owner.token, None).await?;
        ensure!(warm.status == 200, "warm exact-OID GET returned {}", warm.status);
        ensure!(contains(&warm.body, &oid), "warm body did not name the exact commit");
        let before = gateway.cache_stats().ok_or_else(|| anyhow!("cache stats are absent"))?;
        ensure!(before.hits == 0 && before.misses == 1, "warm request was not one miss: {before:?}");

        // Replace main with an unrelated root commit. The old commit is no
        // longer in the captured refs closure even though its payload is cached.
        //
        // This fixture creates no `forge_branch_rules` row, so the real
        // publication policy accepts the forced root. A separate later
        // checkpoint should inject an explicit protected-branch rule through
        // the existing gates and prove `ForcePushDenied`; it must not be
        // emulated here.
        gateway.git.ok(&checkout, &["checkout", "--orphan", "unrelated"]).await?;
        let _ = gateway.git.run(&checkout, &["rm", "-rf", "--ignore-unmatch", "."]).await?;
        let new_oid = gateway.git.commit(&checkout, "orphan.txt", "orphan root\n", "orphan root").await?;
        ensure!(new_oid != oid, "orphan root unexpectedly reused the cached OID");
        let pushed = gateway.git.run(&checkout, &["push", "--force", "origin", &format!("HEAD:{PUSHED_REF}")]).await?;
        ensure!(pushed.success, "force push of the unrelated root was refused");
        assert_no_compute_views(gateway.scratch.path()).await?;

        let denied = raw_get(&client, &old_url, &owner.token, None).await?;
        ensure!(denied.status == 404, "unreachable exact OID expected 404, got {}", denied.status);
        ensure_no_disclosure(&denied.body, &[oid.as_str(), PUSHED_REF], "unreachable commit refusal")?;
        let after = gateway.cache_stats().ok_or_else(|| anyhow!("cache stats are absent"))?;
        ensure!(
            after.hits == before.hits && after.misses == before.misses,
            "unreachable old OID consulted the cache before the live reachable-closure proof"
        );

        let fresh = raw_get(&client, &commit_url(&gateway, &owner, &name, &new_oid), &owner.token, None).await?;
        ensure!(fresh.status == 200, "new orphan tip exact-OID GET returned {}", fresh.status);
        ensure!(contains(&fresh.body, &new_oid), "new orphan tip body did not name the new exact commit");
        Ok(())
    }
    .await;
    db.finish(outcome).await
}
