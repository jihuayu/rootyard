use anyhow::{Context, Result, anyhow, ensure};

use crate::blob_git_gateway::repo_session::{BEHIND_MESSAGE, TEST_MAX_TOKEN_LEN};

use super::fixtures::{actor, db::Db};
use super::support::{
    self, COMMIT_FILE, Gateway, contains, corrupt_registered_pack, delete_registered_idx, ensure_no_disclosure,
    is_denial, load_keyring_stage, looks_like_refs, raw_get, status_succeeds,
};

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob storage and native Git"]
async fn corrupt_pack_bytes_and_missing_idx_fail_closed_with_and_without_session() -> Result<()> {
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    let db = Db::setup().await?;
    let outcome = corrupt_and_missing_idx_case(&db).await;
    db.finish(outcome).await
}

async fn corrupt_and_missing_idx_case(db: &Db) -> Result<()> {
    let store = support::open_store()?;
    let (_keyring_dir, tokens) = support::keyring_tokens(store.backend_identity())?;
    let gateway = Gateway::start(db, store, tokens).await?;
    let owner = actor::owner(&db.pool).await?;
    let client = reqwest::Client::new();

    let name_corrupt = support::unique_name("corrupt-pack");
    gateway.create_repository(&owner, &name_corrupt).await?;
    gateway.provision_decision_realm(db, &owner, &name_corrupt).await?;
    gateway.push_commit(&owner, &name_corrupt).await?;
    let corrupt_session = gateway.push_session().admit()?;
    corrupt_registered_pack(&gateway, db, &owner, &name_corrupt).await?;

    let corrupt_base = gateway.base(&owner.username, &name_corrupt);
    let corrupt_secrets = [owner.token.as_str(), corrupt_session.token.as_str()];
    for session in [Some(corrupt_session.token.as_str()), None] {
        for suffix in ["/refs", "/tree?oid=HEAD"] {
            let answer = raw_get(&client, &format!("{corrupt_base}{suffix}"), &owner.token, session).await?;
            ensure!(
                !status_succeeds(answer.status) && answer.status >= 500,
                "corrupted pack read {suffix} returned unexpected status {}",
                answer.status
            );
            ensure!(
                answer.session.token.is_none() && answer.session.revision.is_none(),
                "corrupted pack failure emitted session headers"
            );
            ensure!(!looks_like_refs(&answer.body), "corrupted pack failure leaked repository contents");
            ensure_no_disclosure(&answer.body, &corrupt_secrets, "corrupted pack failure")?;
        }
    }

    let name_idx = support::unique_name("missing-idx");
    gateway.create_repository(&owner, &name_idx).await?;
    gateway.provision_decision_realm(db, &owner, &name_idx).await?;
    gateway.push_commit(&owner, &name_idx).await?;
    let idx_session = gateway.push_session().admit()?;
    delete_registered_idx(&gateway, db, &owner, &name_idx).await?;

    let idx_base = gateway.base(&owner.username, &name_idx);
    let idx_secrets = [owner.token.as_str(), idx_session.token.as_str()];
    for session in [Some(idx_session.token.as_str()), None] {
        for suffix in ["/refs", "/tree?oid=HEAD"] {
            let answer = raw_get(&client, &format!("{idx_base}{suffix}"), &owner.token, session).await?;
            ensure!(
                !status_succeeds(answer.status) && answer.status >= 500,
                "missing idx read {suffix} returned unexpected status {}",
                answer.status
            );
            ensure!(
                answer.session.token.is_none() && answer.session.revision.is_none(),
                "missing idx failure emitted session headers"
            );
            ensure!(!looks_like_refs(&answer.body), "missing idx failure leaked repository contents");
            ensure_no_disclosure(&answer.body, &idx_secrets, "missing idx failure")?;
        }
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob storage and native Git"]
async fn behind_bound_recovers_after_second_push_and_serves_historical_oid_reads() -> Result<()> {
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    let db = Db::setup().await?;
    let outcome = recovery_case(&db).await;
    db.finish(outcome).await
}

async fn recovery_case(db: &Db) -> Result<()> {
    let store = support::open_store()?;
    let (_keyring_dir, tokens) = support::keyring_tokens(store.backend_identity())?;
    let gateway = Gateway::start(db, store, tokens).await?;
    let owner = actor::owner(&db.pool).await?;
    let name = support::unique_name("behind-recover");
    gateway.create_repository(&owner, &name).await?;
    gateway.provision_decision_realm(db, &owner, &name).await?;

    let (_work, checkout) = gateway.clone_checkout(&owner, &name).await?;
    let oid1 = gateway.commit_and_push(&checkout, COMMIT_FILE, "first commit payload\n", "first commit").await?;
    let live1 = support::live_realm(db, &gateway, &owner, &name, false).await?;
    let future_rev = live1.revision.checked_add(1).context("live gate revision overflow")?;
    let future = gateway
        .tokens
        .issue_for_test(&live1.realm, future_rev)
        .map_err(|_| anyhow!("future-bound session issue refused"))?;

    let client = reqwest::Client::new();
    let base = gateway.base(&owner.username, &name);
    let secrets = [owner.token.as_str(), future.token()];

    let behind = raw_get(&client, &format!("{base}/tree?oid=HEAD"), &owner.token, Some(future.token())).await?;
    ensure!(behind.status == 503, "behind bound expected 503, got {}", behind.status);
    ensure!(contains(&behind.body, BEHIND_MESSAGE), "503 missing BEHIND_MESSAGE");
    ensure!(
        behind.session.token.is_none() && behind.session.revision.is_none(),
        "503 refusal must not emit session headers"
    );
    ensure!(!contains(&behind.body, COMMIT_FILE), "503 refusal disclosed tree contents");
    ensure_no_disclosure(&behind.body, &secrets, "behind 503 refusal")?;

    let oid2 = gateway.commit_and_push(&checkout, "second.txt", "second commit payload\n", "second commit").await?;

    let recovered = raw_get(&client, &format!("{base}/tree?oid=HEAD"), &owner.token, Some(future.token())).await?;
    ensure!(recovered.status == 200, "retry after push expected 200, got {}", recovered.status);
    ensure!(contains(&recovered.body, "second.txt"), "recovered HEAD tree did not show second push");
    let b2 = recovered.session.admit()?;
    ensure!(b2.revision >= future_rev, "recovered revision stayed behind presented lower bound");

    let commit_old = raw_get(&client, &format!("{base}/commits/{oid1}"), &owner.token, Some(&b2.token)).await?;
    ensure!(commit_old.status == 200 && contains(&commit_old.body, &oid1), "historical commit {oid1} read failed");
    let b3 = commit_old.session.admit_at_least(&b2)?;

    let tree_old = raw_get(&client, &format!("{base}/tree/{oid1}"), &owner.token, Some(&b3.token)).await?;
    ensure!(
        tree_old.status == 200 && contains(&tree_old.body, COMMIT_FILE) && !contains(&tree_old.body, "second.txt"),
        "historical tree {oid1} read leaked later commit contents"
    );
    let b4 = tree_old.session.admit_at_least(&b3)?;

    let blob_old =
        raw_get(&client, &format!("{base}/blob/{oid1}?path={COMMIT_FILE}"), &owner.token, Some(&b4.token)).await?;
    ensure!(
        blob_old.status == 200 && contains(&blob_old.body, "first commit payload"),
        "historical blob {oid1} read failed"
    );
    let b5 = blob_old.session.admit_at_least(&b4)?;

    let compare =
        raw_get(&client, &format!("{base}/compare?base={oid1}&head={oid2}"), &owner.token, Some(&b5.token)).await?;
    ensure!(
        compare.status == 200 && contains(&compare.body, &oid1) && contains(&compare.body, &oid2),
        "historical compare {oid1}..{oid2} failed"
    );
    let _b6 = compare.session.admit_at_least(&b5)?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob storage and native Git"]
async fn keyring_rotation_accepts_previous_key_during_overlap_and_rejects_after_retirement() -> Result<()> {
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    let db = Db::setup().await?;
    let outcome = keyring_rotation_case(&db).await;
    db.finish(outcome).await
}

async fn keyring_rotation_case(db: &Db) -> Result<()> {
    let store = support::open_store()?;
    let owner = actor::owner(&db.pool).await?;
    let name = support::unique_name("keyring-rotate");
    let client = reqwest::Client::new();

    let (_dir1, tokens_v1) = load_keyring_stage(store.backend_identity(), true, false, "v1")?;
    let gw1 = Gateway::start(db, store.clone(), tokens_v1).await?;
    gw1.create_repository(&owner, &name).await?;
    gw1.provision_decision_realm(db, &owner, &name).await?;
    gw1.push_commit(&owner, &name).await?;
    let base1 = gw1.base(&owner.username, &name);
    let r1 = raw_get(&client, &format!("{base1}/refs"), &owner.token, None).await?;
    ensure!(status_succeeds(r1.status) && looks_like_refs(&r1.body), "v1 refs failed");
    let b1 = r1.session.admit()?;
    drop(gw1);

    let (_dir2, tokens_overlap) = load_keyring_stage(store.backend_identity(), true, true, "v2")?;
    let gw2 = Gateway::start(db, store.clone(), tokens_overlap).await?;
    let base2 = gw2.base(&owner.username, &name);
    let r2 = raw_get(&client, &format!("{base2}/refs"), &owner.token, Some(&b1.token)).await?;
    ensure!(status_succeeds(r2.status) && looks_like_refs(&r2.body), "overlap keyring rejected v1 token");
    let b2 = r2.session.admit_at_least(&b1)?;
    drop(gw2);

    let (_dir3, tokens_retired) = load_keyring_stage(store.backend_identity(), false, true, "v2")?;
    let gw3 = Gateway::start(db, store, tokens_retired).await?;
    let base3 = gw3.base(&owner.username, &name);

    let retired = raw_get(&client, &format!("{base3}/refs"), &owner.token, Some(&b1.token)).await?;
    ensure!(retired.status == 400, "retired v1 token expected 400, got {}", retired.status);
    ensure!(
        retired.session.token.is_none() && retired.session.revision.is_none(),
        "retired v1 refusal emitted session headers"
    );
    ensure!(!looks_like_refs(&retired.body), "retired v1 refusal leaked refs");
    ensure_no_disclosure(&retired.body, &[&owner.token, &b1.token, &b2.token], "retired key refusal")?;

    let valid = raw_get(&client, &format!("{base3}/refs"), &owner.token, Some(&b2.token)).await?;
    ensure!(status_succeeds(valid.status) && looks_like_refs(&valid.body), "active v2 token failed after retirement");
    let b3 = valid.session.admit_at_least(&b2)?;
    ensure!(b3.revision >= b2.revision, "v2 read regressed across key retirement");

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob storage and native Git"]
async fn restore_cluster_incarnation_rotation_and_oversized_session_header_fail_closed() -> Result<()> {
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    let db = Db::setup().await?;
    let outcome = restore_and_oversized_case(&db).await;
    db.finish(outcome).await
}

async fn restore_and_oversized_case(db: &Db) -> Result<()> {
    let store = support::open_store()?;
    let (_keyring_dir, tokens) = support::keyring_tokens(store.backend_identity())?;
    let gateway = Gateway::start(db, store, tokens).await?;
    let owner = actor::owner(&db.pool).await?;
    let stranger = actor::stranger(&db.pool).await?;
    let name = support::unique_name("restore-incarn");
    gateway.create_repository(&owner, &name).await?;
    gateway.provision_decision_realm(db, &owner, &name).await?;

    let (_work, checkout) = gateway.clone_checkout(&owner, &name).await?;
    let _oid1 = gateway.commit_and_push(&checkout, COMMIT_FILE, "pre-restore\n", "pre-restore").await?;
    let pre_restore = gateway.push_session().admit()?;

    let client = reqwest::Client::new();
    let base = gateway.base(&owner.username, &name);
    let oversized = "a".repeat(TEST_MAX_TOKEN_LEN + 1);
    let secrets = [owner.token.as_str(), stranger.token.as_str(), pre_restore.token.as_str(), oversized.as_str()];

    let owner_oversized = raw_get(&client, &format!("{base}/refs"), &owner.token, Some(&oversized)).await?;
    ensure!(owner_oversized.status == 400, "oversized header expected 400, got {}", owner_oversized.status);
    ensure!(
        owner_oversized.session.token.is_none() && owner_oversized.session.revision.is_none(),
        "oversized header emitted session headers"
    );
    ensure!(!looks_like_refs(&owner_oversized.body), "oversized header leaked refs");
    ensure_no_disclosure(&owner_oversized.body, &secrets, "oversized header refusal")?;

    let stranger_plain = raw_get(&client, &format!("{base}/refs"), &stranger.token, None).await?;
    let stranger_oversized = raw_get(&client, &format!("{base}/refs"), &stranger.token, Some(&oversized)).await?;
    ensure!(is_denial(stranger_plain.status), "stranger must be denied");
    ensure!(
        stranger_oversized.status == stranger_plain.status,
        "oversized header changed unauthorized stranger status"
    );
    ensure!(stranger_oversized.session.token.is_none(), "stranger refusal emitted session header");
    ensure_no_disclosure(&stranger_oversized.body, &secrets, "stranger oversized denial")?;

    db.pool
        .get()
        .await?
        .execute(
            "UPDATE cluster_authority SET incarnation = gen_random_uuid(), rotated_at = clock_timestamp() WHERE singleton = true",
            &[],
        )
        .await?;

    let rotated = raw_get(&client, &format!("{base}/refs"), &owner.token, Some(&pre_restore.token)).await?;
    ensure!(rotated.status == 400, "post-restore pre-rotation token expected 400, got {}", rotated.status);
    ensure!(
        contains(&rotated.body, "authority generation"),
        "post-restore refusal did not explain authority generation change"
    );
    ensure!(
        rotated.session.token.is_none() && rotated.session.revision.is_none(),
        "post-restore refusal emitted session headers"
    );
    ensure!(!looks_like_refs(&rotated.body), "post-restore refusal leaked refs");
    ensure_no_disclosure(&rotated.body, &secrets, "post-restore refusal")?;

    gateway.commit_and_push(&checkout, "post-restore.txt", "post-restore\n", "post-restore").await?;
    let still_stale = raw_get(&client, &format!("{base}/refs"), &owner.token, Some(&pre_restore.token)).await?;
    ensure!(still_stale.status == 400, "pre-restore token remained valid after revision advance");
    ensure!(
        still_stale.session.token.is_none() && still_stale.session.revision.is_none(),
        "post-restore post-push refusal emitted session headers"
    );
    ensure!(!looks_like_refs(&still_stale.body), "post-restore post-push refusal leaked refs");
    ensure_no_disclosure(&still_stale.body, &secrets, "post-restore post-push refusal")?;

    let fresh = raw_get(&client, &format!("{base}/refs"), &owner.token, None).await?;
    ensure!(status_succeeds(fresh.status) && looks_like_refs(&fresh.body), "fresh read after restore failed");
    let fresh_bound = fresh.session.admit()?;
    ensure!(fresh_bound.revision > pre_restore.revision, "fresh post-restore bound did not advance");

    Ok(())
}
