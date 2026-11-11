//! Real-HTTP negative and production-keyring acceptance for `#174`.
//!
//! Every case drives the production router over loopback TCP: no handler is
//! called directly and no refusal is fabricated. The shared fixtures are in
//! [`super::support`]; the main push/read/monotonic case is in the parent.
use anyhow::{Result, ensure};

use super::{
    fixtures::{
        actor::{self, Actor},
        db::Db,
    },
    support::{
        BOUNDED_LIFETIME, COMMIT_FILE, Gateway, PUSHED_REF, add_read_collaborator, contains, delete_registered_pack,
        ensure_no_disclosure, flip_mac, json_read, keyring_tokens, live_realm, looks_like_refs, open_store, raw_get,
        remove_collaborator, serving, status_succeeds, test_tokens, unique_name, unix_now,
    },
};

/// One fresh schema, gateway, owner and really pushed repository.
async fn pushed(db: &Db, label: &str) -> Result<(Gateway, Actor, String, String)> {
    let store = open_store()?;
    let tokens = test_tokens(store.backend_identity())?;
    let gateway = Gateway::start(db, store, tokens).await?;
    let owner = actor::owner(&db.pool).await?;
    let name = unique_name(label);
    gateway.create_repository(&owner, &name).await?;
    gateway.provision_decision_realm(db, &owner, &name).await?;
    let oid = gateway.push_commit(&owner, &name).await?;
    Ok((gateway, owner, name, oid))
}

/// One valid, unexpired session token obtained through a real HTTP read.
///
/// `actor` authenticates and is issued the token; `repo_owner` is the personal
/// namespace the repository actually lives in, which may be another actor (a
/// repository collaborator).
async fn issued_token(
    gateway: &Gateway,
    client: &reqwest::Client,
    actor: &Actor,
    repo_owner: &str,
    name: &str,
) -> Result<String> {
    let answer = json_read(client, &format!("{}/refs", gateway.base(repo_owner, name)), &actor.token, None).await?;
    Ok(answer.session.admit()?.token)
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn cross_repository_session_replay_is_refused() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = async {
        let (gateway, owner, name_a, oid_a) = pushed(&db, "replay-repo").await?;
        let client = reqwest::Client::new();
        let token = issued_token(&gateway, &client, &owner, &owner.username, &name_a).await?;

        // A second repository of the same tenant exists and is authorized for
        // the same owner, so only the signed repository binding can refuse it.
        let name_b = unique_name("replay-target");
        gateway.create_repository(&owner, &name_b).await?;
        gateway.provision_decision_realm(&db, &owner, &name_b).await?;
        let denied =
            raw_get(&client, &format!("{}/refs", gateway.base(&owner.username, &name_b)), &owner.token, Some(&token))
                .await?;
        ensure!(denied.status == 400, "a same-tenant cross-repository token was not refused with 400");
        ensure!(!status_succeeds(denied.status), "a same-tenant cross-repository token succeeded");
        ensure!(denied.session.token.is_none(), "a refused cross-repository read emitted a session");
        ensure!(!looks_like_refs(&denied.body), "a cross-repository refusal looked like a refs answer");
        ensure_no_disclosure(&denied.body, &[oid_a.as_str(), PUSHED_REF], "cross-repository replay")?;
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn cross_tenant_session_replay_is_refused() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = async {
        let (gateway, owner_a, name_a, oid_a) = pushed(&db, "replay-tenant-a").await?;
        let client = reqwest::Client::new();
        let token = issued_token(&gateway, &client, &owner_a, &owner_a.username, &name_a).await?;

        // Tenant B's authorized owner creates and authorizes its own repository.
        let owner_b = actor::owner(&db.pool).await?;
        let name_b = unique_name("replay-tenant-b");
        gateway.create_repository(&owner_b, &name_b).await?;
        gateway.provision_decision_realm(&db, &owner_b, &name_b).await?;
        let denied = raw_get(
            &client,
            &format!("{}/refs", gateway.base(&owner_b.username, &name_b)),
            &owner_b.token,
            Some(&token),
        )
        .await?;
        ensure!(denied.status == 400, "a cross-tenant token was not refused with 400");
        ensure!(!status_succeeds(denied.status), "a cross-tenant token succeeded");
        ensure!(denied.session.token.is_none(), "a refused cross-tenant read emitted a session");
        ensure!(!looks_like_refs(&denied.body), "a cross-tenant refusal looked like a refs answer");
        ensure_no_disclosure(&denied.body, &[oid_a.as_str(), PUSHED_REF], "cross-tenant replay")?;
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn expired_session_token_is_refused_over_http() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = async {
        let (gateway, owner, name, _oid) = pushed(&db, "expired-token").await?;
        let live = live_realm(&db, &gateway, &owner, &name, false).await?;
        // Deterministic mint: signed one second past its whole bounded lifetime,
        // so no test ever sleeps for expiry.
        let issued_unix = unix_now()?.checked_sub(i64::from(BOUNDED_LIFETIME) + 1).ok_or_else(|| {
            anyhow::anyhow!("trusted clock is too close to the Unix epoch for a deterministic expiry")
        })?;
        let expired = gateway
            .tokens
            .issue_at(&live.realm, live.revision, issued_unix)
            .map_err(|_| anyhow::anyhow!("deterministic expired session issue was refused"))?;
        let client = reqwest::Client::new();
        let denied = raw_get(
            &client,
            &format!("{}/refs", gateway.base(&owner.username, &name)),
            &owner.token,
            Some(expired.token()),
        )
        .await?;
        ensure!(denied.status == 400, "an expired token was not refused with 400");
        ensure!(contains(&denied.body, "expired"), "an expired token was not named as expired");
        ensure!(denied.session.token.is_none(), "a refused expired read emitted a session");
        ensure!(!looks_like_refs(&denied.body), "an expired-token refusal looked like a refs answer");
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn tampered_session_token_is_refused_over_http() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = async {
        let (gateway, owner, name, oid) = pushed(&db, "forged-token").await?;
        let client = reqwest::Client::new();
        let token = issued_token(&gateway, &client, &owner, &owner.username, &name).await?;
        let forged = flip_mac(&token)?;
        let denied =
            raw_get(&client, &format!("{}/refs", gateway.base(&owner.username, &name)), &owner.token, Some(&forged))
                .await?;
        ensure!(denied.status == 400, "a tampered MAC was not refused with 400");
        ensure!(denied.session.token.is_none(), "a refused forged read emitted a session");
        ensure!(!looks_like_refs(&denied.body), "a forged-token refusal looked like a refs answer");
        ensure_no_disclosure(&denied.body, &[oid.as_str(), PUSHED_REF], "forged-token refusal")?;
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn revoked_collaborator_session_is_refused_before_token_scoring() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = async {
        let (gateway, owner, name, oid) = pushed(&db, "revoked-collaborator").await?;
        let collaborator = actor::stranger(&db.pool).await?;
        let repo = serving(&db, &gateway, &owner, &name, false).await?;
        add_read_collaborator(&db, repo.gate.repository_id(), repo.gate.tenant_id(), collaborator.identity.id).await?;

        let client = reqwest::Client::new();
        let token = issued_token(&gateway, &client, &collaborator, &owner.username, &name).await?;
        remove_collaborator(&db, repo.gate.repository_id(), collaborator.identity.id).await?;

        // The token is still authentic and unexpired, but the live repository
        // authorization now refuses exactly like an unauthorized stranger.
        let denied = raw_get(
            &client,
            &format!("{}/refs", gateway.base(&owner.username, &name)),
            &collaborator.token,
            Some(&token),
        )
        .await?;
        let stranger = actor::stranger(&db.pool).await?;
        let baseline =
            raw_get(&client, &format!("{}/refs", gateway.base(&owner.username, &name)), &stranger.token, None).await?;
        ensure!(!status_succeeds(denied.status), "a revoked collaborator's token still read the repository");
        ensure!(denied.status == baseline.status, "revocation answered differently from an unauthorized stranger");
        ensure!(denied.body == baseline.body, "revocation body differed from an unauthorized stranger");
        ensure!(denied.session.token.is_none(), "a refused revoked read emitted a session");
        ensure!(!looks_like_refs(&denied.body), "a revoked-collaborator refusal looked like a refs answer");
        ensure_no_disclosure(&denied.body, &[oid.as_str(), PUSHED_REF], "revoked-collaborator refusal")?;
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn missing_registered_pack_fails_closed_without_a_session() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = async {
        let (gateway, owner, name, oid) = pushed(&db, "missing-pack").await?;
        let client = reqwest::Client::new();
        let token = issued_token(&gateway, &client, &owner, &owner.username, &name).await?;

        // The token is valid, the refs are durable, but the acknowledged pack
        // bytes are gone from the shared Blob store.
        delete_registered_pack(&gateway, &db, &owner, &name).await?;
        let url = format!("{}/tree?oid=HEAD", gateway.base(&owner.username, &name));
        let denied = raw_get(&client, &url, &owner.token, Some(&token)).await?;
        ensure!((500..600).contains(&denied.status), "a missing registered pack did not fail closed with a 5xx status");
        ensure!(denied.session.token.is_none(), "a missing-pack failure emitted a session header");
        ensure!(!looks_like_refs(&denied.body), "a missing-pack failure looked like a successful read");
        ensure_no_disclosure(&denied.body, &[oid.as_str(), PUSHED_REF], "missing-pack refusal")?;

        // The same corruption is not a token verdict: a token-free read must
        // fail closed too, never fall back to the durable refs alone.
        let token_free = raw_get(&client, &url, &owner.token, None).await?;
        ensure!((500..600).contains(&token_free.status), "a token-free corrupt read did not fail closed");
        ensure!(token_free.session.token.is_none(), "a token-free corrupt read emitted a session");
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn keyring_loaded_gateway_issues_and_validates_sessions() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = async {
        let store = open_store()?;
        // Production loader: 0700 directory, 0600 schema-2 manifest, 0600 key.
        let (_keyring, tokens) = keyring_tokens(store.backend_identity())?;
        let gateway = Gateway::start(&db, store, tokens).await?;
        let owner = actor::owner(&db.pool).await?;
        let name = unique_name("keyring");
        gateway.create_repository(&owner, &name).await?;
        gateway.provision_decision_realm(&db, &owner, &name).await?;
        let oid = gateway.push_commit(&owner, &name).await?;
        let pushed = gateway.push_session().admit()?;
        let authoritative = serving(&db, &gateway, &owner, &name, false).await?;
        ensure!(
            pushed.revision > 0 && pushed.revision == authoritative.gate.revision(),
            "the keyring-loaded push token was not bound to the committed gate revision"
        );

        let client = reqwest::Client::new();
        let refs = json_read(
            &client,
            &format!("{}/refs", gateway.base(&owner.username, &name)),
            &owner.token,
            Some(&pushed.token),
        )
        .await?;
        ensure!(contains(&refs.body, &oid) && contains(&refs.body, PUSHED_REF), "keyring refs read missed the push");
        let refs_bound = refs.session.admit_at_least(&pushed)?;
        let tree = json_read(
            &client,
            &format!("{}/tree?oid=HEAD", gateway.base(&owner.username, &name)),
            &owner.token,
            Some(&refs_bound.token),
        )
        .await?;
        ensure!(contains(&tree.body, COMMIT_FILE), "keyring tree read missed the pushed file");
        drop(tree.session.admit_at_least(&refs_bound)?);

        // The loaded key set validates as well as issues.
        let forged = flip_mac(&refs_bound.token)?;
        let denied =
            raw_get(&client, &format!("{}/refs", gateway.base(&owner.username, &name)), &owner.token, Some(&forged))
                .await?;
        ensure!(denied.status == 400, "the keyring-loaded gateway accepted a tampered token");
        ensure!(denied.session.token.is_none(), "a keyring-loaded forged read emitted a session");
        Ok(())
    }
    .await;
    db.finish(outcome).await
}
