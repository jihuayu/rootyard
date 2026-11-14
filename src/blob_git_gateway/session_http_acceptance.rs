//! Real HTTP acceptance for the push-bound repository session (#174).
//!
//! Compiled only inside the library's `cfg(test)` build, so it opens the very
//! same production token codec (`SessionTokenCodec`, `SessionTokens`) that the
//! standalone keyring loader uses. It adds no production API and edits no
//! keyring: the only test-only artifact is one deterministic HMAC key held in
//! `Zeroizing` memory, attached exactly like a configured key set. The negative
//! and keyring cases live in [`negative_tests`]; the loopback fixtures live in
//! [`support`].
//!
//! Run explicitly by Root (one case, `#[ignore]`, hard-fails when a real
//! service or variable is absent):
//!
//! ```text
//! ROOTYARD_TEST_DATABASE_URL=... ROOTYARD_BLOB_SERVICE=s3 ROOTYARD_BLOB_ENDPOINT=... \
//! ROOTYARD_BLOB_BUCKET=... ROOTYARD_BLOB_REGION=... ROOTYARD_BLOB_ACCESS_KEY_ID=... \
//! ROOTYARD_BLOB_SECRET_ACCESS_KEY=... ROOTYARD_TEST_GIT=/usr/bin/git \
//! cargo test --lib session_http_acceptance -- --ignored --test-threads=1
//! ```
//!
//! The outer runner first migrates a fresh owned physical database with the
//! current CLI, so `public.cluster_authority` already holds the production
//! fence. This case never writes that row: it creates its own random schema
//! with the real `db::migrate` and reads the fence only through the real
//! lookups.
//!
//! Flow: real `POST /api/repos`, real `lookup` + `PgDecisionProtocol::provision`
//! of the migration-144 realm, a native Git clone/commit/push over the real
//! `/git/{owner}/{name}.git` Smart HTTP route, then `/refs` -> `/tree?oid=HEAD`
//! -> `/commits`, each presenting the previous successful read's session token.
//! The push-issued revision is compared with a fresh authoritative serving
//! lookup before any read, so the test proves the bound is the committed gate
//! revision rather than merely a monotone number. Every answer must carry a
//! nonempty token and a positive revision that never regresses. A final `/refs`
//! without any session header proves the token-free request still succeeds.
//!
//! Refusals over the same real routes, never through handler calls:
//!
//! * a malformed `x-rootyard-session` from the owner is an explicit `400`;
//! * a live foreign actor (`fixtures::actor::stranger`) sending malformed and no
//!   session header to the owner's repository gets the same refusal and body,
//!   so actor/repository authorization runs before any version-token error;
//! * a correctly MACed lower bound `live_revision + 1` minted through the
//!   crate-private test-only `SessionRealm::new` + `SessionTokens::issue_for_test`
//!   for a fresh authorized `serving::lookup` realm is the generic `503`
//!   `BEHIND_MESSAGE`.
//!
//! Every refusal body is checked against the pushed OID/ref so it discloses
//! neither repository content nor another repository's details.
//!
//! Messages are generic on purpose: Git URLs carry credentials, so neither a
//! URL, Git stderr, a token, the key, the database URL nor Blob secrets are
//! ever printed.

// The integration suite compiles the whole fixture tree. This library harness
// includes the narrow `session.rs` entry point once, exposing only the real
// actor/database/Git modules the HTTP harnesses drive. The admission case
// imports these same modules instead of loading the files a second time, so
// no `dead_code` allowance is needed on either side.
#[path = "../../tests/blob_gateway_support/session.rs"]
pub(super) mod fixtures;
mod negative_tests;
mod support;

use anyhow::{Context, Result, anyhow, ensure};

use self::{
    fixtures::{actor, db::Db},
    support::{
        Gateway, MALFORMED_SESSION, PUSHED_REF, contains, ensure_no_disclosure, is_denial, json_read, json_string,
        live_realm, looks_like_refs, open_store, raw_get, serving, status_succeeds, test_tokens, unique_name,
    },
};
use super::repo_session::BEHIND_MESSAGE;

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn push_token_bounds_repeated_http_reads() -> Result<()> {
    let _serial = super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    let db = Db::setup().await?;
    let outcome = case(&db).await;
    db.finish(outcome).await
}

async fn case(db: &Db) -> Result<()> {
    let store = open_store()?;
    let tokens = test_tokens(store.backend_identity())?;
    let gateway = Gateway::start(db, store, tokens).await?;
    let owner = actor::owner(&db.pool).await?;
    // A live real actor with no role on the owner's repository.
    let stranger = actor::stranger(&db.pool).await?;

    let name = unique_name("session");
    gateway.create_repository(&owner, &name).await?;
    gateway.provision_decision_realm(db, &owner, &name).await?;

    // Real native Git over the real Smart HTTP routes.
    let oid = gateway.push_commit(&owner, &name).await?;
    let pushed_bound = gateway.push_session().admit()?;

    // The push token's bound is the revision a fresh authoritative lookup
    // states, not merely some positive number: this is the read-your-writes
    // guarantee the repeated reads below must keep.
    let authoritative = serving(db, &gateway, &owner, &name, false).await?;
    ensure!(
        pushed_bound.revision > 0 && pushed_bound.revision == authoritative.gate.revision(),
        "the push session bound is not the freshly committed authoritative gate revision"
    );

    let base = gateway.base(&owner.username, &name);
    let client = reqwest::Client::new();

    // 1. refs, presenting the push-issued bound.
    let answer = json_read(&client, &format!("{base}/refs"), &owner.token, Some(&pushed_bound.token)).await?;
    ensure!(
        contains(&answer.body, PUSHED_REF) && contains(&answer.body, &oid),
        "refs body did not contain the pushed ref and OID"
    );
    let refs_bound = answer.session.admit_at_least(&pushed_bound)?;
    ensure!(refs_bound.revision >= pushed_bound.revision, "refs answered behind the push bound");

    // 2. tree at HEAD, presenting the refs bound.
    let answer = json_read(&client, &format!("{base}/tree?oid=HEAD"), &owner.token, Some(&refs_bound.token)).await?;
    ensure!(
        contains(&answer.body, &json_string("readme.txt")) && contains(&answer.body, &oid),
        "tree body did not contain the pushed commit and file"
    );
    let tree_bound = answer.session.admit_at_least(&refs_bound)?;
    ensure!(tree_bound.revision >= pushed_bound.revision, "tree answered behind the push bound");

    // 3. commits, presenting the tree bound.
    let answer = json_read(&client, &format!("{base}/commits"), &owner.token, Some(&tree_bound.token)).await?;
    ensure!(contains(&answer.body, &oid), "commits body did not contain the pushed commit");
    let commits_bound = answer.session.admit_at_least(&tree_bound)?;
    ensure!(commits_bound.revision >= pushed_bound.revision, "commits answered behind the push bound");

    // 4. Token-free compatibility: no session header is presented at all.
    let answer = json_read(&client, &format!("{base}/refs"), &owner.token, None).await?;
    ensure!(
        contains(&answer.body, PUSHED_REF) && contains(&answer.body, &oid),
        "token-free refs body did not contain the pushed ref and OID"
    );
    // A configured gateway may answer with its own token; if it does, it is
    // still a complete, non-regressing bound against the last presented one.
    drop(answer.session.admit_at_least(&commits_bound)?);

    let secrets = [oid.as_str(), PUSHED_REF];

    // 5. The authorized owner's malformed session header is an explicit 400.
    let malformed = raw_get(&client, &format!("{base}/refs"), &owner.token, Some(MALFORMED_SESSION)).await?;
    ensure!(malformed.status == 400, "malformed session header was not refused with 400");
    ensure!(!malformed.body.is_empty(), "malformed session refusal carried no body");
    ensure_no_disclosure(&malformed.body, &secrets, "malformed session refusal")?;

    // 6. The live foreign actor is refused identically with a malformed and no
    // session header: actor/repository authorization precedes token errors.
    let foreign = format!("http://{}/api/repos/{}/{}/refs", gateway.address, owner.username, name);
    let mut denied = Vec::new();
    for session in [Some(MALFORMED_SESSION), None] {
        let answer = raw_get(&client, &foreign, &stranger.token, session).await?;
        ensure!(!status_succeeds(answer.status), "foreign actor was not denied on the owner's repository");
        ensure!(is_denial(answer.status), "foreign actor denial was not an authorization refusal");
        ensure!(!answer.body.is_empty(), "foreign actor denial carried no body");
        ensure!(!looks_like_refs(&answer.body), "foreign actor denial looked like a successful refs answer");
        ensure_no_disclosure(&answer.body, &secrets, "foreign actor denial")?;
        ensure_no_disclosure(
            &answer.body,
            &[stranger.username.as_str(), owner.username.as_str()],
            "foreign actor denial",
        )?;
        denied.push(answer);
    }
    ensure!(denied[0].status == denied[1].status, "foreign actor denial status depended on the session header");
    ensure!(denied[0].body == denied[1].body, "foreign actor denial body depended on the session header");

    // 7. A correctly MACed lower bound one past the live revision, minted for
    // the exact realm a fresh authorized lookup states, is the generic 503.
    let live = live_realm(db, &gateway, &owner, &name, false).await?;
    let future_revision = live.revision.checked_add(1).context("live gate revision overflow")?;
    let future = gateway
        .tokens
        .issue_for_test(&live.realm, future_revision)
        .map_err(|_| anyhow!("future-bound session issue refused"))?;
    let ahead = raw_get(&client, &format!("{base}/refs"), &owner.token, Some(future.token())).await?;
    ensure!(ahead.status == 503, "future session bound was not refused with 503");
    ensure!(contains(&ahead.body, BEHIND_MESSAGE), "future session refusal did not carry BEHIND_MESSAGE");
    ensure!(!looks_like_refs(&ahead.body), "future session refusal looked like a successful refs answer");
    ensure_no_disclosure(&ahead.body, &secrets, "future session refusal")?;

    Ok(())
}
