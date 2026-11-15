use anyhow::{Context, Result, ensure};
use axum::http::header;
use reqwest::redirect::Policy;

use crate::blob_git_gateway::repo_session::BEHIND_MESSAGE;

use super::fixtures::{actor, db::Db};
use super::support::{
    self, COMMIT_FILE, Gateway, contains, ensure_no_disclosure, form_encode, raw_get_with_cookies, status_succeeds,
};

#[test]
fn form_encode_escapes_reserved_bytes_without_changing_tokens() {
    let encoded = form_encode(&[
        ("username", "alice smith"),
        ("token", "ry_abc+/=123"),
        ("return_to", "/web/blob/repos/alice/app?x=1&y=2"),
    ]);
    assert_eq!(
        encoded,
        "username=alice+smith&token=ry_abc%2B%2F%3D123&return_to=%2Fweb%2Fblob%2Frepos%2Falice%2Fapp%3Fx%3D1%26y%3D2"
    );
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob storage and native Git"]
async fn browser_cookie_aliases_enforce_bound_and_reject_non_browser_routes() -> Result<()> {
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    let db = Db::setup().await?;
    let outcome = case(&db).await;
    db.finish(outcome).await
}

async fn case(db: &Db) -> Result<()> {
    let store = support::open_store()?;
    let (_keyring_dir, tokens) = support::keyring_tokens(store.backend_identity())?;
    let gateway = Gateway::start(db, store, tokens).await?;
    let owner = actor::owner(&db.pool).await?;
    let name = support::unique_name("browser-http");
    gateway.create_repository(&owner, &name).await?;
    gateway.provision_decision_realm(db, &owner, &name).await?;

    let (_work, checkout) = gateway.clone_checkout(&owner, &name).await?;
    let oid1 = gateway.commit_and_push(&checkout, COMMIT_FILE, "first commit\n", "first commit").await?;
    let oid2 = gateway.commit_and_push(&checkout, "second.txt", "second commit\n", "second commit").await?;
    let live = support::live_realm(db, &gateway, &owner, &name, false).await?;

    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .context("no-redirect HTTP client could not be built")?;
    let origin = format!("http://{}", gateway.address);
    let repo_shell_path = format!("/web/blob/repos/{}/{}", owner.username, name);

    // 1. Anonymous shell requests redirect cleanly to /web/login with return_to.
    let anon = client.get(format!("{origin}/web/blob")).send().await?;
    ensure!(anon.status() == 303, "anonymous /web/blob expected 303, got {}", anon.status());
    ensure!(
        anon.headers().get(header::LOCATION).and_then(|v| v.to_str().ok())
            == Some("/web/login?return_to=%2Fweb%2Fblob"),
        "anonymous /web/blob redirected to unexpected location"
    );
    ensure!(!has_session_headers(anon.headers()), "anonymous /web/blob redirect must not emit session headers");

    // 2. Unauthenticated /web/blob/api/* gets a scoped Bearer challenge, never Basic.
    let unauth_alias =
        client.get(format!("{origin}/web/blob/api/repos/{}/{}/refs", owner.username, name)).send().await?;
    ensure!(unauth_alias.status() == 401, "unauthenticated browser API alias expected 401");
    let alias_challenge = header_text(unauth_alias.headers(), header::WWW_AUTHENTICATE);
    ensure!(
        alias_challenge.as_deref().is_some_and(|v| v.starts_with("Bearer ") && !v.contains("Basic")),
        "browser API alias emitted wrong WWW-Authenticate challenge: {alias_challenge:?}"
    );

    // 3. /web/app.js serves static JS with strict CSP and no auth challenge.
    let script = client.get(format!("{origin}/web/app.js")).send().await?;
    ensure!(script.status() == 200, "/web/app.js expected 200, got {}", script.status());
    ensure!(
        header_text(script.headers(), header::CONTENT_TYPE).as_deref().is_some_and(|v| v.contains("javascript")),
        "/web/app.js did not declare JavaScript content-type"
    );
    ensure!(
        script.headers().contains_key(header::CONTENT_SECURITY_POLICY),
        "/web/app.js missing Content-Security-Policy"
    );
    ensure!(!script.headers().contains_key(header::WWW_AUTHENTICATE), "/web/app.js emitted WWW-Authenticate");

    // 4. Form sign-in exchanges username + API token for an HttpOnly session cookie.
    let form_body =
        form_encode(&[("username", &owner.username), ("token", &owner.token), ("return_to", &repo_shell_path)]);
    let login = client
        .post(format!("{origin}/web/login"))
        .header(header::ORIGIN, &origin)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form_body)
        .send()
        .await?;
    ensure!(login.status() == 303, "POST /web/login expected 303, got {}", login.status());
    ensure!(
        login.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()) == Some(repo_shell_path.as_str()),
        "POST /web/login did not redirect to sanitized return_to"
    );
    let cookie = extract_cookie_header(login.headers()).context("POST /web/login emitted no Set-Cookie")?;

    // 5. Authenticated browser shell pages render cleanly without leaking tokens or minting bounds.
    for page_path in ["/web/blob", &repo_shell_path] {
        let page = client.get(format!("{origin}{page_path}")).header(header::COOKIE, &cookie).send().await?;
        ensure!(page.status() == 200, "authenticated {page_path} expected 200, got {}", page.status());
        ensure!(
            page.headers().contains_key(header::CONTENT_SECURITY_POLICY),
            "{page_path} missing Content-Security-Policy"
        );
        ensure!(!has_session_headers(page.headers()), "{page_path} must not mint session headers");
        let html = page.text().await?;
        ensure!(!contains(&html, &owner.token), "{page_path} leaked API token into HTML");
    }

    // 6. Browser cookie + monotonic session chaining across /web/blob/api/*.
    let alias_base = format!("{origin}/web/blob/api/repos/{}/{}", owner.username, name);
    let list = raw_get_with_cookies(&client, &format!("{origin}/web/blob/api/repos"), Some(&cookie), None).await?;
    ensure!(list.status == 200 && contains(&list.body, &name), "browser list alias failed");
    ensure!(list.session.token.is_none(), "repository list must not mint a session bound");

    let repo_meta = raw_get_with_cookies(&client, &alias_base, Some(&cookie), None).await?;
    ensure!(repo_meta.status == 200 && contains(&repo_meta.body, &name), "browser get_repo alias failed");

    let refs = raw_get_with_cookies(&client, &format!("{alias_base}/refs"), Some(&cookie), None).await?;
    ensure!(status_succeeds(refs.status), "browser /refs alias failed with {}", refs.status);
    let s1 = refs.session.admit()?;
    ensure!(s1.revision >= live.revision, "browser /refs returned stale revision");

    let tree =
        raw_get_with_cookies(&client, &format!("{alias_base}/tree?oid=HEAD"), Some(&cookie), Some(&s1.token)).await?;
    ensure!(tree.status == 200 && contains(&tree.body, "second.txt"), "browser /tree?oid=HEAD failed");
    let s2 = tree.session.admit_at_least(&s1)?;

    let commits =
        raw_get_with_cookies(&client, &format!("{alias_base}/commits"), Some(&cookie), Some(&s2.token)).await?;
    ensure!(commits.status == 200 && contains(&commits.body, &oid2), "browser /commits failed");
    let s3 = commits.session.admit_at_least(&s2)?;

    let commit_old =
        raw_get_with_cookies(&client, &format!("{alias_base}/commits/{oid1}"), Some(&cookie), Some(&s3.token)).await?;
    ensure!(commit_old.status == 200 && contains(&commit_old.body, &oid1), "browser /commits/{{oid}} failed");
    let s4 = commit_old.session.admit_at_least(&s3)?;

    let tree_old =
        raw_get_with_cookies(&client, &format!("{alias_base}/tree/{oid1}"), Some(&cookie), Some(&s4.token)).await?;
    ensure!(
        tree_old.status == 200 && contains(&tree_old.body, COMMIT_FILE) && !contains(&tree_old.body, "second.txt"),
        "browser /tree/{{oid}} did not serve historical tree"
    );
    let s5 = tree_old.session.admit_at_least(&s4)?;

    let blob_old = raw_get_with_cookies(
        &client,
        &format!("{alias_base}/blob/{oid1}?path={COMMIT_FILE}"),
        Some(&cookie),
        Some(&s5.token),
    )
    .await?;
    ensure!(blob_old.status == 200 && contains(&blob_old.body, "first commit"), "browser /blob/{{oid}} failed");
    let s6 = blob_old.session.admit_at_least(&s5)?;

    let compare = raw_get_with_cookies(
        &client,
        &format!("{alias_base}/compare?base={oid1}&head={oid2}"),
        Some(&cookie),
        Some(&s6.token),
    )
    .await?;
    ensure!(
        compare.status == 200 && contains(&compare.body, &oid1) && contains(&compare.body, &oid2),
        "browser /compare failed"
    );
    let _s7 = compare.session.admit_at_least(&s6)?;

    // 7. A bound ahead of the live gate fails closed with 503 BEHIND_MESSAGE.
    let future_rev = live.revision.checked_add(1).context("revision overflow")?;
    let future = gateway.tokens.issue_for_test(&live.realm, future_rev).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let ahead =
        raw_get_with_cookies(&client, &format!("{alias_base}/refs"), Some(&cookie), Some(future.token())).await?;
    ensure!(ahead.status == 503, "future bound on browser alias expected 503, got {}", ahead.status);
    ensure!(contains(&ahead.body, BEHIND_MESSAGE), "503 browser alias refusal missing BEHIND_MESSAGE");
    ensure!(ahead.session.token.is_none() && ahead.session.revision.is_none(), "503 emitted session headers");
    ensure_no_disclosure(&ahead.body, &[&owner.token, future.token(), &cookie], "browser ahead 503")?;

    // 8. Browser session cookies never authenticate raw /api/* or /git/* endpoints.
    let raw_api = client.get(format!("{origin}/api/repos")).header(header::COOKIE, &cookie).send().await?;
    ensure!(raw_api.status() == 401, "cookie-only /api/repos expected 401, got {}", raw_api.status());
    let api_challenge = header_text(raw_api.headers(), header::WWW_AUTHENTICATE);
    ensure!(
        api_challenge.as_deref().is_some_and(|v| v.contains("Bearer") && !v.contains("Basic")),
        "/api/repos challenge mismatch: {api_challenge:?}"
    );

    let raw_git = client
        .get(format!("{origin}/git/{}/{}/info/refs?service=git-upload-pack", owner.username, name))
        .header(header::COOKIE, &cookie)
        .send()
        .await?;
    ensure!(raw_git.status() == 401, "cookie-only /git info/refs expected 401, got {}", raw_git.status());
    let git_challenge = header_text(raw_git.headers(), header::WWW_AUTHENTICATE);
    ensure!(
        git_challenge.as_deref().is_some_and(|v| v.contains("Basic") && !v.contains("Bearer")),
        "/git challenge mismatch: {git_challenge:?}"
    );

    Ok(())
}

fn has_session_headers(headers: &axum::http::HeaderMap) -> bool {
    headers.contains_key("x-rootyard-session") || headers.contains_key("x-rootyard-session-revision")
}

fn header_text(headers: &axum::http::HeaderMap, name: header::HeaderName) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
}

fn extract_cookie_header(headers: &axum::http::HeaderMap) -> Option<String> {
    let pairs: Vec<&str> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|raw| raw.split(';').next())
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .collect();
    if pairs.is_empty() { None } else { Some(pairs.join("; ")) }
}
