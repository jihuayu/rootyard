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

    // 1. Non-navigation anonymous /web/blob returns 401 without session headers,
    //    while browser navigation requests redirect cleanly to /web/login with return_to.
    let non_nav = client.get(format!("{origin}/web/blob")).send().await?;
    ensure!(non_nav.status() == 401, "non-navigation anonymous /web/blob expected 401, got {}", non_nav.status());
    ensure!(!has_session_headers(non_nav.headers()), "anonymous /web/blob 401 must not emit session headers");

    let anon = client
        .get(format!("{origin}/web/blob"))
        .header(header::ACCEPT, "text/html")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await?;
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

    // 6. Browser cookie + monotonic session chaining across /web/blob/api/* (including numeric query params).
    let alias_base = format!("{origin}/web/blob/api/repos/{}/{}", owner.username, name);
    let list =
        raw_get_with_cookies(&client, &format!("{origin}/web/blob/api/repos?limit=10"), Some(&cookie), None).await?;
    ensure!(list.status == 200 && contains(&list.body, &name), "browser list alias failed");
    ensure!(list.session.token.is_none(), "repository list must not mint a session bound");

    let repo_meta = raw_get_with_cookies(&client, &alias_base, Some(&cookie), None).await?;
    ensure!(repo_meta.status == 200 && contains(&repo_meta.body, &name), "browser get_repo alias failed");

    let refs = raw_get_with_cookies(&client, &format!("{alias_base}/refs?limit=10"), Some(&cookie), None).await?;
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
        .get(format!("{origin}/git/{}/{}.git/info/refs?service=git-upload-pack", owner.username, name))
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

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob storage and native Git"]
async fn browser_aliases_paginate_across_default_limits_with_bounded_session() -> Result<()> {
    let _serial = super::super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    let db = Db::setup().await?;
    let outcome = pagination_case(&db).await;
    db.finish(outcome).await
}

async fn pagination_case(db: &Db) -> Result<()> {
    let store = support::open_store()?;
    let (_keyring_dir, tokens) = support::keyring_tokens(store.backend_identity())?;
    let gateway = Gateway::start(db, store, tokens).await?;
    let owner = actor::owner(&db.pool).await?;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .context("no-redirect HTTP client could not be built")?;
    let origin = format!("http://{}", gateway.address);

    for idx in 1..=101 {
        let pad = format!("a-pad-{idx:03}");
        create_serving_repo(&client, &origin, &gateway, db, &owner, &pad).await?;
    }
    let name = support::unique_name("browser-page");
    create_serving_repo(&client, &origin, &gateway, db, &owner, &name).await?;

    let (_work, checkout) = gateway.clone_checkout(&owner, &name).await?;
    let oid_first = gateway.git.commit(&checkout, COMMIT_FILE, "first commit\n", "first commit").await?;
    gateway.git.ok(&checkout, &["branch", "-M", "main"]).await?;
    for idx in 1..=54 {
        gateway
            .git
            .ok(&checkout, &["commit", "--quiet", "--allow-empty", "-m", &format!("page history {idx:02}")])
            .await?;
    }
    for idx in 1..=55 {
        std::fs::write(checkout.join(format!("f-{idx:02}.txt")), "pad\n")?;
    }
    gateway.git.ok(&checkout, &["add", "."]).await?;
    gateway.git.ok(&checkout, &["commit", "--quiet", "-m", "tree page commit"]).await?;
    let oid_head = gateway.git.text(&checkout, &["rev-parse", "HEAD"]).await?;
    for idx in 1..=54 {
        gateway.git.ok(&checkout, &["branch", &format!("z-ref-{idx:02}")]).await?;
    }
    let main_push = gateway.git.run(&checkout, &["push", "--quiet", "origin", "HEAD:refs/heads/main"]).await?;
    ensure!(main_push.success, "multi-page main Smart HTTP push was refused");
    let page_refs: Vec<String> = (1..=54).map(|idx| format!("refs/heads/z-ref-{idx:02}")).collect();
    // Each push stays well below the 64 KiB worst-case PackCommitTerminal budget (<= 52 refs).
    for chunk in page_refs.chunks(27) {
        let mut args = vec!["push", "--quiet", "origin"];
        args.extend(chunk.iter().map(String::as_str));
        let pushed = gateway.git.run(&checkout, &args).await?;
        ensure!(pushed.success, "multi-page fixture Smart HTTP push was refused");
    }
    let live = support::live_realm(db, &gateway, &owner, &name, false).await?;

    let form_body = form_encode(&[("username", &owner.username), ("token", &owner.token), ("return_to", "/web/blob")]);
    let login = client
        .post(format!("{origin}/web/login"))
        .header(header::ORIGIN, &origin)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form_body)
        .send()
        .await?;
    ensure!(login.status() == 303, "POST /web/login expected 303, got {}", login.status());
    let cookie = extract_cookie_header(login.headers()).context("POST /web/login emitted no Set-Cookie")?;

    // 1. Default `/web/blob/api/repos` (limit=100) emits `x-next-cursor`; `?cursor=` finishes page 2.
    let page1 = client.get(format!("{origin}/web/blob/api/repos")).header(header::COOKIE, &cookie).send().await?;
    ensure!(page1.status() == 200, "list page 1 expected 200, got {}", page1.status());
    ensure!(!has_session_headers(page1.headers()), "list page 1 emitted session headers");
    let next_cursor = header_text(page1.headers(), header::HeaderName::from_static("x-next-cursor"))
        .context("102 serving repos did not emit x-next-cursor on page 1")?;
    ensure!(
        header_text(page1.headers(), header::LINK).as_deref().is_some_and(|v| v.contains("rel=\"next\"")),
        "list page 1 missing Link next header"
    );
    let repos1: serde_json::Value = page1.json().await?;
    let rows1 = repos1.as_array().context("list page 1 was not an array")?;
    ensure!(rows1.len() == 100, "list page 1 expected 100 items, got {}", rows1.len());
    ensure!(!rows1.iter().any(|r| r["name"].as_str() == Some(name.as_str())), "target repo appeared early on page 1");

    let list_page2_url = format!("{origin}/web/blob/api/repos?cursor={}", crate::pagination::query_value(&next_cursor));
    let page2 = client.get(list_page2_url).header(header::COOKIE, &cookie).send().await?;
    ensure!(page2.status() == 200, "list page 2 expected 200, got {}", page2.status());
    ensure!(!has_session_headers(page2.headers()), "list page 2 emitted session headers");
    ensure!(!page2.headers().contains_key("x-next-cursor"), "final list page still emitted x-next-cursor");
    let repos2: serde_json::Value = page2.json().await?;
    let rows2 = repos2.as_array().context("list page 2 was not an array")?;
    ensure!(
        rows2.len() == 2 && rows2.iter().any(|r| r["name"].as_str() == Some(name.as_str())),
        "list page 2 did not contain target repo ({} rows)",
        rows2.len()
    );

    // 2. Default `/refs`, `/tree?oid=HEAD`, and `/commits` (limit=50) paginate cleanly while maintaining bound.
    let alias_base = format!("{origin}/web/blob/api/repos/{}/{}", owner.username, name);
    let refs1 = raw_get_with_cookies(&client, &format!("{alias_base}/refs"), Some(&cookie), None).await?;
    ensure!(status_succeeds(refs1.status), "refs page 1 failed with {}", refs1.status);
    let s1 = refs1.session.admit()?;
    ensure!(s1.revision >= live.revision, "refs page 1 behind live revision");
    let refs1_json: serde_json::Value = serde_json::from_str(&refs1.body)?;
    ensure!(refs1_json["items"].as_array().is_some_and(|a| a.len() == 50), "refs page 1 length != 50");
    ensure!(refs1_json["more"].as_bool() == Some(true), "refs page 1 more != true");
    let refs_after = refs1_json["next_after"].as_str().context("refs page 1 missing next_after")?;

    let refs2_url = format!("{alias_base}/refs?after={}", crate::pagination::query_value(refs_after));
    let refs2 = raw_get_with_cookies(&client, &refs2_url, Some(&cookie), Some(&s1.token)).await?;
    ensure!(status_succeeds(refs2.status), "refs page 2 failed with {}", refs2.status);
    let s2 = refs2.session.admit_at_least(&s1)?;
    let refs2_json: serde_json::Value = serde_json::from_str(&refs2.body)?;
    let refs2_items = refs2_json["items"].as_array().context("refs page 2 items missing")?;
    ensure!(
        refs2_items.len() == 5
            && refs2_json["next_after"].is_null()
            && refs2_json["more"].as_bool() == Some(false)
            && refs2_items.iter().any(|item| item["name"].as_str() == Some("refs/heads/z-ref-54")),
        "refs page 2 incomplete"
    );

    let tree1 =
        raw_get_with_cookies(&client, &format!("{alias_base}/tree?oid=HEAD"), Some(&cookie), Some(&s2.token)).await?;
    ensure!(status_succeeds(tree1.status), "tree page 1 failed with {}", tree1.status);
    let s3 = tree1.session.admit_at_least(&s2)?;
    let tree1_json: serde_json::Value = serde_json::from_str(&tree1.body)?;
    ensure!(tree1_json["items"].as_array().is_some_and(|a| a.len() == 50), "tree page 1 length != 50");
    let tree_after = tree1_json["next_after"].as_str().context("tree page 1 missing next_after")?;

    let tree2_url = format!("{alias_base}/tree?oid=HEAD&after={}", crate::pagination::query_value(tree_after));
    let tree2 = raw_get_with_cookies(&client, &tree2_url, Some(&cookie), Some(&s3.token)).await?;
    ensure!(status_succeeds(tree2.status), "tree page 2 failed with {}", tree2.status);
    let s4 = tree2.session.admit_at_least(&s3)?;
    let tree2_json: serde_json::Value = serde_json::from_str(&tree2.body)?;
    let tree2_items = tree2_json["items"].as_array().context("tree page 2 items missing")?;
    ensure!(
        tree2_items.len() == 6
            && tree2_json["next_after"].is_null()
            && tree2_items.iter().any(|item| item["path"].as_str() == Some(COMMIT_FILE)),
        "tree page 2 incomplete"
    );

    let commits1 =
        raw_get_with_cookies(&client, &format!("{alias_base}/commits"), Some(&cookie), Some(&s4.token)).await?;
    ensure!(status_succeeds(commits1.status), "commits page 1 failed with {}", commits1.status);
    let s5 = commits1.session.admit_at_least(&s4)?;
    let commits1_json: serde_json::Value = serde_json::from_str(&commits1.body)?;
    ensure!(commits1_json["items"].as_array().is_some_and(|a| a.len() == 50), "commits page 1 length != 50");
    ensure!(contains(&commits1.body, &oid_head), "commits page 1 missing head commit");
    let commits_after = commits1_json["next_after"].as_u64().context("commits page 1 missing integer next_after")?;
    ensure!(commits_after == 50, "commits page 1 next_after expected 50, got {commits_after}");

    let commits2_url = format!("{alias_base}/commits?after={commits_after}");
    let commits2 = raw_get_with_cookies(&client, &commits2_url, Some(&cookie), Some(&s5.token)).await?;
    ensure!(status_succeeds(commits2.status), "commits page 2 failed with {}", commits2.status);
    let _s6 = commits2.session.admit_at_least(&s5)?;
    let commits2_json: serde_json::Value = serde_json::from_str(&commits2.body)?;
    ensure!(
        commits2_json["items"].as_array().is_some_and(|a| a.len() == 6)
            && commits2_json["next_after"].is_null()
            && contains(&commits2.body, &oid_first),
        "commits page 2 missing earliest commit"
    );

    // 3. An ahead lower bound on any continuation URL still fails closed with 503.
    let future_rev = live.revision.checked_add(1).context("revision overflow")?;
    let future = gateway.tokens.issue_for_test(&live.realm, future_rev).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    for continuation in [refs2_url, tree2_url, commits2_url] {
        let ahead = raw_get_with_cookies(&client, &continuation, Some(&cookie), Some(future.token())).await?;
        ensure!(ahead.status == 503, "continuation ahead bound expected 503, got {}", ahead.status);
        ensure!(contains(&ahead.body, BEHIND_MESSAGE), "continuation 503 missing BEHIND_MESSAGE");
        ensure!(ahead.session.token.is_none() && ahead.session.revision.is_none(), "continuation 503 emitted headers");
        ensure_no_disclosure(&ahead.body, &[&owner.token, future.token(), &cookie], "continuation ahead 503")?;
    }

    Ok(())
}

async fn create_serving_repo(
    client: &reqwest::Client,
    origin: &str,
    gateway: &Gateway,
    db: &Db,
    owner: &super::fixtures::actor::Actor,
    name: &str,
) -> Result<()> {
    let response = client
        .post(format!("{origin}/api/repos"))
        .bearer_auth(&owner.token)
        .json(&serde_json::json!({"name": name, "object_format": "sha1"}))
        .send()
        .await?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
    ensure!(status.is_success(), "create API returned {status}: {}", body["error"].as_str().unwrap_or("<none>"));
    gateway.provision_decision_realm(db, owner, name).await
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
