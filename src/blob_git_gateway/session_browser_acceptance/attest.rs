//! Independent attestation of what the origin really answered.
//!
//! The Rust side never trusts the page's own labels for any fact the adapter
//! observed: every upstream fact below comes from the [`Recorded`] entries the
//! adapter captured, or from the live gate revision read through PostgreSQL.
//! The page-only booleans are checked exactly where the page is the only
//! observer: the synthetic fault tree answer is produced in the browser and
//! never reaches the adapter, so the adapter records only the fault page's own
//! real refs read around it.
//!
//! Session token strings are compared in memory only and are never formatted
//! into a message; the same holds for the API token.
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

use super::capture::{Recorded, Route};

/// The session revisions the page reported for its read chain.
pub(super) struct Chain {
    pub refs_revision: i64,
    pub tree_revision: i64,
    pub commits_revision: i64,
}

/// One summary revision, which must be a positive integer.
pub(super) fn reported_revision(summary: &Value, path: &[&str]) -> Result<i64> {
    let mut node = summary;
    for key in path {
        node = node.get(*key).ok_or_else(|| anyhow!("the page reported no session revision"))?;
    }
    node.as_i64().filter(|revision| *revision > 0).ok_or_else(|| anyhow!("the page reported no session revision"))
}

/// The page's fixed reason code, or `unknown`. Only a short code of uppercase
/// ASCII letters and `_` (1..=40 bytes) is echoed, so neither free-form
/// subprocess text nor a credential can reach the message.
fn diagnostic_reason(summary: &Value) -> &str {
    let reason = summary["reason"].as_str().unwrap_or("");
    let safe = (1..=40).contains(&reason.len()) && reason.bytes().all(|byte| byte.is_ascii_uppercase() || byte == b'_');
    if safe { reason } else { "unknown" }
}

/// The summary's own shape: PASS, a browser version, the fault label, the exact
/// status of every route, and the reported chain revisions, each bounded by the
/// live gate. The fault page's reported revisions are cross-checked against its
/// captured refs answer in [`verify`], never against the main chain. No identity
/// or credential is part of the summary.
pub(super) fn summary(summary: &Value, live: i64) -> Result<Chain> {
    ensure!(
        summary["result"].as_str() == Some("PASS"),
        "the page did not report PASS: reason {}",
        diagnostic_reason(summary)
    );
    ensure!(summary["reason"].as_str() == Some("PASS"), "the page reported PASS with another reason");
    ensure!(!summary["browser"].as_str().unwrap_or("").is_empty(), "the page named no browser version");
    ensure!(summary["fault"]["mode"].as_str() == Some("client_fault_injection"), "the fault is not labelled");
    for (route, expected) in [
        ("web_signin_redirect", 303),
        ("web_login", 303),
        ("web_blob", 200),
        ("web_list", 200),
        ("web_refs", 200),
        ("web_tree", 200),
        ("web_commits", 200),
    ] {
        ensure!(
            summary["routes"].get(route).and_then(Value::as_u64) == Some(expected),
            "the page did not report {route} as {expected}"
        );
    }
    let chain = Chain {
        refs_revision: reported_revision(summary, &["reads", "refs", "revision"])?,
        tree_revision: reported_revision(summary, &["reads", "tree", "revision"])?,
        commits_revision: reported_revision(summary, &["reads", "commits", "revision"])?,
    };
    ensure!(chain.tree_revision >= chain.refs_revision, "the reported chain regressed");
    ensure!(chain.commits_revision >= chain.tree_revision, "the reported commit read regressed");
    ensure!(chain.commits_revision <= live, "a reported revision is ahead of the live gate");
    Ok(chain)
}

/// One complete positive session pair exactly as an answer carried it. The
/// token lives only in this owner and is never formatted.
struct Pair {
    token: String,
    revision: i64,
}

impl Pair {
    fn of(entry: &Recorded, what: &'static str) -> Result<Self> {
        let token = entry.response_token.as_deref().filter(|token| !token.is_empty());
        let token = token.ok_or_else(|| anyhow!("{what} carried no session token"))?;
        let revision = entry.response_revision.as_deref().and_then(|revision| revision.parse::<i64>().ok());
        let revision = revision.ok_or_else(|| anyhow!("{what} carried no readable session revision"))?;
        ensure!(revision > 0, "{what} carried a non-positive session revision");
        Ok(Self { token: token.to_owned(), revision })
    }

    /// The next request presented exactly this token and no revision.
    fn presented_by(&self, entry: &Recorded, what: &'static str) -> Result<()> {
        ensure!(
            entry.request_token.as_deref() == Some(self.token.as_str()),
            "{what} did not present exactly the token"
        );
        ensure!(entry.request_revision.is_none(), "{what} presented a revision");
        Ok(())
    }
}

/// The position of one named request: the `occurrence`-th (0-based) request on
/// the exact path of this route.
fn find(recorded: &[Recorded], route: Route, occurrence: usize, what: &'static str) -> Result<usize> {
    recorded
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.route == route)
        .nth(occurrence)
        .map(|(index, _)| index)
        .ok_or_else(|| anyhow!("the page never requested {what}"))
}

/// The captured request at one position, which must be the expected route.
fn at<'a>(recorded: &'a [Recorded], index: usize, route: Route, what: &'static str) -> Result<&'a Recorded> {
    let entry = recorded.get(index).ok_or_else(|| anyhow!("the captured sequence ended before {what}"))?;
    ensure!(entry.route == route, "the captured request for {what} was another route");
    Ok(entry)
}

/// The full attestation, against the live gate revision and pushed OID.
pub(super) fn verify(recorded: &[Recorded], chain: &Chain, list: &Value, fault: &Value, live: i64) -> Result<()> {
    // 1. Every request reached a named route, carried no Authorization and no
    // request left the loopback origin. Origin confinement is enforced in the
    // browser itself: the Playwright context route aborts any off-origin
    // request, and the fault page's route confines on its own; either aborts
    // the run, so an escaped request can never reach this adapter. Everything
    // after sign-in carries the browser cookie; the three anonymous steps are
    // exactly the sign-in redirect (an anonymous page may answer `303`), the
    // sign-in route itself (the public page and the form that creates the
    // session both precede the cookie), and the browser's own icon request,
    // which Chromium may issue cookie-less.
    for entry in recorded {
        ensure!(entry.route != Route::Other, "an unclassified page request reached the origin");
        ensure!(!entry.has_authorization, "a request to {} carried Authorization", entry.route.name());
        let anonymous = match entry.route {
            Route::WebBlob => entry.status == 303,
            Route::WebLogin | Route::Favicon => true,
            _ => false,
        };
        ensure!(entry.has_cookie || anonymous, "a page request to {} carried no browser cookie", entry.route.name());
    }

    // 2. Anonymous navigation is the origin's own sign-in redirect.
    let anonymous = recorded
        .iter()
        .position(|entry| entry.route == Route::WebBlob && !entry.has_cookie)
        .ok_or_else(|| anyhow!("the page never requested the anonymous page"))?;
    let anonymous = at(recorded, anonymous, Route::WebBlob, "the anonymous page")?;
    ensure!(anonymous.status == 303, "the anonymous page was not an origin 303");
    ensure!(
        anonymous.location.as_deref() == Some("/web/login?return_to=%2Fweb%2Fblob"),
        "the anonymous page did not redirect to sign in with its return_to"
    );

    // 3. The real form is the one sign-in route request answered with 303; the
    // public page precedes it and sends no cookie, so the status names it.
    let login = recorded
        .iter()
        .position(|entry| entry.route == Route::WebLogin && entry.status == 303)
        .ok_or_else(|| anyhow!("the page never submitted the sign-in form"))?;
    at(recorded, login, Route::WebLogin, "the sign-in form")?;

    // 4. The signed-in page is the shell itself, under its CSP.
    let shell = recorded
        .iter()
        .position(|entry| entry.route == Route::WebBlob && entry.has_cookie)
        .ok_or_else(|| anyhow!("the page never loaded the signed-in page"))?;
    ensure!(shell > login, "the signed-in page was requested before the sign-in form");
    let shell = at(recorded, shell, Route::WebBlob, "the signed-in page")?;
    ensure!(shell.status == 200, "the signed-in page was not an origin 200");
    ensure!(
        shell.csp.as_deref().is_some_and(|csp| csp.contains("script-src 'self'")),
        "the signed-in page lacked its shell CSP"
    );

    // 5. The index list is a cookie-authorized, headerless read: no session
    // token or revision in either direction, and the real answer is the bare
    // array naming exactly the fixture repository.
    let list_read = at(recorded, find(recorded, Route::WebList, 0, "the list")?, Route::WebList, "the list")?;
    ensure!(list_read.status == 200, "the repository list was refused");
    ensure!(
        list_read.request_token.is_none() && list_read.request_revision.is_none(),
        "the list request presented a session"
    );
    ensure!(
        list_read.response_token.is_none() && list_read.response_revision.is_none(),
        "the list answer carried a session header"
    );
    ensure!(list_read.list_names_repository, "the list answer did not name exactly the fixture repository");

    // 6. The first repository page's refs starts the chain: unbound, with a
    // complete positive answer pair.
    let refs = at(recorded, find(recorded, Route::WebRefs, 0, "refs")?, Route::WebRefs, "refs")?;
    ensure!(refs.status == 200, "the first refs read was refused");
    ensure!(
        refs.request_token.is_none() && refs.request_revision.is_none(),
        "the first refs request presented a bound"
    );
    let refs_pair = Pair::of(refs, "the first refs answer")?;

    // 7. Tree presents exactly the refs token and no revision; its own answer
    // pair is complete and never below the refs revision; the tree really
    // listed the pushed file at the exact path under `?oid=HEAD`.
    let tree = at(recorded, find(recorded, Route::WebTree, 0, "the tree")?, Route::WebTree, "the tree")?;
    ensure!(tree.status == 200, "the tree read was refused");
    refs_pair.presented_by(tree, "the tree request")?;
    ensure!(tree.oid_head, "the tree request did not ask for the pushed HEAD");
    ensure!(tree.tree_names_file, "the tree answer did not list the pushed file");
    let tree_pair = Pair::of(tree, "the tree answer")?;
    ensure!(tree_pair.revision >= refs_pair.revision, "the tree answer regressed below the refs revision");

    // 8. Commits presents exactly the tree token and no revision; its pair is
    // complete, never below the tree revision and never ahead of the live gate.
    let commits = at(recorded, find(recorded, Route::WebCommits, 0, "commits")?, Route::WebCommits, "commits")?;
    ensure!(commits.status == 200, "the commits read was refused");
    tree_pair.presented_by(commits, "the commits request")?;
    ensure!(commits.commits_names_oid, "the commits answer did not list the pushed commit");
    let commits_pair = Pair::of(commits, "the commits answer")?;
    ensure!(commits_pair.revision >= tree_pair.revision, "the commits answer regressed below the tree revision");
    ensure!(commits_pair.revision <= live, "the commits answer is ahead of the live gate");

    // 9. The page's independent, cookie-only reads of the bearer-only routes
    // are denied with the established status; no Authorization was sent.
    for (route, expected) in [(Route::ApiRepos, 401), (Route::Git, 401)] {
        let denial = at(recorded, find(recorded, route, 0, route.name())?, route, route.name())?;
        ensure!(denial.has_cookie && !denial.has_authorization, "the {} read was not cookie-only", route.name());
        ensure!(denial.status == expected, "the cookie-only {} read was not denied with {expected}", route.name());
    }

    // 10. The fault page is a separate full navigation: its second refs read
    // is unbound exactly like the first page's, and its real refs answer is the
    // complete pair the page's synthetic tree is built from. That tree answer is
    // produced in the browser and never reaches the adapter, so the adapter
    // must hold exactly one real tree (the main chain) and one real commits
    // answer, and no further commits request may follow the fault refs.
    let fault_index = find(recorded, Route::WebRefs, 1, "the fault page refs")?;
    let fault_refs = at(recorded, fault_index, Route::WebRefs, "fault refs")?;
    ensure!(fault_refs.status == 200, "the fault page refs read was refused");
    ensure!(
        fault_refs.request_token.is_none() && fault_refs.request_revision.is_none(),
        "the fault page refs request presented a bound"
    );
    let fault_pair = Pair::of(fault_refs, "the fault page refs answer")?;
    ensure!(fault_pair.revision > 1, "the fault had no positive lower bound");
    ensure!(fault_pair.revision <= live, "the fault page refs answer is ahead of the live gate");
    ensure!(
        recorded.iter().filter(|entry| entry.route == Route::WebTree).count() == 1,
        "an unexpected tree read was made"
    );
    ensure!(
        recorded.iter().filter(|entry| entry.route == Route::WebCommits).count() == 1,
        "an unexpected commits read was made"
    );
    ensure!(
        !recorded[fault_index + 1..].iter().any(|entry| entry.route == Route::WebCommits),
        "a commits request began after the refused tree"
    );

    // 11. The page's own report agrees with the origin's answers: every captured
    // main-chain revision is the exact revision of the corresponding real
    // adapter answer, so the page's reads describe the network reads observed.
    // The chain's monotonicity is already checked by [`summary`], so no equality
    // between tree and refs is asserted here. The fault page's refs answer is
    // the one its injected revision was built from.
    ensure!(chain.refs_revision == refs_pair.revision, "the page did not report the refs revision");
    ensure!(chain.tree_revision == tree_pair.revision, "the page did not report the tree revision");
    ensure!(chain.commits_revision == commits_pair.revision, "the page did not report the commits revision");
    ensure!(fault["refs_revision"].as_i64() == Some(fault_pair.revision), "the page named another refs revision");
    ensure!(fault["synthetic_revision"].as_i64() == Some(fault_pair.revision - 1), "the page named another revision");
    page_fault(list, fault)
}

/// The page-only facts: the index list the shipped script read and accepted as
/// a bare array, and the synthetic fault answer's own booleans.
fn page_fault(list: &Value, fault: &Value) -> Result<()> {
    // The production list is a bare array after the adapter fix; the shipped
    // index read accepts it and the page renders the linked repository entry.
    ensure!(list["status"].as_u64() == Some(200), "the page did not see a successful list answer");
    ensure!(list["items_shape"].as_bool() == Some(true), "the page list answer changed shape");
    ensure!(list["accepted"].as_bool() == Some(true), "the shipped script did not accept the bare list array");
    ensure!(list["repository_link_clicked"].as_bool() == Some(true), "the page did not click the repository link");
    // The synthetic tree carries the fault page's refs token without a
    // request revision; its refusal renders no marker, tree or commits, and no
    // commits request begins.
    for flag in [
        "started",
        "fault_uses_refs_token",
        "fault_request_revision_absent",
        "refusal_shown",
        "marker_absent",
        "tree_absent",
        "commits_absent",
        "commits_not_requested",
    ] {
        ensure!(fault[flag].as_bool() == Some(true), "the fault page did not establish {flag}");
    }
    Ok(())
}
