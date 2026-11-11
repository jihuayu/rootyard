//! Independent attestation of what the origin really answered.
//!
//! The Rust side never trusts the page's own labels for any fact the adapter
//! observed: every upstream fact below comes from the [`Recorded`] entries the
//! adapter captured, or from the live gate revision read through PostgreSQL.
//! The page-only facts are checked where only the browser can observe them, and
//! each is fixed: the synthetic fault tree answer is produced in the browser and
//! never reaches the adapter, and a cookie-only Smart HTTP denial is reported
//! with its own fixed outcome, which is always correlated with the independently
//! captured upstream request and response.
//!
//! Session token strings are compared in memory only and are never formatted
//! into a message; the same holds for the API token.
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

use super::capture::{DenialPath, Recorded, Route};

/// The session revisions the page reported for its read chain, and its fixed
/// cookie-only denial outcomes as sanitized, typed values.
pub(super) struct Chain {
    pub refs_revision: i64,
    pub tree_revision: i64,
    pub commits_revision: i64,
    pub denials: Denials,
}

/// The page's classification of one cookie-only read. Only these fixed words
/// are ever read from the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    DirectResponse,
    BasicChallengePending,
}

/// The page's own fixed outcome of one cookie-only Smart HTTP read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GitDenial {
    /// The page's Fetch resolved; the actual status it reported is kept.
    Direct(u16),
    /// The page's own `AbortSignal.timeout` fired, after `elapsed_ms`.
    Pending { timeout_error: bool, elapsed_ms: u64 },
}

/// The page's fixed cookie-only denial outcomes: the API read, which must be a
/// direct response, and the Smart HTTP read, which is a direct response or a
/// pending Basic challenge. Nothing else of the report is retained here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Denials {
    api: u16,
    git: GitDenial,
}

/// Whether one report object has exactly these fixed keys and nothing else.
fn exactly(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)))
}

fn outcome(value: &Value, what: &'static str) -> Result<Outcome> {
    match value.as_str() {
        Some("direct_response") => Ok(Outcome::DirectResponse),
        Some("basic_challenge_pending") => Ok(Outcome::BasicChallengePending),
        _ => Err(anyhow!("the page reported no fixed {what} denial classification")),
    }
}

impl Denials {
    /// The denial outcomes exactly as the page reported them: each object has
    /// exactly its three fixed keys, the API read is a direct response, and the
    /// Smart HTTP read is a direct response or the page's own timeout.
    fn reported(denials: &Value) -> Result<Self> {
        let shape = ["classification", "status", "abort"];
        let api = &denials["api"];
        ensure!(exactly(api, &shape), "the page reported another API denial shape");
        ensure!(
            outcome(&api["classification"], "API")? == Outcome::DirectResponse,
            "the page reported a non-direct API denial"
        );
        ensure!(api["abort"].is_null(), "the page reported an abort for a direct API read");
        let api = api["status"]
            .as_u64()
            .and_then(|status| u16::try_from(status).ok())
            .ok_or_else(|| anyhow!("the page reported no API denial status"))?;

        let git = &denials["git"];
        ensure!(exactly(git, &shape), "the page reported another Git denial shape");
        let git = match outcome(&git["classification"], "Git")? {
            Outcome::DirectResponse => {
                ensure!(git["abort"].is_null(), "the page reported an abort for a direct Git read");
                let status = git["status"]
                    .as_u64()
                    .and_then(|status| u16::try_from(status).ok())
                    .ok_or_else(|| anyhow!("the page reported no Git denial status"))?;
                GitDenial::Direct(status)
            }
            Outcome::BasicChallengePending => {
                ensure!(git["status"].is_null(), "the page reported a status for a pending Git read");
                let abort = &git["abort"];
                ensure!(exactly(abort, &["reason", "elapsed_ms"]), "the page reported another pending challenge shape");
                let elapsed_ms = abort["elapsed_ms"].as_u64();
                let elapsed_ms = elapsed_ms.ok_or_else(|| anyhow!("the page reported no integer elapsed time"))?;
                GitDenial::Pending { timeout_error: abort["reason"].as_str() == Some("timeout_error"), elapsed_ms }
            }
        };
        Ok(Self { api, git })
    }
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
/// status of every route, the cookie-only denial outcomes, and the reported
/// chain revisions, each bounded by the live gate. The fault page's reported
/// revisions are cross-checked against its captured refs answer in [`verify`],
/// never against the main chain. No identity or credential is part of the
/// summary; the denial outcomes are fixed words, a status and one bounded
/// integer.
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
        denials: Denials::reported(&summary["denials"])?,
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

/// The one record of an exact denial read: the captured requests of that fixed
/// request shape, on the route it names, which must be a real upstream answer
/// (never a forwarding failure). More than one such request is a replay and no
/// single record speaks for the page's read.
fn denials(recorded: &[Recorded], shape: DenialPath, route: Route) -> Result<Vec<&Recorded>> {
    let matching: Vec<&Recorded> = recorded.iter().filter(|entry| entry.denial_path == Some(shape)).collect();
    ensure!(!matching.is_empty(), "the page never requested the {} denial", shape.name());
    ensure!(
        matching.iter().all(|entry| entry.route == route),
        "the {} denial was captured on another route",
        shape.name()
    );
    ensure!(
        matching.iter().all(|entry| !entry.forwarding_failure),
        "the {} denial was not relayed to the origin",
        shape.name()
    );
    Ok(matching)
}

/// The one answer to the `shape` denial and its fixed status, cookie and
/// challenge facts. Exactly one captured request of the shape makes the
/// answer; any other count is another request and can never stand in for it.
fn single_denial<'a>(
    recorded: &'a [Recorded],
    shape: DenialPath,
    route: Route,
    status: u16,
    challenge: &'static str,
) -> Result<&'a Recorded> {
    let findings = denials(recorded, shape, route)?;
    ensure!(findings.len() == 1, "the page requested the {} denial more than once", shape.name());
    let denial = findings[0];
    ensure!(denial.status == status, "the cookie-only {} read was not denied with {status}", shape.name());
    ensure!(denial.has_cookie, "the {} read was not cookie-only", shape.name());
    ensure!(!denial.has_authorization, "the {} read carried Authorization", shape.name());
    ensure!(
        denial.challenge == challenge,
        "the cookie-only {} denial carried no upstream {challenge} challenge",
        shape.name()
    );
    Ok(denial)
}

/// The captured request at one position, which must be the expected route.
fn at<'a>(recorded: &'a [Recorded], index: usize, route: Route, what: &'static str) -> Result<&'a Recorded> {
    let entry = recorded.get(index).ok_or_else(|| anyhow!("the captured sequence ended before {what}"))?;
    ensure!(entry.route == route, "the captured request for {what} was another route");
    Ok(entry)
}

/// The full attestation, against the live gate revision, the pushed OID and
/// the page's already-validated cookie-only denial outcomes.
pub(super) fn verify(
    recorded: &[Recorded],
    chain: &Chain,
    denials: &Denials,
    list: &Value,
    fault: &Value,
    live: i64,
) -> Result<()> {
    // 1. Every request reached a named route, no relayed request failed and no
    // request left the loopback origin. Origin confinement is enforced in the
    // browser itself: the Playwright context route aborts any off-origin
    // request, and the fault page's route confines on its own; either aborts
    // the run, so an escaped request can never reach this adapter. No request
    // of any route carries Authorization except a request the adapter classified
    // as one of the two exact denial reads, which step 9 then requires to carry
    // none; every other route stays headerless in that respect. Everything
    // after sign-in carries the browser cookie; the
    // three anonymous steps are exactly the sign-in redirect (an anonymous page
    // may answer `303`), the sign-in route itself (the public page and the form
    // that creates the session both precede the cookie), and the browser's own
    // icon request, which Chromium may issue cookie-less.
    for entry in recorded {
        ensure!(entry.route != Route::Other, "an unclassified page request reached the origin");
        ensure!(!entry.forwarding_failure, "a page request to {} could not be relayed", entry.route.name());
        ensure!(
            !entry.has_authorization || entry.denial_path.is_some(),
            "a request to {} carried Authorization",
            entry.route.name()
        );
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
    ensure!(tree.tree_names_files, "the tree answer did not list both pushed files");
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
    // were denied by the origin itself, and each page outcome is correlated
    // with the adapter's own record of that exact request and answer: exactly
    // one exact `GET /api/repos` and one exact Smart HTTP `info/refs` request,
    // each answered `401`, carrying a browser cookie, no Authorization and an
    // upstream challenge (Bearer for the JSON API, Basic for Smart HTTP). The
    // page cannot pass by reporting a denial of another route, a forwarding
    // failure or an arbitrary status: the record must agree with its fixed
    // outcome.
    single_denial(recorded, DenialPath::ApiRepos, Route::ApiRepos, 401, "bearer")?;
    ensure!(denials.api == 401, "the page did not report a direct 401 for its API read");

    // The page's Smart HTTP outcome, correlated with the same upstream facts.
    match denials.git {
        // The page's own Fetch resolved with the actual denial, and the origin
        // answered exactly one such request.
        GitDenial::Direct(401) => {
            single_denial(recorded, DenialPath::GitInfoRefs, Route::Git, 401, "basic")?;
        }
        // Still waiting on the origin's challenge: proven below, never here.
        GitDenial::Pending { .. } => {}
        // Any other status the page read is not the origin's denial.
        GitDenial::Direct(_) => {
            return Err(anyhow!("the page did not report a direct 401 for its cookie-only Git read"));
        }
    }
    // A pending Basic challenge is the only other accepted outcome: the page's
    // own TimeoutError, past the configured boundary, while the origin's one 401
    // with its Basic challenge is still the correlated upstream fact.
    if let GitDenial::Pending { timeout_error, elapsed_ms } = denials.git {
        ensure!(timeout_error, "the page reported no TimeoutError for its pending Git read");
        ensure!(elapsed_ms >= 5_000, "the page's Git read timed out before its own 5000 ms boundary");
        single_denial(recorded, DenialPath::GitInfoRefs, Route::Git, 401, "basic")?;
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
