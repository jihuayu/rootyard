//! Independent attestation of what the origin really answered.
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

use super::capture::{DenialPath, Recorded, Route};

pub(super) struct Chain {
    pub refs_revision: i64,
    pub tree_revision: i64,
    pub commits_revision: i64,
    pub denials: Denials,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    DirectResponse,
    BasicChallengePending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GitDenial {
    Direct(u16),
    Pending { timeout_error: bool, elapsed_ms: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Denials {
    api: u16,
    git: GitDenial,
}

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

pub(super) fn reported_revision(summary: &Value, path: &[&str]) -> Result<i64> {
    let mut node = summary;
    for key in path {
        node = node.get(*key).ok_or_else(|| anyhow!("the page reported no session revision"))?;
    }
    node.as_i64().filter(|revision| *revision > 0).ok_or_else(|| anyhow!("the page reported no session revision"))
}

fn diagnostic_reason(summary: &Value) -> &str {
    let reason = summary["reason"].as_str().unwrap_or("");
    let safe = (1..=40).contains(&reason.len()) && reason.bytes().all(|byte| byte.is_ascii_uppercase() || byte == b'_');
    if safe { reason } else { "unknown" }
}

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

    fn presented_by(&self, entry: &Recorded, what: &'static str) -> Result<()> {
        ensure!(
            entry.request_token.as_deref() == Some(self.token.as_str()),
            "{what} did not present exactly the token"
        );
        ensure!(entry.request_revision.is_none(), "{what} presented a revision");
        Ok(())
    }
}

fn find(recorded: &[Recorded], route: Route, occurrence: usize, what: &'static str) -> Result<usize> {
    recorded
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.route == route)
        .nth(occurrence)
        .map(|(index, _)| index)
        .ok_or_else(|| anyhow!("the page never requested {what}"))
}

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

fn at<'a>(recorded: &'a [Recorded], index: usize, route: Route, what: &'static str) -> Result<&'a Recorded> {
    let entry = recorded.get(index).ok_or_else(|| anyhow!("the captured sequence ended before {what}"))?;
    ensure!(entry.route == route, "the captured request for {what} was another route");
    Ok(entry)
}

pub(super) fn verify(
    recorded: &[Recorded],
    chain: &Chain,
    denials: &Denials,
    list: &Value,
    fault: &Value,
    live: i64,
) -> Result<()> {
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

    let login = recorded
        .iter()
        .position(|entry| entry.route == Route::WebLogin && entry.status == 303)
        .ok_or_else(|| anyhow!("the page never submitted the sign-in form"))?;
    at(recorded, login, Route::WebLogin, "the sign-in form")?;

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

    let refs = at(recorded, find(recorded, Route::WebRefs, 0, "refs")?, Route::WebRefs, "refs")?;
    ensure!(refs.status == 200, "the first refs read was refused");
    ensure!(
        refs.request_token.is_none() && refs.request_revision.is_none(),
        "the first refs request presented a bound"
    );
    let refs_pair = Pair::of(refs, "the first refs answer")?;

    let tree = at(recorded, find(recorded, Route::WebTree, 0, "the tree")?, Route::WebTree, "the tree")?;
    ensure!(tree.status == 200, "the tree read was refused");
    refs_pair.presented_by(tree, "the tree request")?;
    ensure!(tree.oid_head, "the tree request did not ask for the pushed HEAD");
    ensure!(tree.tree_names_files, "the tree answer did not list both pushed files");
    let tree_pair = Pair::of(tree, "the tree answer")?;
    ensure!(tree_pair.revision >= refs_pair.revision, "the tree answer regressed below the refs revision");

    let commits = at(recorded, find(recorded, Route::WebCommits, 0, "commits")?, Route::WebCommits, "commits")?;
    ensure!(commits.status == 200, "the commits read was refused");
    tree_pair.presented_by(commits, "the commits request")?;
    ensure!(commits.commits_names_oid, "the commits answer did not list the pushed commit");
    let commits_pair = Pair::of(commits, "the commits answer")?;
    ensure!(commits_pair.revision >= tree_pair.revision, "the commits answer regressed below the tree revision");
    ensure!(commits_pair.revision <= live, "the commits answer is ahead of the live gate");

    single_denial(recorded, DenialPath::ApiRepos, Route::ApiRepos, 401, "bearer")?;
    ensure!(denials.api == 401, "the page did not report a direct 401 for its API read");

    match denials.git {
        GitDenial::Direct(401) => {
            single_denial(recorded, DenialPath::GitInfoRefs, Route::Git, 401, "basic")?;
        }
        GitDenial::Pending { .. } => {}
        GitDenial::Direct(_) => {
            return Err(anyhow!("the page did not report a direct 401 for its cookie-only Git read"));
        }
    }
    if let GitDenial::Pending { timeout_error, elapsed_ms } = denials.git {
        ensure!(timeout_error, "the page reported no TimeoutError for its pending Git read");
        ensure!(elapsed_ms >= 5_000, "the page's Git read timed out before its own 5000 ms boundary");
        single_denial(recorded, DenialPath::GitInfoRefs, Route::Git, 401, "basic")?;
    }

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

    ensure!(chain.refs_revision == refs_pair.revision, "the page did not report the refs revision");
    ensure!(chain.tree_revision == tree_pair.revision, "the page did not report the tree revision");
    ensure!(chain.commits_revision == commits_pair.revision, "the page did not report the commits revision");
    ensure!(fault["refs_revision"].as_i64() == Some(fault_pair.revision), "the page named another refs revision");
    ensure!(fault["synthetic_revision"].as_i64() == Some(fault_pair.revision - 1), "the page named another revision");
    page_fault(list, fault)
}

fn page_fault(list: &Value, fault: &Value) -> Result<()> {
    ensure!(list["status"].as_u64() == Some(200), "the page did not see a successful list answer");
    ensure!(list["items_shape"].as_bool() == Some(true), "the page list answer changed shape");
    ensure!(list["accepted"].as_bool() == Some(true), "the shipped script did not accept the bare list array");
    ensure!(list["repository_link_clicked"].as_bool() == Some(true), "the page did not click the repository link");
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
