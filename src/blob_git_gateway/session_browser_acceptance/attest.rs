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
    ensure!(summary["reads"]["partial_status_shown"].as_bool() == Some(true), "partial status was not observed");
    ensure!(summary["reads"]["load_more_completed"].as_bool() == Some(true), "Load more did not finish");
    ensure!(chain.commits_revision >= chain.refs_revision, "the reported commit read regressed");
    ensure!(chain.tree_revision >= chain.commits_revision, "the final Load more tree read regressed");
    ensure!(chain.tree_revision <= live, "a reported revision is ahead of the live gate");
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

    ensure!(
        recorded.iter().filter(|entry| entry.route == Route::WebList).count() == 2,
        "the list did not paginate across both pages"
    );
    let list_0 = at(recorded, find(recorded, Route::WebList, 0, "the list page 1")?, Route::WebList, "list page 1")?;
    ensure!(list_0.status == 200, "the repository list page 1 was refused");
    ensure!(list_0.request_token.is_none() && list_0.request_revision.is_none(), "list page 1 presented a session");
    ensure!(
        list_0.response_token.is_none() && list_0.response_revision.is_none(),
        "list page 1 carried a session header"
    );
    ensure!(!list_0.has_cursor_query && list_0.has_next_cursor_header, "list page 1 missed x-next-cursor pagination");
    ensure!(!list_0.list_names_repository, "target repository unexpectedly appeared on list page 1");

    let list_1 = at(recorded, find(recorded, Route::WebList, 1, "the list page 2")?, Route::WebList, "list page 2")?;
    ensure!(list_1.status == 200, "the repository list page 2 was refused");
    ensure!(list_1.request_token.is_none() && list_1.request_revision.is_none(), "list page 2 presented a session");
    ensure!(
        list_1.response_token.is_none() && list_1.response_revision.is_none(),
        "list page 2 carried a session header"
    );
    ensure!(list_1.has_cursor_query && !list_1.has_next_cursor_header, "list page 2 did not conclude pagination");
    ensure!(list_1.list_names_repository, "list page 2 did not name the fixture repository");

    let refs_0 = at(recorded, find(recorded, Route::WebRefs, 0, "refs page 1")?, Route::WebRefs, "refs page 1")?;
    ensure!(refs_0.status == 200, "the first refs read was refused");
    ensure!(
        refs_0.request_token.is_none() && refs_0.request_revision.is_none(),
        "the first refs request presented a bound"
    );
    ensure!(!refs_0.has_after_query && refs_0.body_has_next_after, "refs page 1 did not expose next_after");
    let refs_0_pair = Pair::of(refs_0, "the first refs answer")?;

    let refs_1 = at(recorded, find(recorded, Route::WebRefs, 1, "refs page 2")?, Route::WebRefs, "refs page 2")?;
    ensure!(refs_1.status == 200, "the second refs read was refused");
    ensure!(refs_1.has_after_query && !refs_1.body_has_next_after, "refs page 2 did not finish pagination");
    refs_0_pair.presented_by(refs_1, "the second refs request")?;
    let refs_1_pair = Pair::of(refs_1, "the second refs answer")?;
    ensure!(refs_1_pair.revision >= refs_0_pair.revision, "refs page 2 regressed");

    let tree_0 = at(recorded, find(recorded, Route::WebTree, 0, "tree page 1")?, Route::WebTree, "tree page 1")?;
    ensure!(tree_0.status == 200, "the first tree read was refused");
    refs_1_pair.presented_by(tree_0, "the first tree request")?;
    ensure!(tree_0.oid_head, "the first tree request did not ask for the pushed HEAD");
    ensure!(tree_0.tree_names_files, "the first tree page did not list both initial pushed files");
    ensure!(tree_0.body_has_next_after, "tree page 1 did not expose next_after");
    let mut prev_tree_pair = Pair::of(tree_0, "tree page 1 answer")?;
    ensure!(prev_tree_pair.revision >= refs_1_pair.revision, "tree page 1 regressed below refs");

    for occurrence in 1..5 {
        let entry = at(
            recorded,
            find(recorded, Route::WebTree, occurrence, "auto tree continuation")?,
            Route::WebTree,
            "tree continuation",
        )?;
        ensure!(entry.status == 200, "a tree continuation page was refused");
        ensure!(
            entry.tree_oid_head_after && entry.body_has_next_after,
            "auto tree continuation lacked after/next_after"
        );
        prev_tree_pair.presented_by(entry, "auto tree continuation")?;
        let next_pair = Pair::of(entry, "auto tree continuation answer")?;
        ensure!(next_pair.revision >= prev_tree_pair.revision, "auto tree continuation regressed");
        prev_tree_pair = next_pair;
    }

    let commits_0 =
        at(recorded, find(recorded, Route::WebCommits, 0, "commits page 1")?, Route::WebCommits, "commits page 1")?;
    ensure!(commits_0.status == 200, "commits page 1 was refused");
    prev_tree_pair.presented_by(commits_0, "the first commits request")?;
    ensure!(!commits_0.has_after_query && commits_0.body_has_next_after, "commits page 1 lacked next_after");
    ensure!(commits_0.commits_names_oid, "commits page 1 did not list the pushed HEAD commit");
    let commits_0_pair = Pair::of(commits_0, "commits page 1 answer")?;
    ensure!(commits_0_pair.revision >= prev_tree_pair.revision, "commits page 1 regressed below tree");

    let commits_1 =
        at(recorded, find(recorded, Route::WebCommits, 1, "commits page 2")?, Route::WebCommits, "commits page 2")?;
    ensure!(commits_1.status == 200, "commits page 2 was refused");
    commits_0_pair.presented_by(commits_1, "the second commits request")?;
    ensure!(commits_1.has_after_query && !commits_1.body_has_next_after, "commits page 2 did not finish pagination");
    let commits_1_pair = Pair::of(commits_1, "commits page 2 answer")?;
    ensure!(commits_1_pair.revision >= commits_0_pair.revision, "commits page 2 regressed");

    let tree_5 =
        at(recorded, find(recorded, Route::WebTree, 5, "tree Load more page 6")?, Route::WebTree, "tree Load more")?;
    ensure!(tree_5.status == 200, "tree Load more page 6 was refused");
    ensure!(tree_5.tree_oid_head_after && !tree_5.body_has_next_after, "tree page 6 did not terminate pagination");
    commits_1_pair.presented_by(tree_5, "tree Load more request")?;
    let tree_5_pair = Pair::of(tree_5, "tree Load more answer")?;
    ensure!(tree_5_pair.revision >= commits_1_pair.revision, "tree Load more answer regressed below commits");
    ensure!(tree_5_pair.revision <= live, "tree Load more answer is ahead of the live gate");

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

    let fault_0 =
        at(recorded, find(recorded, Route::WebRefs, 2, "fault refs page 1")?, Route::WebRefs, "fault refs 1")?;
    ensure!(fault_0.status == 200, "the fault page first refs read was refused");
    ensure!(
        fault_0.request_token.is_none() && fault_0.request_revision.is_none(),
        "the fault page first refs request presented a bound"
    );
    let fault_0_pair = Pair::of(fault_0, "the fault page first refs answer")?;

    let fault_index = find(recorded, Route::WebRefs, 3, "the fault page refs page 2")?;
    let fault_refs = at(recorded, fault_index, Route::WebRefs, "fault refs page 2")?;
    ensure!(fault_refs.status == 200, "the fault page second refs read was refused");
    fault_0_pair.presented_by(fault_refs, "the fault page second refs request")?;
    let fault_pair = Pair::of(fault_refs, "the fault page refs answer")?;
    ensure!(fault_pair.revision >= fault_0_pair.revision, "fault refs regressed across pages");
    ensure!(fault_pair.revision > 1, "the fault had no positive lower bound");
    ensure!(fault_pair.revision <= live, "the fault page refs answer is ahead of the live gate");
    ensure!(
        recorded.iter().filter(|entry| entry.route == Route::WebRefs).count() == 4,
        "an unexpected refs read was made"
    );
    ensure!(
        recorded.iter().filter(|entry| entry.route == Route::WebTree).count() == 6,
        "an unexpected tree read was made"
    );
    ensure!(
        recorded.iter().filter(|entry| entry.route == Route::WebCommits).count() == 2,
        "an unexpected commits read was made"
    );
    ensure!(
        !recorded[fault_index + 1..].iter().any(|entry| matches!(entry.route, Route::WebTree | Route::WebCommits)),
        "a tree or commits request reached the origin after fault refs"
    );

    ensure!(chain.refs_revision == refs_1_pair.revision, "the page did not report the refs revision");
    ensure!(chain.tree_revision == tree_5_pair.revision, "the page did not report the final tree revision");
    ensure!(chain.commits_revision == commits_1_pair.revision, "the page did not report the commits revision");
    ensure!(fault["refs_revision"].as_i64() == Some(fault_pair.revision), "the page named another refs revision");
    ensure!(fault["synthetic_revision"].as_i64() == Some(fault_pair.revision - 1), "the page named another revision");
    page_fault(list, fault)
}

fn page_fault(list: &Value, fault: &Value) -> Result<()> {
    ensure!(list["status"].as_u64() == Some(200), "the page did not see a successful list answer");
    ensure!(list["pages"].as_u64() == Some(2), "the page did not traverse both repository list pages");
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
