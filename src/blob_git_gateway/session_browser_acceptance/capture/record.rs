use axum::http::{HeaderValue, header};
use serde_json::Value;

use crate::blob_git_gateway::repo_session::{REVISION_HEADER, SESSION_HEADER};

use super::Fixture;

const FAVICON: &str = "/favicon.ico";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum Route {
    WebBlob,
    WebLogin,
    WebAppJs,
    Favicon,
    WebList,
    WebRefs,
    WebTree,
    WebCommits,
    WebApiOther,
    ApiRepos,
    Git,
    Other,
}

impl Route {
    pub(in super::super) fn name(self) -> &'static str {
        match self {
            Self::WebBlob => "web_blob",
            Self::WebLogin => "web_login",
            Self::WebAppJs => "web_app_js",
            Self::Favicon => "favicon",
            Self::WebList => "web_list",
            Self::WebRefs => "web_refs",
            Self::WebTree => "web_tree",
            Self::WebCommits => "web_commits",
            Self::WebApiOther => "web_api_other",
            Self::ApiRepos => "api_repos",
            Self::Git => "git",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum DenialPath {
    ApiRepos,
    GitInfoRefs,
}

impl DenialPath {
    pub(in super::super) fn name(self) -> &'static str {
        match self {
            Self::ApiRepos => "api_repos",
            Self::GitInfoRefs => "git_info_refs",
        }
    }

    fn of(fixture: &Fixture, method: &str, path: &str, query: Option<&str>) -> Option<Self> {
        if method != "GET" {
            return None;
        }
        if path == "/api/repos" {
            return match query {
                None | Some("") => Some(Self::ApiRepos),
                Some(_) => None,
            };
        }
        if path == fixture.git_info_refs() {
            return match query {
                Some(query) if fixture.requests_git_info_refs(query) => Some(Self::GitInfoRefs),
                _ => None,
            };
        }
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Challenge {
    None,
    Basic,
    Bearer,
    Other,
}

impl Challenge {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Basic => "basic",
            Self::Bearer => "bearer",
            Self::Other => "other",
        }
    }

    fn of(answer: Option<&axum::http::HeaderMap>) -> Self {
        let Some(value) = answer.and_then(|answer| answer.get(header::WWW_AUTHENTICATE)) else {
            return Self::None;
        };
        let scheme = value.to_str().map(str::trim_start).unwrap_or("").split([' ', ',']).next().unwrap_or("");
        if scheme.eq_ignore_ascii_case("basic") {
            Self::Basic
        } else if scheme.eq_ignore_ascii_case("bearer") {
            Self::Bearer
        } else {
            Self::Other
        }
    }
}

pub(in super::super) struct Recorded {
    pub route: Route,
    pub status: u16,
    pub has_cookie: bool,
    pub has_authorization: bool,
    pub challenge: &'static str,
    pub denial_path: Option<DenialPath>,
    pub forwarding_failure: bool,
    pub request_token: Option<String>,
    pub request_revision: Option<String>,
    pub response_token: Option<String>,
    pub response_revision: Option<String>,
    pub oid_head: bool,
    pub tree_oid_head_after: bool,
    pub has_cursor_query: bool,
    pub has_after_query: bool,
    pub has_next_cursor_header: bool,
    pub body_has_next_after: bool,
    pub location: Option<String>,
    pub csp: Option<String>,
    pub list_names_repository: bool,
    pub tree_names_files: bool,
    pub commits_names_oid: bool,
}

pub(super) fn denial_of(fixture: &Fixture, parts: &axum::http::request::Parts) -> Option<DenialPath> {
    DenialPath::of(fixture, parts.method.as_str(), parts.uri.path(), parts.uri.query())
}

pub(super) fn record(
    fixture: &Fixture,
    request: &axum::http::request::Parts,
    route: Route,
    status: u16,
    answer: Option<&axum::http::HeaderMap>,
) -> Recorded {
    let headers = &request.headers;
    Recorded {
        route,
        status,
        has_cookie: headers.contains_key(header::COOKIE),
        has_authorization: headers.contains_key(header::AUTHORIZATION),
        challenge: Challenge::of(answer).name(),
        denial_path: denial_of(fixture, request),
        forwarding_failure: false,
        request_token: text(headers.get(SESSION_HEADER)),
        request_revision: text(headers.get(REVISION_HEADER)),
        response_token: answer.and_then(|answer| text(answer.get(SESSION_HEADER))),
        response_revision: answer.and_then(|answer| text(answer.get(REVISION_HEADER))),
        oid_head: route == Route::WebTree
            && request.uri.path() == fixture.read_path("tree")
            && tree_oid_is_head(request.uri.query()),
        tree_oid_head_after: route == Route::WebTree
            && request.uri.path() == fixture.read_path("tree")
            && tree_oid_is_head_after(request.uri.query()),
        has_cursor_query: query_has_param(request.uri.query(), "cursor"),
        has_after_query: query_has_param(request.uri.query(), "after"),
        has_next_cursor_header: answer.is_some_and(|answer| answer.contains_key("x-next-cursor")),
        body_has_next_after: false,
        location: answer.and_then(|answer| text(answer.get(header::LOCATION))),
        csp: answer.and_then(|answer| text(answer.get(header::CONTENT_SECURITY_POLICY))),
        list_names_repository: false,
        tree_names_files: false,
        commits_names_oid: false,
    }
}

fn tree_oid_is_head(query: Option<&str>) -> bool {
    query.is_some_and(|query| query.split('&').eq(["oid=HEAD"]))
}

fn tree_oid_is_head_after(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        let mut parts = query.split('&');
        matches!(
            (parts.next(), parts.next(), parts.next()),
            (Some("oid=HEAD"), Some(after), None) if after.strip_prefix("after=").is_some_and(|v| !v.is_empty())
        )
    })
}

fn query_has_param(query: Option<&str>, key: &str) -> bool {
    query.is_some_and(|query| {
        query.split('&').any(|pair| pair.split_once('=').is_some_and(|(name, value)| name == key && !value.is_empty()))
    })
}

pub(super) fn marker(fixture: &Fixture, bytes: &[u8], route: Route, record: &mut Recorded) {
    if !matches!(route, Route::WebList | Route::WebRefs | Route::WebTree | Route::WebCommits) {
        return;
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    match route {
        Route::WebList => {
            let Some(rows) = value.as_array() else {
                return;
            };
            let named = |row: &Value| {
                row["owner"].as_str() == Some(fixture.owner.as_str())
                    && row["name"].as_str() == Some(fixture.name.as_str())
            };
            record.list_names_repository = rows.iter().filter(|row| named(row)).count() == 1
                && rows.iter().filter(|row| row["name"].as_str() == Some(fixture.name.as_str())).count() == 1;
        }
        Route::WebRefs | Route::WebTree | Route::WebCommits => {
            record.body_has_next_after = value.get("next_after").is_some_and(|next| !next.is_null());
            let Some(rows) = value["items"].as_array() else {
                return;
            };
            if route == Route::WebTree {
                let named = |file: &str| rows.iter().any(|entry| entry["path"].as_str() == Some(file));
                record.tree_names_files = named(&fixture.file) && named(&fixture.second_file);
            } else if route == Route::WebCommits {
                record.commits_names_oid = rows.iter().any(|entry| entry["oid"].as_str() == Some(fixture.oid.as_str()));
            }
        }
        _ => {}
    }
}

fn text(value: Option<&HeaderValue>) -> Option<String> {
    value.and_then(|value| value.to_str().ok()).map(str::to_owned)
}

pub(super) fn route_of(fixture_prefix: &str, path: &str) -> Route {
    for (exact, route) in
        [("/web/blob/api/repos", Route::WebList), ("/web/app.js", Route::WebAppJs), (FAVICON, Route::Favicon)]
    {
        if path == exact {
            return route;
        }
    }
    for (tail, route) in [("refs", Route::WebRefs), ("tree", Route::WebTree), ("commits", Route::WebCommits)] {
        if path == format!("{fixture_prefix}{tail}") {
            return route;
        }
    }
    for (prefix, route) in [
        ("/web/login", Route::WebLogin),
        ("/web/blob/api/", Route::WebApiOther),
        ("/api/repos", Route::ApiRepos),
        ("/git/", Route::Git),
    ] {
        let descendant = format!("{}/", prefix.trim_end_matches('/'));
        if path == prefix || path.starts_with(&descendant) {
            return route;
        }
    }
    if path.trim_end_matches('/') == "/web/blob" || path.starts_with("/web/blob/repos/") {
        Route::WebBlob
    } else {
        Route::Other
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{
        Challenge, DenialPath, Fixture, Route, denial_of, marker, query_has_param, record, route_of, tree_oid_is_head,
        tree_oid_is_head_after,
    };

    fn fixture() -> Fixture {
        Fixture {
            owner: "owner".into(),
            name: "repo".into(),
            oid: "0".repeat(40),
            file: "afile.txt".into(),
            second_file: "other file.txt".into(),
            upstream: "http://127.0.0.1:1".into(),
        }
    }

    fn request(method: &str, uri: &str) -> axum::http::request::Parts {
        axum::http::Request::builder().method(method).uri(uri).body(()).unwrap().into_parts().0
    }

    fn answer(challenges: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for challenge in challenges {
            headers.append(header::WWW_AUTHENTICATE, HeaderValue::from_str(challenge).unwrap());
        }
        headers
    }

    #[test]
    fn the_tree_names_both_pushed_files_at_their_exact_paths() {
        let fixture = fixture();
        let first = fixture.file.clone();
        let second = fixture.second_file.clone();
        let tree = format!("{}?oid=HEAD", fixture.read_path("tree"));
        let mark = |entries: &[(&str, &str)]| {
            let items: Vec<serde_json::Value> =
                entries.iter().map(|(name, path)| serde_json::json!({"name": name, "path": path})).collect();
            let body = serde_json::to_vec(&serde_json::json!({"items": items})).unwrap();
            let mut recorded = record(&fixture, &request("GET", &tree), Route::WebTree, 200, None);
            marker(&fixture, &body, Route::WebTree, &mut recorded);
            recorded
        };
        let both = mark(&[(&first, &first), (&second, &second)]);
        assert!(both.tree_names_files);
        assert!(both.oid_head);
        assert!(!mark(&[(&first, &first)]).tree_names_files);
        let near = format!("prefix/{second}");
        assert!(!mark(&[(&first, &first), (&second, &near)]).tree_names_files);
        assert!(!mark(&[(&first, &first), (&second, &first)]).tree_names_files);
    }

    #[test]
    fn only_the_two_exact_denial_reads_classify() {
        let fixture = fixture();
        assert_eq!(denial_of(&fixture, &request("GET", "/api/repos")), Some(DenialPath::ApiRepos));
        let git = "/git/owner/repo.git/info/refs?service=git-upload-pack";
        assert_eq!(denial_of(&fixture, &request("GET", git)), Some(DenialPath::GitInfoRefs));
        for uri in [
            "/api/repos/owner/repo",
            "/api/repos?page=2",
            "/web/blob/api/repos",
            "/git/other/repo.git/info/refs?service=git-upload-pack",
            "/git/owner/repo/info/refs?service=git-upload-pack",
            "/git/owner/repo.git/info/refs?service=git-receive-pack",
            "/git/owner/repo.git/info/refs",
        ] {
            assert_eq!(denial_of(&fixture, &request("GET", uri)), None, "{uri}");
        }
        assert_eq!(denial_of(&fixture, &request("POST", "/api/repos")), None);
        assert_eq!(denial_of(&fixture, &request("HEAD", git)), None);
    }

    #[test]
    fn the_challenge_is_one_fixed_scheme_word() {
        assert_eq!(Challenge::of(None), Challenge::None);
        assert_eq!(Challenge::of(Some(&answer(&[]))), Challenge::None);
        assert_eq!(Challenge::of(Some(&answer(&["Basic realm=\"Rootyard\", charset=\"UTF-8\""]))), Challenge::Basic);
        assert_eq!(Challenge::of(Some(&answer(&["bearer realm=\"Rootyard\""]))), Challenge::Bearer);
        assert_eq!(
            Challenge::of(Some(&answer(&["Bearer realm=\"Rootyard\"", "Basic realm=\"Rootyard\""]))),
            Challenge::Bearer
        );
        assert_eq!(Challenge::of(Some(&answer(&["Negotiate"]))), Challenge::Other);
        let mut binary = HeaderMap::new();
        binary.append(header::WWW_AUTHENTICATE, HeaderValue::from_bytes(b"\xff\xfe").unwrap());
        assert_eq!(Challenge::of(Some(&binary)), Challenge::Other);
    }

    #[test]
    fn the_list_is_exact_and_nested_reads_are_distinct() {
        let prefix = fixture().alias_prefix();
        assert_eq!(prefix, "/web/blob/api/repos/owner/repo/");
        assert_eq!(route_of(&prefix, "/web/blob/api/repos"), Route::WebList);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/"), Route::WebApiOther);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo/refs"), Route::WebRefs);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo/tree"), Route::WebTree);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo/commits"), Route::WebCommits);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/other/repo/refs"), Route::WebApiOther);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo/blob"), Route::WebApiOther);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo_extra/refs"), Route::WebApiOther);
        assert!(tree_oid_is_head(Some("oid=HEAD")));
        assert!(!tree_oid_is_head(Some("oid=HEAD&path=a")));
        assert!(!tree_oid_is_head(Some("oid=HEAD&oid=HEAD")));
        assert!(!tree_oid_is_head(None));
        assert!(tree_oid_is_head_after(Some("oid=HEAD&after=z-pad-048.txt")));
        assert!(!tree_oid_is_head_after(Some("oid=HEAD&after=")));
        assert!(!tree_oid_is_head_after(Some("oid=HEAD")));
        assert!(query_has_param(Some("cursor=abc"), "cursor"));
        assert!(!query_has_param(Some("cursor="), "cursor"));
        assert_eq!(fixture().read_path("tree"), "/web/blob/api/repos/owner/repo/tree");
        for (path, route) in [
            ("/web/blob", Route::WebBlob),
            ("/web/blob/repos/owner/repo", Route::WebBlob),
            ("/web/login", Route::WebLogin),
            ("/web/app.js", Route::WebAppJs),
            ("/favicon.ico", Route::Favicon),
            ("/api/repos", Route::ApiRepos),
            ("/api/repos/owner/repo/refs", Route::ApiRepos),
            ("/git/owner/repo.git/info/refs", Route::Git),
            ("/", Route::Other),
        ] {
            assert_eq!(route_of(&prefix, path), route, "{path}");
        }
    }
}
