//! Canonical repository alias resolution and HTTP redirect rewriting (#85).
use crate::{Error, db};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Route family for a repository-scoped HTTP request path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepoRouteKind {
    Git,
    PinnedCiGit,
    Lfs,
    Api,
    Web,
}

/// Zero-copy breakdown of a repository-scoped HTTP request path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedRepoPath<'a> {
    pub kind: RepoRouteKind,
    pub owner: &'a str,
    pub name: &'a str,
    prefix: &'a str,
    git_suffix: &'a str,
    tail: &'a str,
}

impl<'a> ParsedRepoPath<'a> {
    /// Rewrite this parsed path to `(new_owner, new_name)`, preserving route family,
    /// `.git` suffix presence, path tail, and query string.
    pub fn rewrite_to(&self, query: Option<&str>, new_owner: &str, new_name: &str) -> Result<String, Error> {
        if !valid_segment(new_owner) || !valid_segment(new_name) {
            return Err(Error::bad_request());
        }
        let target =
            append_query(format!("{}{new_owner}/{new_name}{}{}", self.prefix, self.git_suffix, self.tail), query);
        safe_relative_target(&target)?;
        Ok(target)
    }

    pub fn tail(&self) -> &'a str {
        self.tail
    }

    pub fn ci_pin(&self) -> Option<&'a str> {
        if self.kind != RepoRouteKind::PinnedCiGit {
            return None;
        }
        self.prefix.strip_prefix("/ci/")?.strip_suffix("/git/")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRepoRoute {
    pub requested_owner: String,
    pub requested_name: String,
    pub canonical_owner: String,
    pub canonical_name: String,
    pub is_alias: bool,
}

impl ResolvedRepoRoute {
    pub fn canonical_prefix_git(&self) -> String {
        format!("/git/{}/{}.git", self.canonical_owner, self.canonical_name)
    }

    pub fn canonical_prefix_api(&self) -> String {
        format!("/api/repos/{}/{}", self.canonical_owner, self.canonical_name)
    }

    pub fn canonical_prefix_web(&self) -> String {
        format!("/web/repos/{}/{}", self.canonical_owner, self.canonical_name)
    }
}

fn valid_segment(s: &str) -> bool {
    db::valid_name(s)
}

fn split_two_segments(rest: &str) -> Option<(&str, &str, &str)> {
    let (seg1, after1) = rest.split_once('/')?;
    let (seg2, tail) = match after1.find('/') {
        Some(idx) => (&after1[..idx], &after1[idx..]),
        None => (after1, ""),
    };
    if seg1.is_empty() || seg2.is_empty() {
        return None;
    }
    Some((seg1, seg2, tail))
}

fn strip_git_suffix(raw_name: &str) -> (&str, &str) {
    match raw_name.strip_suffix(".git") {
        Some(base) => (base, ".git"),
        None => (raw_name, ""),
    }
}

fn is_lfs_tail(tail: &str) -> bool {
    matches!(tail, "/info/lfs" | "/lfs") || tail.starts_with("/info/lfs/") || tail.starts_with("/lfs/")
}

fn is_valid_pin_segment(pin: &str) -> bool {
    !pin.is_empty() && !pin.contains('\\') && !pin.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// Parse any repository-scoped HTTP URL path across Git Smart HTTP, pinned CI
/// mirrors, Git LFS, REST API (`/api/repos/{owner}/{name}...`), and Web UI
/// (`/web/repos/{owner}/{name}...`, `/ui/repos/{owner}/{name}...`).
pub fn parse_repo_scoped_path(path: &str) -> Option<ParsedRepoPath<'_>> {
    if let Some(rest) = path.strip_prefix("/api/repos/") {
        let (owner, raw_name, tail) = split_two_segments(rest)?;
        let (name, git_suffix) = if is_lfs_tail(tail) { strip_git_suffix(raw_name) } else { (raw_name, "") };
        if !valid_segment(owner) || !valid_segment(name) {
            return None;
        }
        let kind = if is_lfs_tail(tail) { RepoRouteKind::Lfs } else { RepoRouteKind::Api };
        return Some(ParsedRepoPath { kind, owner, name, prefix: "/api/repos/", git_suffix, tail });
    }
    for prefix in ["/web/repos/", "/ui/repos/"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            let (owner, name, tail) = split_two_segments(rest)?;
            if !valid_segment(owner) || !valid_segment(name) {
                return None;
            }
            return Some(ParsedRepoPath { kind: RepoRouteKind::Web, owner, name, prefix, git_suffix: "", tail });
        }
    }
    if let Some(rest) = path.strip_prefix("/git/") {
        let (owner, raw_name, tail) = split_two_segments(rest)?;
        let (name, git_suffix) = strip_git_suffix(raw_name);
        if !valid_segment(owner) || !valid_segment(name) {
            return None;
        }
        let git_gateway_tail = matches!(tail, "/info/refs" | "/git-upload-pack" | "/git-receive-pack");
        if git_suffix.is_empty() && !is_lfs_tail(tail) && !git_gateway_tail {
            return None;
        }
        let kind = if is_lfs_tail(tail) { RepoRouteKind::Lfs } else { RepoRouteKind::Git };
        return Some(ParsedRepoPath { kind, owner, name, prefix: "/git/", git_suffix, tail });
    }
    if let Some(after_ci) = path.strip_prefix("/ci/") {
        let (pin, after_pin) = after_ci.split_once('/')?;
        if !is_valid_pin_segment(pin) {
            return None;
        }
        let after_git = after_pin.strip_prefix("git/")?;
        let prefix = &path[.."/ci/".len() + pin.len() + "/git/".len()];
        let (owner, raw_name, tail) = split_two_segments(after_git)?;
        let (name, git_suffix) = strip_git_suffix(raw_name);
        if !valid_segment(owner) || !valid_segment(name) || (git_suffix.is_empty() && !is_lfs_tail(tail)) {
            return None;
        }
        let kind = if is_lfs_tail(tail) { RepoRouteKind::Lfs } else { RepoRouteKind::PinnedCiGit };
        return Some(ParsedRepoPath { kind, owner, name, prefix, git_suffix, tail });
    }
    if let Some(rest) = path.strip_prefix('/') {
        let (owner, raw_name, tail) = split_two_segments(rest)?;
        if !(tail == "/info/lfs" || tail.starts_with("/info/lfs/")) {
            return None;
        }
        if matches!(owner, "api" | "web" | "ui" | "git" | "ci") {
            return None;
        }
        let (name, git_suffix) = strip_git_suffix(raw_name);
        if !valid_segment(owner) || !valid_segment(name) {
            return None;
        }
        return Some(ParsedRepoPath { kind: RepoRouteKind::Lfs, owner, name, prefix: "/", git_suffix, tail });
    }
    None
}

fn safe_relative_target(location: &str) -> Result<(), Error> {
    if !location.starts_with('/')
        || location.starts_with("//")
        || location.starts_with("/\\")
        || location.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'\\')
    {
        return Err(Error::bad_request());
    }
    Ok(())
}

fn append_query(base: String, query: Option<&str>) -> String {
    match query.filter(|q| !q.is_empty()) {
        Some(q) => format!("{base}?{q}"),
        None => base,
    }
}

fn rewrite_filtered(
    path: &str,
    query: Option<&str>,
    old_owner: &str,
    old_name: &str,
    new_owner: &str,
    new_name: &str,
    accept: fn(&ParsedRepoPath<'_>) -> bool,
) -> Result<String, Error> {
    if !valid_segment(old_owner) || !valid_segment(old_name) || !valid_segment(new_owner) || !valid_segment(new_name) {
        return Err(Error::bad_request());
    }
    let parsed = parse_repo_scoped_path(path).ok_or_else(Error::not_found)?;
    if parsed.owner != old_owner || parsed.name != old_name || !accept(&parsed) {
        return Err(Error::not_found());
    }
    parsed.rewrite_to(query, new_owner, new_name)
}

/// Rewrite a Git Smart HTTP or pinned-CI mirror alias path onto its canonical
/// path while preserving query parameters.
pub fn rewrite_git_location(
    path: &str,
    query: Option<&str>,
    old_owner: &str,
    old_name: &str,
    new_owner: &str,
    new_name: &str,
) -> Result<String, Error> {
    rewrite_filtered(path, query, old_owner, old_name, new_owner, new_name, |p| {
        p.prefix == "/git/" || p.prefix.starts_with("/ci/")
    })
}

/// Rewrite a Git LFS alias path across `/git/.../info/lfs/...`, `/{owner}/{name}/info/lfs/...`,
/// `/api/repos/.../lfs/...`, `/api/repos/.../info/lfs/...`, and `/ci/{target}/git/.../info/lfs/...`.
pub fn rewrite_lfs_location(
    path: &str,
    query: Option<&str>,
    old_owner: &str,
    old_name: &str,
    new_owner: &str,
    new_name: &str,
) -> Result<String, Error> {
    rewrite_filtered(path, query, old_owner, old_name, new_owner, new_name, |p| p.kind == RepoRouteKind::Lfs)
}

/// Rewrite an API alias path (`/api/repos/{old}/{old}...`) to `/api/repos/{new}/{new}...`.
pub fn rewrite_api_location(
    path: &str,
    query: Option<&str>,
    old_owner: &str,
    old_name: &str,
    new_owner: &str,
    new_name: &str,
) -> Result<String, Error> {
    rewrite_filtered(path, query, old_owner, old_name, new_owner, new_name, |p| p.prefix == "/api/repos/")
}

/// Rewrite a Web UI alias path (`/web/repos/{old}/{old}...` or `/ui/repos/{old}/{old}...`)
/// onto the matching canonical Web/UI prefix.
pub fn rewrite_web_location(
    path: &str,
    query: Option<&str>,
    old_owner: &str,
    old_name: &str,
    new_owner: &str,
    new_name: &str,
) -> Result<String, Error> {
    rewrite_filtered(path, query, old_owner, old_name, new_owner, new_name, |p| p.kind == RepoRouteKind::Web)
}

/// Build a method-preserving `308 Permanent Redirect` response with `Cache-Control: no-store`.
pub fn permanent_redirect_response(location: &str) -> Result<Response, Error> {
    safe_relative_target(location)?;
    let value = HeaderValue::from_str(location).map_err(Error::internal)?;
    Ok((
        StatusCode::PERMANENT_REDIRECT,
        [(header::LOCATION, value), (header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_lfs_api_and_web_alias_rewrites_preserve_paths_and_queries() {
        assert_eq!(
            rewrite_git_location(
                "/git/alice/old-repo.git/info/refs",
                Some("service=git-upload-pack"),
                "alice",
                "old-repo",
                "acme",
                "new-repo",
            )
            .unwrap(),
            "/git/acme/new-repo.git/info/refs?service=git-upload-pack"
        );
        assert_eq!(
            rewrite_git_location(
                "/ci/main/git/alice/old-repo.git/info/refs",
                Some("service=git-upload-pack"),
                "alice",
                "old-repo",
                "acme",
                "new-repo",
            )
            .unwrap(),
            "/ci/main/git/acme/new-repo.git/info/refs?service=git-upload-pack"
        );
        assert_eq!(
            rewrite_lfs_location(
                "/git/alice/old-repo.git/info/lfs/objects/batch",
                None,
                "alice",
                "old-repo",
                "acme",
                "new-repo",
            )
            .unwrap(),
            "/git/acme/new-repo.git/info/lfs/objects/batch"
        );
        assert_eq!(
            rewrite_lfs_location("/git/alice/old-repo/info/lfs/locks", None, "alice", "old-repo", "acme", "new-repo")
                .unwrap(),
            "/git/acme/new-repo/info/lfs/locks"
        );
        assert_eq!(
            rewrite_lfs_location(
                "/alice/old-repo/info/lfs/objects/batch",
                None,
                "alice",
                "old-repo",
                "acme",
                "new-repo"
            )
            .unwrap(),
            "/acme/new-repo/info/lfs/objects/batch"
        );
        assert_eq!(
            rewrite_lfs_location(
                "/api/repos/alice/old-repo/info/lfs/objects/abcd",
                None,
                "alice",
                "old-repo",
                "acme",
                "new-repo",
            )
            .unwrap(),
            "/api/repos/acme/new-repo/info/lfs/objects/abcd"
        );
        assert_eq!(
            rewrite_api_location(
                "/api/repos/alice/old-repo/issues",
                Some("state=open"),
                "alice",
                "old-repo",
                "acme",
                "new-repo",
            )
            .unwrap(),
            "/api/repos/acme/new-repo/issues?state=open"
        );
        assert_eq!(
            rewrite_api_location("/api/repos/alice/old-repo", None, "alice", "old-repo", "acme", "new-repo").unwrap(),
            "/api/repos/acme/new-repo"
        );
        assert_eq!(
            rewrite_web_location(
                "/web/repos/alice/old-repo/pulls/1",
                Some("tab=diff"),
                "alice",
                "old-repo",
                "acme",
                "new-repo",
            )
            .unwrap(),
            "/web/repos/acme/new-repo/pulls/1?tab=diff"
        );
        assert_eq!(
            rewrite_web_location("/ui/repos/alice/old-repo", None, "alice", "old-repo", "acme", "new-repo").unwrap(),
            "/ui/repos/acme/new-repo"
        );
    }

    #[test]
    fn parse_ignores_non_repo_routes_and_rejects_open_redirects() {
        assert_eq!(parse_repo_scoped_path("/api/repos"), None);
        assert_eq!(parse_repo_scoped_path("/web/repos"), None);
        assert_eq!(parse_repo_scoped_path("/api/auth/whoami"), None);
        assert_eq!(parse_repo_scoped_path("/alice/other-page"), None);
        assert!(
            rewrite_api_location("/api/repos/alice/old-repo2/issues", None, "alice", "old-repo", "acme", "new-repo")
                .is_err()
        );
        assert!(safe_relative_target("//evil.example/a").is_err());
        assert!(safe_relative_target("/ok\r\nX-Test: 1").is_err());
        assert!(permanent_redirect_response("/git/acme/new.git/info/refs").is_ok());
    }
}
