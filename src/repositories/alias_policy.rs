//! Surface-parity authorization policy and bounded payload inspection for alias redirects (#85).
use super::alias::{ParsedRepoPath, RepoRouteKind};
use crate::{Error, members::models::Role, pulls::models::valid_review_state, token_scopes::RepoAction};
use axum::{
    body::Body,
    http::{Method, StatusCode},
};

const MAX_LFS_BATCH_ALIAS_BODY: usize = 1024 * 1024;
const MAX_REVIEW_ALIAS_BODY: usize = 64 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct AliasRequestInspect {
    pub(super) lfs_batch_op: Option<String>,
    pub(super) pull_review_state: Option<String>,
}

pub(super) fn query_has_service_receive_pack(query: Option<&str>) -> bool {
    query.is_some_and(|raw| {
        raw.split('&').any(|pair| pair.split_once('=').is_some_and(|(k, v)| k == "service" && v == "git-receive-pack"))
    })
}

pub(super) fn lfs_tail(tail: &str) -> &str {
    tail.strip_prefix("/info/lfs").or_else(|| tail.strip_prefix("/lfs")).unwrap_or(tail)
}

pub(super) fn is_lfs_batch_post(method: &Method, parsed: &ParsedRepoPath<'_>) -> bool {
    parsed.kind == RepoRouteKind::Lfs && *method == Method::POST && lfs_tail(parsed.tail()) == "/objects/batch"
}

fn is_pull_review_post_tail(method: &Method, tail: &str) -> bool {
    if *method != Method::POST {
        return false;
    }
    let Some(rest) = tail.strip_prefix("/pulls/") else {
        return false;
    };
    let Some((num, suffix)) = rest.split_once('/') else {
        return false;
    };
    suffix == "reviews" && !num.is_empty()
}

pub(super) fn is_pull_review_post(method: &Method, parsed: &ParsedRepoPath<'_>) -> bool {
    matches!(parsed.kind, RepoRouteKind::Api | RepoRouteKind::Web) && is_pull_review_post_tail(method, parsed.tail())
}

pub(super) fn body_inspect_limit(method: &Method, parsed: &ParsedRepoPath<'_>) -> Option<usize> {
    if is_lfs_batch_post(method, parsed) {
        Some(MAX_LFS_BATCH_ALIAS_BODY)
    } else if is_pull_review_post(method, parsed) {
        Some(MAX_REVIEW_ALIAS_BODY)
    } else {
        None
    }
}

pub(super) async fn inspect_alias_request(
    method: &Method,
    parsed: &ParsedRepoPath<'_>,
    body: Option<Body>,
) -> Result<AliasRequestInspect, Error> {
    let Some(limit) = body_inspect_limit(method, parsed) else {
        return Ok(AliasRequestInspect::default());
    };
    let Some(body) = body else {
        return Err(Error::bad_request());
    };
    let bytes = axum::body::to_bytes(body, limit)
        .await
        .map_err(|_| Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded"))?;
    let val: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| Error::bad_request())?;
    if is_lfs_batch_post(method, parsed) {
        let op = val.get("operation").and_then(|v| v.as_str()).ok_or_else(Error::bad_request)?;
        if !matches!(op, "upload" | "download") {
            return Err(Error::bad_request());
        }
        return Ok(AliasRequestInspect { lfs_batch_op: Some(op.to_owned()), pull_review_state: None });
    }
    let state = val.get("state").and_then(|v| v.as_str()).ok_or_else(Error::bad_request)?;
    if !valid_review_state(state) {
        return Err(Error::bad_request());
    }
    Ok(AliasRequestInspect { lfs_batch_op: None, pull_review_state: Some(state.to_owned()) })
}

fn review_role_and_action(review_state: Option<&str>) -> Result<(Role, RepoAction), Error> {
    match review_state {
        Some("commented") => Ok((Role::Triage, RepoAction::PullsWrite)),
        Some("approved" | "changes_requested") => Ok((Role::Write, RepoAction::PullsWrite)),
        _ => Err(Error::bad_request()),
    }
}

fn lfs_role_and_action(
    method: &Method,
    is_mutation: bool,
    tail: &str,
    batch_op: Option<&str>,
) -> Result<(Role, RepoAction), Error> {
    let sub = lfs_tail(tail);
    if sub == "/upload-waiters" {
        return if !is_mutation {
            Ok((Role::Admin, RepoAction::RepoRead))
        } else {
            Ok((Role::Admin, RepoAction::RepoAdmin))
        };
    }
    if sub == "/objects/batch" && *method == Method::POST {
        return match batch_op {
            Some("upload") => Ok((Role::Write, RepoAction::ContentsWrite)),
            Some("download") => Ok((Role::Read, RepoAction::ContentsRead)),
            _ => Err(Error::bad_request()),
        };
    }
    if is_mutation { Ok((Role::Write, RepoAction::ContentsWrite)) } else { Ok((Role::Read, RepoAction::ContentsRead)) }
}

fn web_role_and_action(
    method: &Method,
    is_mutation: bool,
    tail: &str,
    review_state: Option<&str>,
) -> Result<(Role, RepoAction), Error> {
    if !is_mutation {
        if tail == "/audit" {
            return Ok((Role::Maintain, RepoAction::MembersRead));
        }
        if tail.starts_with("/tree") || tail.starts_with("/blob") || tail == "/compare" {
            return Ok((Role::Read, RepoAction::ContentsRead));
        }
        if tail.starts_with("/commits") {
            let action = if tail.ends_with("/checks") { RepoAction::ChecksRead } else { RepoAction::ContentsRead };
            return Ok((Role::Read, action));
        }
        if tail.starts_with("/issues") {
            return Ok((Role::Read, RepoAction::IssuesRead));
        }
        if tail.starts_with("/pulls") {
            let action = if tail.ends_with("/checks") { RepoAction::ChecksRead } else { RepoAction::PullsRead };
            return Ok((Role::Read, action));
        }
        return Ok((Role::Read, RepoAction::RepoRead));
    }

    if tail.starts_with("/labels") {
        Ok((Role::Triage, RepoAction::IssuesWrite))
    } else if tail == "/subscription" {
        Ok((Role::Read, RepoAction::RepoRead))
    } else if tail.starts_with("/issues") {
        if tail.ends_with("/subscription") {
            Ok((Role::Read, RepoAction::IssuesRead))
        } else if tail.ends_with("/moderate") {
            Ok((Role::Maintain, RepoAction::IssuesWrite))
        } else {
            Ok((Role::Triage, RepoAction::IssuesWrite))
        }
    } else if tail.starts_with("/pulls") {
        if is_pull_review_post_tail(method, tail) {
            return review_role_and_action(review_state);
        }
        if tail.ends_with("/subscription") {
            Ok((Role::Read, RepoAction::PullsRead))
        } else if tail.ends_with("/moderate") {
            Ok((Role::Maintain, RepoAction::PullsWrite))
        } else if tail.ends_with("/labels")
            || tail.ends_with("/assignees")
            || tail.contains("/review-comments")
            || tail.ends_with("/reviews")
        {
            Ok((Role::Triage, RepoAction::PullsWrite))
        } else {
            Ok((Role::Write, RepoAction::PullsWrite))
        }
    } else {
        Ok((Role::Admin, RepoAction::RepoAdmin))
    }
}

fn api_role_and_action(
    method: &Method,
    is_mutation: bool,
    tail: &str,
    review_state: Option<&str>,
) -> Result<(Role, RepoAction), Error> {
    if !is_mutation {
        let action = if tail.starts_with("/issues") {
            RepoAction::IssuesRead
        } else if tail.starts_with("/pulls") || tail == "/branch-rules" || tail.starts_with("/branch-rules/") {
            RepoAction::PullsRead
        } else if tail.starts_with("/checks") || tail.starts_with("/check-runs") {
            RepoAction::ChecksRead
        } else if tail.starts_with("/webhooks") || tail.starts_with("/hooks") {
            RepoAction::HooksRead
        } else if tail.starts_with("/collaborators") || tail.starts_with("/teams") || tail.starts_with("/audit") {
            RepoAction::MembersRead
        } else if tail.starts_with("/workspaces") {
            RepoAction::WorkspacesRead
        } else if tail.starts_with("/tree")
            || tail.starts_with("/blob")
            || tail.starts_with("/commits")
            || tail.starts_with("/branches")
            || tail.starts_with("/tags")
            || tail.starts_with("/compare")
            || tail.starts_with("/archive")
        {
            RepoAction::ContentsRead
        } else {
            RepoAction::RepoRead
        };
        return Ok((Role::Read, action));
    }

    if (*method == Method::DELETE && tail.is_empty())
        || matches!(tail, "/archive" | "/unarchive" | "/rename" | "/restore" | "/purge" | "/transfer")
        || tail.starts_with("/aliases")
        || tail.starts_with("/storage-backend")
    {
        return Ok((Role::Admin, RepoAction::RepoAdmin));
    }
    if tail.starts_with("/issues") {
        Ok((Role::Triage, RepoAction::IssuesWrite))
    } else if tail == "/branch-rules" || tail.starts_with("/branch-rules/") {
        Ok((Role::Maintain, RepoAction::PullsWrite))
    } else if tail.starts_with("/pulls") {
        if is_pull_review_post_tail(method, tail) {
            return review_role_and_action(review_state);
        }
        Ok((Role::Write, RepoAction::PullsWrite))
    } else if tail.starts_with("/checks") || tail.starts_with("/check-runs") {
        Ok((Role::Write, RepoAction::ChecksWrite))
    } else if tail.starts_with("/webhooks") || tail.starts_with("/hooks") {
        Ok((Role::Write, RepoAction::HooksAdmin))
    } else if tail.starts_with("/collaborators") || tail.starts_with("/teams") {
        Ok((Role::Admin, RepoAction::MembersAdmin))
    } else if tail.starts_with("/workspaces") {
        Ok((Role::Write, RepoAction::WorkspacesWrite))
    } else if tail.starts_with("/commits") || tail.starts_with("/branches") || tail.starts_with("/files") {
        Ok((Role::Write, RepoAction::ContentsWrite))
    } else {
        Ok((Role::Admin, RepoAction::RepoAdmin))
    }
}

pub(super) fn surface_role_and_action(
    method: &Method,
    parsed: &ParsedRepoPath<'_>,
    query: Option<&str>,
    inspect: &AliasRequestInspect,
) -> Result<(Role, RepoAction), Error> {
    let tail = parsed.tail();
    let is_mutation = matches!(*method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE);
    match parsed.kind {
        RepoRouteKind::Git => {
            if (*method == Method::POST && tail == "/git-receive-pack")
                || (*method == Method::GET && tail == "/info/refs" && query_has_service_receive_pack(query))
            {
                Ok((Role::Write, RepoAction::ContentsWrite))
            } else {
                Ok((Role::Read, RepoAction::ContentsRead))
            }
        }
        RepoRouteKind::Lfs => lfs_role_and_action(method, is_mutation, tail, inspect.lfs_batch_op.as_deref()),
        RepoRouteKind::Web => web_role_and_action(method, is_mutation, tail, inspect.pull_review_state.as_deref()),
        RepoRouteKind::PinnedCiGit => Ok((Role::Read, RepoAction::ContentsRead)),
        RepoRouteKind::Api => api_role_and_action(method, is_mutation, tail, inspect.pull_review_state.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::alias::parse_repo_scoped_path;

    #[test]
    fn alias_policy_matches_canonical_reviews_waiters_and_branch_rules() {
        let p = |path| parse_repo_scoped_path(path).unwrap();
        let none = AliasRequestInspect::default();
        let commented = AliasRequestInspect { lfs_batch_op: None, pull_review_state: Some("commented".into()) };
        let approved = AliasRequestInspect { lfs_batch_op: None, pull_review_state: Some("approved".into()) };
        let upload = AliasRequestInspect { lfs_batch_op: Some("upload".into()), pull_review_state: None };
        let download = AliasRequestInspect { lfs_batch_op: Some("download".into()), pull_review_state: None };

        assert_eq!(
            surface_role_and_action(&Method::GET, &p("/api/repos/o/r/lfs/upload-waiters"), None, &none).unwrap(),
            (Role::Admin, RepoAction::RepoRead)
        );
        assert_eq!(
            surface_role_and_action(&Method::GET, &p("/api/repos/o/r/branch-rules"), None, &none).unwrap(),
            (Role::Read, RepoAction::PullsRead)
        );
        assert_eq!(
            surface_role_and_action(&Method::POST, &p("/api/repos/o/r/branch-rules"), None, &none).unwrap(),
            (Role::Maintain, RepoAction::PullsWrite)
        );
        assert_eq!(
            surface_role_and_action(&Method::PUT, &p("/api/repos/o/r/branch-rules/main"), None, &none).unwrap(),
            (Role::Maintain, RepoAction::PullsWrite)
        );
        assert_eq!(
            surface_role_and_action(&Method::DELETE, &p("/api/repos/o/r/branch-rules/main"), None, &none).unwrap(),
            (Role::Maintain, RepoAction::PullsWrite)
        );

        for url in ["/api/repos/o/r/pulls/7/reviews", "/web/repos/o/r/pulls/7/reviews", "/ui/repos/o/r/pulls/7/reviews"]
        {
            assert_eq!(
                surface_role_and_action(&Method::POST, &p(url), None, &commented).unwrap(),
                (Role::Triage, RepoAction::PullsWrite)
            );
            assert_eq!(
                surface_role_and_action(&Method::POST, &p(url), None, &approved).unwrap(),
                (Role::Write, RepoAction::PullsWrite)
            );
            assert!(surface_role_and_action(&Method::POST, &p(url), None, &none).is_err());
        }

        assert_eq!(
            surface_role_and_action(&Method::POST, &p("/git/o/r.git/info/lfs/objects/batch"), None, &upload).unwrap(),
            (Role::Write, RepoAction::ContentsWrite)
        );
        assert_eq!(
            surface_role_and_action(&Method::POST, &p("/git/o/r.git/info/lfs/objects/batch"), None, &download).unwrap(),
            (Role::Read, RepoAction::ContentsRead)
        );
        assert_eq!(
            surface_role_and_action(&Method::GET, &p("/web/repos/o/r/audit"), None, &none).unwrap(),
            (Role::Maintain, RepoAction::MembersRead)
        );
    }

    #[tokio::test]
    async fn inspect_alias_request_enforces_review_64kib_limit_and_state() {
        let parsed = parse_repo_scoped_path("/web/repos/o/r/pulls/1/reviews").unwrap();
        let ok = inspect_alias_request(
            &Method::POST,
            &parsed,
            Some(Body::from(r#"{"state":"commented","commit_oid":"deadbeef"}"#)),
        )
        .await
        .unwrap();
        assert_eq!(ok.pull_review_state.as_deref(), Some("commented"));

        let oversized = vec![b'a'; MAX_REVIEW_ALIAS_BODY + 128];
        let err = inspect_alias_request(&Method::POST, &parsed, Some(Body::from(oversized))).await.unwrap_err();
        assert_eq!(err.0, StatusCode::PAYLOAD_TOO_LARGE);

        let bad_state = inspect_alias_request(&Method::POST, &parsed, Some(Body::from(r#"{"state":"unknown"}"#)))
            .await
            .unwrap_err();
        assert_eq!(bad_state.0, StatusCode::BAD_REQUEST);
    }
}
