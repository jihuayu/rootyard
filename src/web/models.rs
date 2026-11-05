//! Request/query extractors, strict serde input models, database row mappers,
//! and typed view-model structures for Part II Track 1 Web UI (`F33` & `F34`).
use crate::{
    Error,
    browse::models::{
        CommitSummary, CommitsQuery, HeadInfo, RefItem, TreeResponse, normalize_rel_path,
        valid_revision_spec, validate_limit, validate_tree_after,
    },
    members::models::Role,
    pulls::{
        models::{
            CheckRun, PullDiffResponse, PullRequest, PullReview, PullStateFilter, body_valid,
            positive, title_valid,
        },
        rules::PolicyEvaluation,
    },
    web::sanitize::{
        DEFAULT_WEB_BLOB_PREVIEW_BYTES, MAX_WEB_BLOB_PREVIEW_BYTES, MIN_WEB_BLOB_PREVIEW_BYTES,
    },
};
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

pub const ISSUE_FIELDS: &str =
    "repository_id,number,author_id,title,body,state,version,created_at::text,updated_at::text";
pub const COMMENT_FIELDS: &str =
    "repository_id,issue_number,number,author_id,body,version,created_at::text,updated_at::text";

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebTreeQuery {
    pub oid: Option<String>,
    pub rev: Option<String>,
    pub path: Option<String>,
    pub after: Option<String>,
    pub limit: Option<usize>,
}

impl WebTreeQuery {
    pub fn resolve_spec_and_validate<'a>(
        &'a self,
        path_oid: Option<&'a str>,
    ) -> Result<(Option<&'a str>, String, Option<&'a str>, usize), Error> {
        let query_spec = match (&self.oid, &self.rev) {
            (Some(o), Some(r)) if o != r => return Err(Error::bad_request()),
            (Some(o), _) => Some(o.as_str()),
            (None, Some(r)) => Some(r.as_str()),
            (None, None) => None,
        };
        let spec = match (path_oid, query_spec) {
            (Some(p), Some(q)) if p != q => return Err(Error::bad_request()),
            (Some(p), _) => Some(p),
            (None, q) => q,
        };
        if let Some(s) = spec {
            if !valid_revision_spec(s) {
                return Err(Error::bad_request());
            }
        }
        let rel_path = normalize_rel_path(self.path.as_deref())?;
        let after = validate_tree_after(self.after.as_deref())?;
        let limit = validate_limit(self.limit)?;
        Ok((spec, rel_path, after, limit))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebBlobQuery {
    pub oid: Option<String>,
    pub rev: Option<String>,
    pub path: Option<String>,
    pub max_bytes: Option<usize>,
}

impl WebBlobQuery {
    pub fn validate_max_bytes(&self) -> Result<usize, Error> {
        let max_bytes = self.max_bytes.unwrap_or(DEFAULT_WEB_BLOB_PREVIEW_BYTES);
        if !(MIN_WEB_BLOB_PREVIEW_BYTES..=MAX_WEB_BLOB_PREVIEW_BYTES).contains(&max_bytes) {
            return Err(Error::bad_request());
        }
        Ok(max_bytes)
    }

    pub fn resolve_spec<'a>(&'a self, path_oid: Option<&'a str>) -> Result<Option<&'a str>, Error> {
        let query_spec = match (&self.oid, &self.rev) {
            (Some(o), Some(r)) if o != r => return Err(Error::bad_request()),
            (Some(o), _) => Some(o.as_str()),
            (None, Some(r)) => Some(r.as_str()),
            (None, None) => None,
        };
        let spec = match (path_oid, query_spec) {
            (Some(p), Some(q)) if p != q => return Err(Error::bad_request()),
            (Some(p), _) => Some(p),
            (None, q) => q,
        };
        if let Some(s) = spec {
            if !valid_revision_spec(s) {
                return Err(Error::bad_request());
            }
        }
        Ok(spec)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebCommitsQuery {
    pub oid: Option<String>,
    pub rev: Option<String>,
    pub after: Option<usize>,
    pub limit: Option<usize>,
}

impl WebCommitsQuery {
    pub fn validate(&self) -> Result<(&str, usize, usize), Error> {
        let limit = validate_limit(self.limit)?;
        let after = self.after.unwrap_or(0);
        if after > 10_000 {
            return Err(Error::bad_request());
        }
        let spec = match (&self.oid, &self.rev) {
            (Some(o), Some(r)) if o != r => return Err(Error::bad_request()),
            (Some(o), _) => o.as_str(),
            (None, Some(r)) => r.as_str(),
            (None, None) => "HEAD",
        };
        if !valid_revision_spec(spec) {
            return Err(Error::bad_request());
        }
        let _ = CommitsQuery {
            oid: self.oid.clone(),
            rev: self.rev.clone(),
            after: self.after,
            limit: self.limit,
        };
        Ok((spec, after, limit))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebCompareQuery {
    pub base: Option<String>,
    pub head: Option<String>,
}

impl WebCompareQuery {
    pub fn validate(&self) -> Result<(&str, &str), Error> {
        let base = self.base.as_deref().ok_or_else(Error::bad_request)?;
        let head = self.head.as_deref().ok_or_else(Error::bad_request)?;
        if !valid_revision_spec(base) || !valid_revision_spec(head) {
            return Err(Error::bad_request());
        }
        Ok((base, head))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebIssueFilterQuery {
    pub state: Option<String>,
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

impl WebIssueFilterQuery {
    pub fn validate(&self) -> Result<(Option<&'static str>, i64, i64), Error> {
        let after = self.after.unwrap_or(0);
        let limit = self.limit.unwrap_or(50);
        if after < 0 || !(1..=100).contains(&limit) {
            return Err(Error::bad_request());
        }
        let state = match self.state.as_deref() {
            None => None,
            Some("open") => Some("open"),
            Some("closed") => Some("closed"),
            Some(_) => return Err(Error::bad_request()),
        };
        Ok((state, after, limit))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebPullFilterQuery {
    pub state: Option<String>,
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

impl WebPullFilterQuery {
    pub fn validate(&self) -> Result<(Option<PullStateFilter>, i64, i64), Error> {
        let after = self.after.unwrap_or(0);
        let limit = self.limit.unwrap_or(50);
        if after < 0 || !(1..=100).contains(&limit) {
            return Err(Error::bad_request());
        }
        let filter = match self.state.as_deref() {
            None => None,
            Some("open") => Some(PullStateFilter::Open),
            Some("closed") => Some(PullStateFilter::Closed),
            Some("merged") => Some(PullStateFilter::Merged),
            Some(_) => return Err(Error::bad_request()),
        };
        Ok((filter, after, limit))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebCheckPanelQuery {
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

impl WebCheckPanelQuery {
    pub fn validate(&self) -> Result<(i64, i64), Error> {
        let after = self.after.unwrap_or(0);
        let limit = self.limit.unwrap_or(50);
        if after < 0 || !(1..=100).contains(&limit) {
            return Err(Error::bad_request());
        }
        Ok((after, limit))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebNewIssue {
    pub title: String,
    #[serde(default)]
    pub body: String,
}

impl WebNewIssue {
    pub fn validate(&self) -> Result<(), Error> {
        if !title_valid(&self.title) || !body_valid(&self.body, false) {
            return Err(Error::bad_request());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebIssuePatch {
    pub expected_version: i64,
    pub title: Option<String>,
    pub body: Option<String>,
    pub state: Option<String>,
}

impl WebIssuePatch {
    pub fn validate(&self) -> Result<(), Error> {
        positive(self.expected_version)?;
        if self.title.as_ref().is_some_and(|t| !title_valid(t))
            || self.body.as_ref().is_some_and(|b| !body_valid(b, false))
            || self
                .state
                .as_ref()
                .is_some_and(|s| !matches!(s.as_str(), "open" | "closed"))
            || (self.title.is_none() && self.body.is_none() && self.state.is_none())
        {
            return Err(Error::bad_request());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebNewComment {
    pub body: String,
}

impl WebNewComment {
    pub fn validate(&self) -> Result<(), Error> {
        if !body_valid(&self.body, true) {
            return Err(Error::bad_request());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebIssue {
    pub repository_id: Uuid,
    pub number: i64,
    pub author_id: Uuid,
    pub title: String,
    pub body: String,
    pub state: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl WebIssue {
    pub fn from_row(row: &Row) -> Self {
        Self {
            repository_id: row.get("repository_id"),
            number: row.get("number"),
            author_id: row.get("author_id"),
            title: row.get("title"),
            body: row.get("body"),
            state: row.get("state"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebComment {
    pub repository_id: Uuid,
    pub issue_number: i64,
    pub number: i64,
    pub author_id: Uuid,
    pub body: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl WebComment {
    pub fn from_row(row: &Row) -> Self {
        Self {
            repository_id: row.get("repository_id"),
            issue_number: row.get("issue_number"),
            number: row.get("number"),
            author_id: row.get("author_id"),
            body: row.get("body"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RepoHeaderCtx {
    pub owner: String,
    pub name: String,
    pub repository_id: Uuid,
    pub owner_id: Uuid,
    pub effective_role: Role,
    pub actor_username: String,
    pub storage_backend: String,
    pub storage_generation: i64,
    pub repo_state: String,
}

#[derive(Clone, Debug)]
pub struct OverviewViewData {
    pub header: RepoHeaderCtx,
    pub head: HeadInfo,
    pub branches: Vec<RefItem>,
    pub tags: Vec<RefItem>,
    pub latest_commit: Option<CommitSummary>,
    pub tree: Option<TreeResponse>,
    pub readme_html: Option<String>,
    pub open_issues: i64,
    pub open_pulls: i64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BlobPreview {
    pub oid: String,
    pub path: String,
    pub total_size: u64,
    pub preview_bytes: usize,
    pub is_binary: bool,
    pub truncated: bool,
    pub line_count: usize,
    pub text_preview: Option<String>,
    pub rendered_markdown_html: Option<String>,
    pub hex_preview: Option<String>,
}

#[derive(Clone, Debug)]
pub struct IssueViewItem {
    pub issue: WebIssue,
    pub author_username: String,
    pub comment_count: i64,
}

#[derive(Clone, Debug)]
pub struct CommentViewItem {
    pub comment: WebComment,
    pub author_username: String,
}

#[derive(Clone, Debug)]
pub struct PullDetailViewData {
    pub pull: PullRequest,
    pub author_username: String,
    pub reviews: Vec<PullReview>,
    pub checks: Vec<CheckRun>,
    pub policy: PolicyEvaluation,
    pub diff: PullDiffResponse,
    pub disallow_self_approval: bool,
    pub can_approve: bool,
    pub can_merge: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_deny_unknown_fields_on_web_models() {
        let bad_issue = serde_json::from_str::<WebNewIssue>(
            r#"{"title":"Bug","body":"Details","unexpected":true}"#,
        );
        assert!(bad_issue.is_err());

        let bad_patch = serde_json::from_str::<WebIssuePatch>(
            r#"{"expected_version":1,"state":"closed","extra":"x"}"#,
        );
        assert!(bad_patch.is_err());

        let bad_comment =
            serde_json::from_str::<WebNewComment>(r#"{"body":"Hello","malicious":1}"#);
        assert!(bad_comment.is_err());

        let bad_blob_q =
            serde_json::from_str::<WebBlobQuery>(r#"{"path":"README.md","unknown":123}"#);
        assert!(bad_blob_q.is_err());
    }

    #[test]
    fn test_blob_query_max_bytes_bounds() {
        let default_q = WebBlobQuery::default();
        assert_eq!(
            default_q.validate_max_bytes().unwrap(),
            DEFAULT_WEB_BLOB_PREVIEW_BYTES
        );

        let too_small = WebBlobQuery {
            max_bytes: Some(MIN_WEB_BLOB_PREVIEW_BYTES - 1),
            ..Default::default()
        };
        assert!(too_small.validate_max_bytes().is_err());

        let too_large = WebBlobQuery {
            max_bytes: Some(MAX_WEB_BLOB_PREVIEW_BYTES + 1),
            ..Default::default()
        };
        assert!(too_large.validate_max_bytes().is_err());
    }

    #[test]
    fn test_issue_and_pull_filter_validation() {
        let ok_issue = WebIssueFilterQuery {
            state: Some("open".to_owned()),
            after: Some(0),
            limit: Some(25),
        };
        assert_eq!(ok_issue.validate().unwrap(), (Some("open"), 0, 25));

        let bad_issue = WebIssueFilterQuery {
            state: Some("merged".to_owned()),
            after: None,
            limit: None,
        };
        assert!(bad_issue.validate().is_err());

        let ok_pull = WebPullFilterQuery {
            state: Some("merged".to_owned()),
            after: Some(5),
            limit: Some(10),
        };
        assert_eq!(
            ok_pull.validate().unwrap(),
            (Some(PullStateFilter::Merged), 5, 10)
        );
    }

    #[test]
    fn test_new_issue_patch_and_comment_validators() {
        assert!(
            WebNewIssue {
                title: "Valid issue".to_owned(),
                body: "Body text".to_owned(),
            }
            .validate()
            .is_ok()
        );
        assert!(
            WebNewIssue {
                title: "   ".to_owned(),
                body: String::new(),
            }
            .validate()
            .is_err()
        );
        assert!(
            WebIssuePatch {
                expected_version: 1,
                title: None,
                body: None,
                state: None,
            }
            .validate()
            .is_err()
        );
        assert!(
            WebNewComment {
                body: "  ".to_owned()
            }
            .validate()
            .is_err()
        );
    }
}
