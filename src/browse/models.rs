//! Data models and input validators for Track 2A repository browse and ref transactions.
use crate::Error;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const ZERO_OID: &str = "0000000000000000000000000000000000000000";
pub const ZERO_OID_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const MAX_BROWSE_BLOB_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DIFF_BYTES: usize = 2 * 1024 * 1024;

pub fn is_zero_oid(oid: &str) -> bool {
    oid == ZERO_OID || oid == ZERO_OID_SHA256
}

pub fn valid_oid(oid: &str) -> bool {
    crate::browse::object_format::detect_oid_format(oid).is_some()
}

pub fn valid_non_zero_oid(oid: &str) -> bool {
    valid_oid(oid) && !is_zero_oid(oid)
}

pub fn valid_public_ref(name: &str) -> bool {
    if crate::ci_pins::reserved(name) || crate::namespace_service::proposal_ref_reserved(name) {
        return false;
    }
    let suffix = if let Some(rest) = name.strip_prefix("refs/heads/") {
        rest
    } else if let Some(rest) = name.strip_prefix("refs/tags/") {
        rest
    } else {
        return false;
    };
    !suffix.is_empty()
        && name.len() <= 1024
        && !name.ends_with('/')
        && !name.ends_with('.')
        && !name.contains("..")
        && !name.contains("@{")
        && name
            .split('/')
            .all(|p| !p.is_empty() && !p.starts_with('.') && !p.ends_with(".lock"))
        && !name
            .bytes()
            .any(|b| b <= 32 || b == 127 || b"~^:?*[\\".contains(&b))
}

pub fn valid_revision_spec(spec: &str) -> bool {
    if spec.is_empty()
        || spec.len() > 1024
        || spec.starts_with('-')
        || crate::ci_pins::reserved(spec)
        || crate::namespace_service::proposal_ref_reserved(spec)
        || spec.contains("rootyard-ci")
        || spec.contains("..")
        || spec.contains("@{")
        || spec
            .bytes()
            .any(|b| b <= 32 || b == 127 || b"~^:?*[\\".contains(&b))
    {
        return false;
    }
    if spec == "HEAD" || valid_non_zero_oid(spec) {
        return true;
    }
    if spec.starts_with("refs/") {
        return valid_public_ref(spec);
    }
    !spec.ends_with('/')
        && !spec.ends_with('.')
        && spec
            .split('/')
            .all(|p| !p.is_empty() && !p.starts_with('.') && !p.ends_with(".lock"))
}

pub fn normalize_rel_path(path: Option<&str>) -> Result<String, Error> {
    let Some(raw) = path else {
        return Ok(String::new());
    };
    if raw.is_empty() {
        return Ok(String::new());
    }
    if raw.len() > 4096
        || raw.starts_with('/')
        || raw.ends_with('/')
        || raw.bytes().any(|b| b < 32 || b == 127 || b == b'\\')
    {
        return Err(Error::bad_request());
    }
    for segment in raw.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.eq_ignore_ascii_case(".git")
        {
            return Err(Error::bad_request());
        }
    }
    Ok(raw.to_owned())
}

pub fn validate_limit(limit: Option<usize>) -> Result<usize, Error> {
    let n = limit.unwrap_or(50);
    if !(1..=100).contains(&n) {
        return Err(Error::bad_request());
    }
    Ok(n)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefsQuery {
    pub prefix: Option<String>,
    pub after: Option<String>,
    pub limit: Option<usize>,
}

impl RefsQuery {
    pub fn validate(&self) -> Result<(Option<&str>, Option<&str>, usize), Error> {
        let limit = validate_limit(self.limit)?;
        if let Some(ref prefix) = self.prefix
            && (prefix.is_empty()
                || prefix.len() > 1024
                || !prefix.starts_with("refs/")
                || crate::ci_pins::reserved(prefix)
                || prefix.starts_with("refs/rootyard-ci")
                || "refs/rootyard-ci".starts_with(prefix.as_str()) && prefix != "refs/"
                || prefix.contains("..")
                || prefix.bytes().any(|b| b <= 32 || b == 127))
            {
                return Err(Error::bad_request());
            }
        if let Some(ref after) = self.after
            && !valid_public_ref(after) {
                return Err(Error::bad_request());
            }
        Ok((self.prefix.as_deref(), self.after.as_deref(), limit))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitsQuery {
    pub oid: Option<String>,
    pub rev: Option<String>,
    pub after: Option<usize>,
    pub limit: Option<usize>,
}

impl CommitsQuery {
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
        Ok((spec, after, limit))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeQuery {
    pub oid: Option<String>,
    pub path: Option<String>,
    pub after: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeByOidQuery {
    pub path: Option<String>,
    pub after: Option<String>,
    pub limit: Option<usize>,
}

pub fn validate_tree_after(after: Option<&str>) -> Result<Option<&str>, Error> {
    if let Some(cursor) = after
        && (cursor.is_empty()
            || cursor.len() > 1024
            || cursor == "."
            || cursor == ".."
            || cursor.bytes().any(|b| b < 32 || b == 127 || b == b'/'))
        {
            return Err(Error::bad_request());
        }
    Ok(after)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobQuery {
    pub oid: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobByOidQuery {
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompareQuery {
    pub base: String,
    pub head: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadInfo {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefItem {
    pub name: String,
    pub oid: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peeled_oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefsResponse {
    pub repository_id: Uuid,
    pub storage_generation: i64,
    pub head: HeadInfo,
    pub items: Vec<RefItem>,
    pub next_after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitSummary {
    pub oid: String,
    pub tree_oid: String,
    pub parents: Vec<String>,
    pub author_name: String,
    pub author_email: String,
    pub authored_at: i64,
    pub committer_name: String,
    pub committer_email: String,
    pub committed_at: i64,
    pub subject: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitDetail {
    #[serde(flatten)]
    pub summary: CommitSummary,
    pub changed_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitsResponse {
    pub repository_id: Uuid,
    pub items: Vec<CommitSummary>,
    pub next_after: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreeEntry {
    pub name: String,
    pub path: String,
    pub mode: String,
    pub kind: String,
    pub oid: String,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreeResponse {
    pub oid: String,
    pub tree_oid: String,
    pub path: String,
    pub items: Vec<TreeEntry>,
    pub next_after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobResponse {
    pub oid: String,
    pub size: u64,
    pub is_binary: bool,
    pub content: Option<String>,
    pub content_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompareResponse {
    pub base_oid: String,
    pub head_oid: String,
    pub merge_base_oid: Option<String>,
    pub ahead: u64,
    pub behind: u64,
    pub fast_forward: bool,
    pub commits: Vec<CommitSummary>,
    pub diff: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageRouteQuery {
    pub operation: Option<String>,
}

impl StorageRouteQuery {
    pub fn validate(&self) -> Result<&str, Error> {
        let op = self.operation.as_deref().unwrap_or("read");
        if !matches!(
            op,
            "read" | "write" | "git-upload-pack" | "git-receive-pack"
        ) {
            return Err(Error::bad_request());
        }
        Ok(op)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageRouteResponse {
    pub repository_id: Uuid,
    pub owner: String,
    pub name: String,
    pub storage_backend: String,
    pub storage_generation: i64,
    pub state: String,
    pub gateway_route: String,
    pub read_backend: String,
    pub write_backend: String,
    pub requested_operation: String,
    pub selected_backend: String,
    pub write_paused: bool,
    pub pando_ready: bool,
    pub gitfs_ready: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_and_path_validation() {
        assert!(valid_public_ref("refs/heads/main"));
        assert!(valid_public_ref("refs/heads/feature/sub-1"));
        assert!(valid_public_ref("refs/tags/v1.0.0"));
        for bad in [
            "HEAD",
            "refs/heads/",
            "refs/tags/",
            "refs/rootyard-ci/jobs/123",
            "refs/rootyard-ci",
            "refs/heads/rootyard-proposals",
            "refs/heads/rootyard-proposals/00000000-0000-0000-0000-000000000001",
            "refs/remotes/origin/main",
            "refs/heads/..bad",
            "refs/heads/.hidden",
            "refs/heads/foo.lock",
            "refs/heads/foo/",
            "refs/heads/foo bar",
        ] {
            assert!(!valid_public_ref(bad), "expected invalid ref: {bad}");
        }

        assert_eq!(normalize_rel_path(None).unwrap(), "");
        assert_eq!(normalize_rel_path(Some("")).unwrap(), "");
        assert_eq!(normalize_rel_path(Some("src/lib.rs")).unwrap(), "src/lib.rs");
        for bad_path in [
            "/etc/passwd",
            "src/",
            "../secret",
            "src/../lib.rs",
            "src//lib.rs",
            ".git/config",
            "a/.GIT/hooks",
            "a\\b",
            "a\0b",
        ] {
            assert!(
                normalize_rel_path(Some(bad_path)).is_err(),
                "expected invalid path: {bad_path}"
            );
        }
    }
}
