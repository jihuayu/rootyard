//! Shared data models, request/query extractors, validators, idempotency helpers,
//! and native Git read helpers for Track 1 (Pull Requests, Reviews, Check Runs, Branch Rules, Merge).
use crate::{AppState, Error, git_http};
use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_postgres::Row;
use uuid::Uuid;

pub const ZERO_OID: &str = "0000000000000000000000000000000000000000";
pub const ZERO_OID_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const PULL_FIELDS: &str = "repository_id,number,author_id,title,body,state,head_ref,base_ref,head_oid,base_oid,merge_commit_oid,merged_storage_generation,version,created_at::text,updated_at::text";
pub const REVIEW_FIELDS: &str = "repository_id,pull_number,number,author_id,state,commit_oid,pull_version,body,created_at::text";
pub const CHECK_FIELDS: &str = "repository_id,commit_oid,context,attempt,sequence,status,conclusion,output,created_at::text,updated_at::text";
pub const RULE_FIELDS: &str = "repository_id,branch_ref,required_approvals,required_checks,require_fast_forward,prevent_deletion,prevent_force_push,version,created_at::text,updated_at::text";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PullRequest {
    pub repository_id: Uuid,
    pub number: i64,
    pub author_id: Uuid,
    pub title: String,
    pub body: String,
    pub state: String,
    pub head_ref: String,
    pub base_ref: String,
    pub head_oid: String,
    pub base_oid: String,
    pub merge_commit_oid: Option<String>,
    pub merged_storage_generation: Option<i64>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}
impl PullRequest {
    pub fn row(row: &Row) -> Self {
        Self {
            repository_id: row.get("repository_id"),
            number: row.get("number"),
            author_id: row.get("author_id"),
            title: row.get("title"),
            body: row.get("body"),
            state: row.get("state"),
            head_ref: row.get("head_ref"),
            base_ref: row.get("base_ref"),
            head_oid: row.get("head_oid"),
            base_oid: row.get("base_oid"),
            merge_commit_oid: row.get("merge_commit_oid"),
            merged_storage_generation: row.get("merged_storage_generation"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PullReview {
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub number: i64,
    pub author_id: Uuid,
    pub state: String,
    pub commit_oid: String,
    pub pull_version: i64,
    pub body: String,
    pub created_at: String,
}
impl PullReview {
    pub fn row(row: &Row) -> Self {
        Self {
            repository_id: row.get("repository_id"),
            pull_number: row.get("pull_number"),
            number: row.get("number"),
            author_id: row.get("author_id"),
            state: row.get("state"),
            commit_oid: row.get("commit_oid"),
            pull_version: row.get("pull_version"),
            body: row.get("body"),
            created_at: row.get("created_at"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckRun {
    pub repository_id: Uuid,
    pub commit_oid: String,
    pub context: String,
    pub attempt: i64,
    pub sequence: i64,
    pub status: String,
    pub conclusion: Option<String>,
    pub output: String,
    pub created_at: String,
    pub updated_at: String,
}
impl CheckRun {
    pub fn row(row: &Row) -> Self {
        Self {
            repository_id: row.get("repository_id"),
            commit_oid: row.get("commit_oid"),
            context: row.get("context"),
            attempt: row.get("attempt"),
            sequence: row.get("sequence"),
            status: row.get("status"),
            conclusion: row.get("conclusion"),
            output: row.get("output"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BranchRule {
    pub repository_id: Uuid,
    pub branch_ref: String,
    pub required_approvals: i64,
    pub required_checks: Vec<String>,
    pub require_fast_forward: bool,
    pub prevent_deletion: bool,
    pub prevent_force_push: bool,
    #[serde(default)]
    pub prevent_self_approval: bool,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}
impl BranchRule {
    pub fn row(row: &Row) -> Result<Self, Error> {
        let checks_val: Value = row.get("required_checks");
        let required_checks = serde_json::from_value(checks_val).map_err(Error::internal)?;
        Ok(Self {
            repository_id: row.get("repository_id"),
            branch_ref: row.get("branch_ref"),
            required_approvals: row.get("required_approvals"),
            required_checks,
            require_fast_forward: row.get("require_fast_forward"),
            prevent_deletion: row.get("prevent_deletion"),
            prevent_force_push: row.get("prevent_force_push"),
            prevent_self_approval: row.try_get("prevent_self_approval").unwrap_or(false),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewPull {
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(alias = "source_ref")]
    pub head_ref: String,
    #[serde(alias = "target_ref")]
    pub base_ref: String,
    pub head_oid: Option<String>,
    pub base_oid: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullPatch {
    pub expected_version: i64,
    pub title: Option<String>,
    pub body: Option<String>,
    pub state: Option<String>,
    pub head_oid: Option<String>,
    pub base_oid: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewReview {
    pub state: String,
    pub commit_oid: String,
    #[serde(default)]
    pub body: String,
}

fn default_one() -> i64 {
    1
}
fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRunInput {
    pub commit_oid: Option<String>,
    pub context: String,
    pub status: String,
    #[serde(default)]
    pub conclusion: Option<String>,
    #[serde(default = "default_one")]
    pub attempt: i64,
    #[serde(default = "default_one")]
    pub sequence: i64,
    #[serde(default)]
    pub output: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchRuleInput {
    pub branch_ref: Option<String>,
    pub expected_version: Option<i64>,
    #[serde(default)]
    pub required_approvals: i64,
    #[serde(default)]
    pub required_checks: Vec<String>,
    #[serde(default = "default_true")]
    pub require_fast_forward: bool,
    #[serde(default = "default_true")]
    pub prevent_deletion: bool,
    #[serde(default = "default_true")]
    pub prevent_force_push: bool,
    #[serde(default)]
    pub prevent_self_approval: bool,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeInput {
    pub expected_version: i64,
    pub expected_head_oid: String,
    pub expected_base_oid: String,
    pub storage_generation: Option<i64>,
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default)]
    pub commit_message: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub after: Option<i64>,
    pub limit: Option<i64>,
}
impl Page {
    pub fn bounds(&self) -> Result<(i64, i64), Error> {
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
pub struct PullPage {
    pub after: Option<i64>,
    pub limit: Option<i64>,
    pub state: Option<PullStateFilter>,
}
impl PullPage {
    pub fn bounds(&self) -> Result<(i64, i64), Error> {
        Page {
            after: self.after,
            limit: self.limit,
        }
        .bounds()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PullStateFilter {
    Open,
    Closed,
    Merged,
}
impl PullStateFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Merged => "merged",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PullDiffResponse {
    pub pull_number: i64,
    pub base_ref: String,
    pub head_ref: String,
    pub base_oid: String,
    pub head_oid: String,
    pub merge_base_oid: Option<String>,
    pub fast_forward: bool,
    pub diff: String,
}

pub fn json(status: StatusCode, value: impl Serialize) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}
pub fn positive(number: i64) -> Result<(), Error> {
    if number <= 0 {
        Err(Error::bad_request())
    } else {
        Ok(())
    }
}
pub fn title_valid(title: &str) -> bool {
    !title.trim().is_empty() && title.len() <= 256 && !title.chars().any(char::is_control)
}
pub fn body_valid(body: &str, required: bool) -> bool {
    body.len() <= 8192
        && (!required || !body.trim().is_empty())
        && !body
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}
pub fn valid_format(format: &str) -> bool {
    matches!(format, "sha1" | "sha256")
}

pub fn oid_hex_len(format: &str) -> Option<usize> {
    match format {
        "sha1" => Some(40),
        "sha256" => Some(64),
        _ => None,
    }
}

pub fn zero_oid(format: &str) -> Option<String> {
    oid_hex_len(format).map(|len| "0".repeat(len))
}

pub fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64)
        && oid.bytes().any(|b| b != b'0')
        && oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn valid_oid_for_format(oid: &str, format: &str) -> bool {
    oid_hex_len(format).is_some_and(|len| oid.len() == len) && valid_oid(oid)
}

/// Load the repository's immutable Git object format for the current
/// transaction. Callers validate inbound OIDs against this value instead of
/// inferring a format from the supplied hex length.
pub async fn repository_object_format(
    tx: &Transaction<'_>,
    repo: Uuid,
) -> Result<String, Error> {
    let format: String = tx
        .query_one("SELECT object_format FROM repositories WHERE id=$1", &[&repo])
        .await
        .map_err(Error::internal)?
        .get(0);
    if !valid_format(&format) {
        return Err(Error::internal("invalid repository object format"));
    }
    Ok(format)
}
pub fn context_valid(context: &str) -> bool {
    !context.trim().is_empty() && context.len() <= 128 && !context.chars().any(char::is_control)
}
pub fn valid_review_state(state: &str) -> bool {
    matches!(state, "approved" | "changes_requested" | "commented")
}
pub fn valid_check_status_and_conclusion(status: &str, conclusion: Option<&str>) -> bool {
    match status {
        "queued" | "in_progress" => conclusion.is_none(),
        "completed" => matches!(
            conclusion,
            Some("success" | "failure" | "neutral" | "cancelled" | "timed_out" | "skipped")
        ),
        _ => false,
    }
}
pub fn valid_branch_ref(s: &str) -> bool {
    (12..=1024).contains(&s.len())
        && s.starts_with("refs/heads/")
        && s != "refs/heads/HEAD"
        && !crate::ci_pins::reserved(s)
        && !crate::namespace_service::proposal_ref_reserved(s)
        && !s.ends_with('/')
        && !s.ends_with('.')
        && !s.contains("..")
        && !s.contains("@{")
        && s.split('/')
            .all(|p| !p.is_empty() && !p.starts_with('.') && !p.ends_with(".lock"))
        && !s
            .bytes()
            .any(|b| b <= 32 || b == 127 || b"~^:?*[\\".contains(&b))
}
pub fn normalize_branch_ref(raw: &str) -> Result<String, Error> {
    let branch_ref = if raw.starts_with("refs/") {
        raw.to_owned()
    } else {
        format!("refs/heads/{raw}")
    };
    if !valid_branch_ref(&branch_ref) {
        return Err(Error::bad_request());
    }
    Ok(branch_ref)
}

pub async fn creation_replay(
    tx: &Transaction<'_>,
    actor: Uuid,
    repo: Uuid,
    key: &str,
    request: &Value,
) -> Result<Option<Value>, Error> {
    let inserted = tx
        .execute(
            "INSERT INTO forge_creation_requests (tenant_id,repository_id,idempotency_key,request) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
            &[&actor, &repo, &key, &request],
        )
        .await
        .map_err(Error::internal)?;
    if inserted == 1 {
        return Ok(None);
    }
    let row = tx
        .query_one(
            "SELECT request,response FROM forge_creation_requests WHERE tenant_id=$1 AND repository_id=$2 AND idempotency_key=$3",
            &[&actor, &repo, &key],
        )
        .await
        .map_err(Error::internal)?;
    if row.get::<_, Value>("request") != *request {
        return Err(Error(StatusCode::CONFLICT, "idempotency key conflict"));
    }
    row.get::<_, Option<Value>>("response")
        .map(Some)
        .ok_or_else(|| Error::internal("incomplete creation record"))
}

pub async fn record_creation(
    tx: &Transaction<'_>,
    actor: Uuid,
    repo: Uuid,
    key: Option<&str>,
    response: &Value,
) -> Result<(), Error> {
    if let Some(key) = key {
        let changed = tx
            .execute(
                "UPDATE forge_creation_requests SET response=$4 WHERE tenant_id=$1 AND repository_id=$2 AND idempotency_key=$3 AND response IS NULL",
                &[&actor, &repo, &key, &response],
            )
            .await
            .map_err(Error::internal)?;
        if changed != 1 {
            return Err(Error::internal("creation record was not finalized"));
        }
    }
    Ok(())
}

pub async fn pull_exists(
    tx: &Transaction<'_>,
    actor: Uuid,
    repo: Uuid,
    number: i64,
) -> Result<(), Error> {
    tx.query_opt(
        "SELECT number FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3",
        &[&actor, &repo, &number],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::not_found)?;
    Ok(())
}

pub async fn repo_tenant_id(tx: &Transaction<'_>, repo: Uuid) -> Result<Uuid, Error> {
    let sql = "SELECT owner_id FROM repositories WHERE id=$1";
    Ok(tx.query_one(sql, &[&repo]).await.map_err(Error::internal)?.get(0))
}

pub fn git_cmd(state: &AppState, repo: Uuid) -> Result<tokio::process::Command, Error> {
    let path = state.storage.verify_path(repo).map_err(Error::internal)?;
    let mut cmd = state.storage.git(&state.config);
    cmd.arg("--no-replace-objects")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("--git-dir")
        .arg(path);
    Ok(cmd)
}

pub async fn resolve_ref_oid(
    state: &AppState,
    repo: Uuid,
    branch_ref: &str,
) -> Result<Option<String>, Error> {
    let mut cmd = git_cmd(state, repo)?;
    cmd.args([
        "for-each-ref",
        "--count=1",
        "--format=%(objectname)%00%(objecttype)%00%(symref)",
        branch_ref,
    ]);
    let out = git_http::collect_git_output(cmd, 4096, state.config.git_timeout)
        .await
        .map_err(Error::internal)?;
    if out.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&out).map_err(Error::internal)?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    let mut parts = line.split('\0');
    let (oid, obj_type, symref) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    if !symref.is_empty() || obj_type != "commit" || !valid_oid(oid) {
        return Ok(None);
    }
    Ok(Some(oid.to_owned()))
}

pub async fn verify_commit_exists(state: &AppState, repo: Uuid, oid: &str) -> Result<bool, Error> {
    if !valid_oid(oid) {
        return Ok(false);
    }
    let mut cmd = git_cmd(state, repo)?;
    cmd.args(["cat-file", "-t", oid]);
    Ok(matches!(
        git_http::collect_git_output(cmd, 256, state.config.git_timeout).await,
        Ok(out) if out == b"commit\n"
    ))
}

pub async fn merge_base(
    state: &AppState,
    repo: Uuid,
    base_oid: &str,
    head_oid: &str,
) -> Result<Option<String>, Error> {
    let mut cmd = git_cmd(state, repo)?;
    cmd.args(["merge-base", base_oid, head_oid]);
    match git_http::collect_git_output(cmd, 256, state.config.git_timeout).await {
        Ok(out) => {
            let oid = std::str::from_utf8(&out).map_err(Error::internal)?.trim();
            Ok(valid_oid(oid).then(|| oid.to_owned()))
        }
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;

    #[test]
    fn pull_filter_query_contract() {
        for (query, expected) in [
            ("", None),
            ("?state=open", Some("open")),
            ("?state=closed&after=4&limit=2", Some("closed")),
            ("?state=merged&limit=10", Some("merged")),
        ] {
            let uri = format!("/pulls{query}").parse().unwrap();
            let Query(page) = Query::<PullPage>::try_from_uri(&uri).unwrap();
            assert_eq!(page.state.as_ref().map(PullStateFilter::as_str), expected);
            assert!(page.bounds().is_ok());
        }
        for query in ["?state=", "?state=all", "?state=Open", "?state=open&state=closed", "?state=open&unknown=1"] {
            let uri = format!("/pulls{query}").parse().unwrap();
            assert!(Query::<PullPage>::try_from_uri(&uri).is_err());
        }
        for query in ["?state=open&after=-1", "?state=closed&limit=0", "?state=merged&limit=101"] {
            let uri = format!("/pulls{query}").parse().unwrap();
            let Query(page) = Query::<PullPage>::try_from_uri(&uri).unwrap();
            assert!(page.bounds().is_err());
        }
    }

    #[test]
    fn branch_ref_normalization_and_validation() {
        assert_eq!(normalize_branch_ref("main").unwrap(), "refs/heads/main");
        assert_eq!(normalize_branch_ref("refs/heads/feature/x").unwrap(), "refs/heads/feature/x");
        for bad in ["", "HEAD", "refs/heads/HEAD", "refs/tags/v1", "refs/rootyard-ci/jobs/1", "refs/heads/", "refs/heads/.hidden", "refs/heads/foo..bar", "refs/heads/foo.lock", "refs/heads/foo/", "refs/heads/foo@{1}", "refs/heads/foo bar"] {
            assert!(normalize_branch_ref(bad).is_err(), "expected error for {bad}");
        }
    }

    #[test]
    fn oid_and_check_state_validators() {
        assert!(valid_oid("0123456789abcdef0123456789abcdef01234567"));
        for bad_oid in ["", ZERO_OID, "0123456789ABCDEF0123456789abcdef01234567", "0123456789abcdef0123456789abcdef0123456", "0123456789abcdef0123456789abcdef0123456g"] {
            assert!(!valid_oid(bad_oid));
        }
        let sha1 = "a".repeat(40);
        let sha256 = "b".repeat(64);
        assert!(valid_oid_for_format(&sha1, "sha1"));
        assert!(!valid_oid_for_format(&sha1, "sha256"));
        assert!(valid_oid_for_format(&sha256, "sha256"));
        assert!(!valid_oid_for_format(&sha256, "sha1"));
        assert!(!valid_oid_for_format(&sha1, "sha512"));
        assert_eq!(zero_oid("sha1").as_deref(), Some(ZERO_OID));
        assert_eq!(zero_oid("sha256").as_deref(), Some(ZERO_OID_SHA256));
        assert!(zero_oid("sha512").is_none());
        assert!(valid_check_status_and_conclusion("queued", None));
        assert!(valid_check_status_and_conclusion("in_progress", None));
        assert!(!valid_check_status_and_conclusion("queued", Some("success")));
        assert!(!valid_check_status_and_conclusion("completed", None));
        assert!(valid_check_status_and_conclusion("completed", Some("success")));
        assert!(valid_check_status_and_conclusion("completed", Some("failure")));
        assert!(!valid_check_status_and_conclusion("completed", Some("unknown")));
    }
}
