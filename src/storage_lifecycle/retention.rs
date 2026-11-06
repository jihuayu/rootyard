//! Complete reachability-root union and GC keep refs.
//!
//! Native refs are collected from Git. SQL pins are collected from every
//! durable retention root domain and anchored under a reserved keep namespace
//! before any physical pack rewrite or unlink. A keep ref is a native root, so
//! Git's own reachability walk protects the pinned closure without the service
//! having to reimplement object graph traversal.
use super::gitfs;
use crate::{AppState, journal};
use anyhow::{Context, Result, bail, ensure};
use std::collections::{BTreeMap, BTreeSet};
use tokio_postgres::GenericClient;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const KEEP_PREFIX: &str = "refs/keep/gc-epoch-";
const MAX_ROOTS: usize = 100_000;
const MAX_REF_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RootPin {
    pub kind: String,
    pub oid: String,
}

fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64)
        && oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && oid.bytes().any(|b| b != b'0')
}

fn root_kind(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Every SQL row that can keep an object reachable in this repository.
///
/// The query intentionally over-retains: it is safer to keep a historical
/// review/checkpoint pin than to infer that its object closure is dispensable.
/// Every expression is text and is filtered again in Rust before use.
const ROOT_SQL: &str = "
SELECT 'pull_head' AS kind, head_oid AS oid
  FROM forge_pulls
 WHERE repository_id=$1 AND state IN ('open','merged')
UNION ALL
SELECT 'pull_base', base_oid
  FROM forge_pulls
 WHERE repository_id=$1 AND state IN ('open','merged')
UNION ALL
SELECT 'pull_merge', merge_commit_oid
  FROM forge_pulls
 WHERE repository_id=$1 AND state IN ('open','merged') AND merge_commit_oid IS NOT NULL
UNION ALL
SELECT 'pull_review', r.commit_oid
  FROM forge_pull_reviews r
  JOIN forge_pulls p
    ON p.tenant_id=r.tenant_id AND p.repository_id=r.repository_id
   AND p.number=r.pull_number
 WHERE p.repository_id=$1 AND p.state IN ('open','merged')
UNION ALL
SELECT 'check_run', commit_oid
  FROM forge_check_runs
 WHERE repository_id=$1 AND status IN ('queued','in_progress')
UNION ALL
SELECT 'ci_run_head', head_oid
  FROM ci_runs
 WHERE repository_id=$1 AND state IN ('queued','leased')
UNION ALL
SELECT 'ci_run_base', base_oid
  FROM ci_runs
 WHERE repository_id=$1 AND state IN ('queued','leased')
UNION ALL
SELECT 'ci_checkout_pin', plan->>'target_oid'
  FROM ci_checkout_jobs
 WHERE repository_id=$1 AND NOT cancelled AND NOT revoked AND plan IS NOT NULL
   AND (expires_unix IS NULL OR expires_unix > extract(epoch FROM clock_timestamp())::bigint)
UNION ALL
SELECT 'ci_integration_pin', plan->>'target_oid'
  FROM ci_integration_checkout_jobs
 WHERE repository_id=$1
   AND expires_unix > extract(epoch FROM clock_timestamp())::bigint
UNION ALL
SELECT 'ci_pull_sync_head', head_oid
  FROM ci_pull_sync_progress
 WHERE repository_id=$1
UNION ALL
SELECT 'ci_pull_sync_base', base_oid
  FROM ci_pull_sync_progress
 WHERE repository_id=$1
UNION ALL
SELECT 'workspace_base', base_oid
  FROM workspaces
 WHERE repository_id=$1 AND state<>'deleted' AND base_oid IS NOT NULL
UNION ALL
SELECT 'checkpoint_base', base_oid
  FROM workspace_checkpoints
 WHERE repository_id=$1 AND state<>'failed' AND base_oid IS NOT NULL
UNION ALL
SELECT 'namespace_mount', base_oid
  FROM workspace_namespace_mounts
 WHERE repository_id=$1
UNION ALL
SELECT 'view_source', source_oid
  FROM workspace_views
 WHERE repository_id=$1
UNION ALL
SELECT 'view_history_source', h.source_oid
  FROM workspace_view_history h
  JOIN workspace_views v ON v.id=h.view_id
 WHERE v.repository_id=$1
UNION ALL
SELECT 'changeset_old', s.old_oid
  FROM workspace_changeset_steps s
  JOIN workspace_changesets c ON c.id=s.changeset_id
 WHERE s.repository_id=$1 AND (c.state<>'complete' OR NOT s.applied)
UNION ALL
SELECT 'changeset_new', s.new_oid
  FROM workspace_changeset_steps s
  JOIN workspace_changesets c ON c.id=s.changeset_id
 WHERE s.repository_id=$1 AND (c.state<>'complete' OR NOT s.applied)
UNION ALL
SELECT 'ci_sandbox_head', s.ci_head_oid
  FROM sandbox_jobs s
  LEFT JOIN workspaces w ON w.id=s.workspace_id
  LEFT JOIN ci_runs r ON r.id=s.ci_run_id
 WHERE (w.repository_id=$1 OR r.repository_id=$1)
   AND s.state IN ('queued','running') AND s.ci_head_oid IS NOT NULL
UNION ALL
SELECT 'ref_projection', oid
  FROM repository_ref_projection
 WHERE repository_id=$1 AND NOT deleted AND oid IS NOT NULL
";

pub async fn collect_sql_roots<C: GenericClient + Sync>(client: &C, repo: Uuid) -> Result<Vec<RootPin>> {
    let rows = client.query(ROOT_SQL, &[&repo]).await.context("read GC retention roots")?;
    let mut pins = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let kind: String = row.get(0);
        let oid: String = row.get(1);
        ensure!(root_kind(&kind), "invalid GC root kind");
        ensure!(valid_oid(&oid), "invalid GC retention root object ID");
        if seen.insert(oid.clone()) {
            pins.push(RootPin { kind, oid });
            ensure!(pins.len() <= MAX_ROOTS, "GC root union exceeds limit");
        }
    }
    Ok(pins)
}

pub async fn collect_native_roots(state: &AppState, repo: Uuid, cancel: &CancellationToken) -> Result<Vec<RootPin>> {
    let raw =
        gitfs::run_git(state, repo, &["for-each-ref", "--format=%(objectname) %(refname)"], cancel, MAX_REF_BYTES)
            .await?;
    let mut pins = Vec::new();
    let mut seen = BTreeSet::new();
    for line in raw.lines() {
        let Some((oid, name)) = line.split_once(' ') else {
            bail!("invalid native ref listing");
        };
        ensure!(valid_oid(oid) && name.starts_with("refs/") && name.len() <= 1024, "unsupported native ref");
        // Keep refs are an implementation detail of this collector; comparing
        // them in the native-root snapshot would make the snapshot differ from
        // itself as soon as the SQL pins are anchored.
        if name.starts_with(KEEP_PREFIX) {
            continue;
        }
        if seen.insert(oid.to_owned()) {
            pins.push(RootPin { kind: "native_ref".into(), oid: oid.to_owned() });
            ensure!(pins.len() <= MAX_ROOTS, "native GC root union exceeds limit");
        }
    }
    Ok(pins)
}

pub fn keep_ref_name(epoch: i64, oid: &str) -> String {
    format!("{KEEP_PREFIX}{epoch}/{oid}")
}

fn parse_ref_listing(raw: &str) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for line in raw.lines() {
        let Some((name, oid)) = line.split_once(' ') else {
            bail!("invalid Git ref listing");
        };
        ensure!(name.starts_with("refs/") && valid_oid(oid), "invalid Git ref listing");
        result.insert(name.to_owned(), oid.to_owned());
    }
    Ok(result)
}

async fn list_refs(
    state: &AppState,
    repo: Uuid,
    prefix: &str,
    cancel: &CancellationToken,
) -> Result<BTreeMap<String, String>> {
    let raw = gitfs::run_git(
        state,
        repo,
        &["for-each-ref", "--format=%(refname) %(objectname)", prefix],
        cancel,
        MAX_REF_BYTES,
    )
    .await?;
    parse_ref_listing(&raw)
}

async fn delete_refs(
    state: &AppState,
    repo: Uuid,
    refs: &BTreeMap<String, String>,
    cancel: &CancellationToken,
) -> Result<bool> {
    if refs.is_empty() {
        return Ok(false);
    }
    ensure!(refs.len() <= MAX_ROOTS, "too many GC keep refs");
    let mut input = String::from("start\n");
    for name in refs.keys() {
        ensure!(name.starts_with(KEEP_PREFIX) && journal::valid_ref(name), "ref is outside the GC keep namespace");
        input.push_str("delete ");
        input.push_str(name);
        input.push('\n');
    }
    input.push_str("prepare\ncommit\n");
    gitfs::run_git_with_input(state, repo, &["update-ref", "--stdin", "--no-deref"], input.as_bytes(), cancel, 4096)
        .await?;
    Ok(true)
}

/// Remove keep refs from an interrupted or older collection. Only the reserved
/// namespace is touched; a stale keep ref is a retention leak, never data loss.
pub async fn cleanup_keep_refs(state: &AppState, repo: Uuid, cancel: &CancellationToken) -> Result<u64> {
    let refs = list_refs(state, repo, KEEP_PREFIX, cancel).await?;
    let count = refs.len() as u64;
    delete_refs(state, repo, &refs, cancel).await?;
    Ok(count)
}

async fn object_types(
    state: &AppState,
    repo: Uuid,
    oids: &[String],
    cancel: &CancellationToken,
) -> Result<BTreeMap<String, String>> {
    if oids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut input = String::new();
    for oid in oids {
        ensure!(valid_oid(oid), "invalid retention root object ID");
        input.push_str(oid);
        input.push('\n');
    }
    let raw = gitfs::run_git_with_input(
        state,
        repo,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input.as_bytes(),
        cancel,
        8 * 1024 * 1024,
    )
    .await?;
    let mut result = BTreeMap::new();
    for line in raw.lines() {
        let mut fields = line.split_ascii_whitespace();
        let oid = fields.next().context("missing object type")?;
        let kind = fields.next().context("missing object type")?;
        if fields.next().is_some() {
            bail!("invalid object type listing");
        }
        ensure!(valid_oid(oid), "invalid object type object ID");
        if kind != "missing" {
            ensure!(matches!(kind, "commit" | "tree" | "blob" | "tag"), "unsupported Git object type");
            result.insert(oid.to_owned(), kind.to_owned());
        }
    }
    Ok(result)
}

#[derive(Clone, Debug)]
pub struct KeepRefs {
    pub epoch: i64,
    pub refs: BTreeMap<String, String>,
}

/// Anchor every SQL pin under `refs/keep/gc-epoch-<epoch>/`. Existing keep refs
/// are removed first, so an interrupted collection cannot hide a missing root.
pub async fn anchor_keep_refs(
    state: &AppState,
    repo: Uuid,
    epoch: i64,
    roots: &[RootPin],
    cancel: &CancellationToken,
) -> Result<KeepRefs> {
    ensure!(epoch > 0, "invalid GC epoch");
    cleanup_keep_refs(state, repo, cancel).await?;
    let mut oids = roots.iter().map(|pin| pin.oid.clone()).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
    oids.sort();
    ensure!(oids.len() <= MAX_ROOTS, "too many GC retention roots");
    let types = object_types(state, repo, &oids, cancel).await?;
    for pin in roots {
        ensure!(types.contains_key(&pin.oid), "GC retention root object is missing: {} {}", pin.kind, pin.oid);
    }
    if oids.is_empty() {
        return Ok(KeepRefs { epoch, refs: BTreeMap::new() });
    }
    let mut expected = BTreeMap::new();
    let mut input = String::from("start\n");
    for oid in &oids {
        let name = keep_ref_name(epoch, oid);
        ensure!(journal::valid_ref(&name), "invalid GC keep ref name");
        input.push_str("create ");
        input.push_str(&name);
        input.push(' ');
        input.push_str(oid);
        input.push('\n');
        expected.insert(name, oid.clone());
    }
    input.push_str("prepare\ncommit\n");
    gitfs::run_git_with_input(state, repo, &["update-ref", "--stdin", "--no-deref"], input.as_bytes(), cancel, 4096)
        .await?;
    let actual = list_refs(state, repo, &format!("{KEEP_PREFIX}{epoch}/"), cancel).await?;
    ensure!(actual == expected, "GC keep refs were not anchored exactly as requested");
    Ok(KeepRefs { epoch, refs: expected })
}

pub async fn verify_keep_refs(state: &AppState, repo: Uuid, keep: &KeepRefs, cancel: &CancellationToken) -> Result<()> {
    let prefix = format!("{KEEP_PREFIX}{}/", keep.epoch);
    let actual = list_refs(state, repo, &prefix, cancel).await?;
    ensure!(actual == keep.refs, "GC keep refs changed before physical deletion");
    Ok(())
}

pub async fn remove_keep_refs(state: &AppState, repo: Uuid, keep: &KeepRefs, cancel: &CancellationToken) -> Result<()> {
    let prefix = format!("{KEEP_PREFIX}{}/", keep.epoch);
    let actual = list_refs(state, repo, &prefix, cancel).await?;
    if actual.is_empty() {
        return Ok(());
    }
    ensure!(actual.keys().all(|name| keep.refs.contains_key(name)), "refusing to delete an unmanaged keep ref");
    delete_refs(state, repo, &actual, cancel).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_oids_are_canonical_and_keep_names_are_reserved() {
        let oid = "a".repeat(40);
        assert!(valid_oid(&oid));
        assert!(!valid_oid(&"A".repeat(40)));
        assert!(!valid_oid(&"0".repeat(40)));
        assert!(!valid_oid("../escape"));
        let name = keep_ref_name(7, &oid);
        assert_eq!(name, format!("refs/keep/gc-epoch-7/{oid}"));
        assert!(journal::valid_ref(&name));
        assert!(root_kind("workspace_base"));
        assert!(!root_kind("Workspace Base"));
    }

    #[test]
    fn ref_listing_rejects_truncated_or_unsafe_lines() {
        let oid = "b".repeat(40);
        let parsed = parse_ref_listing(&format!("refs/heads/main {oid}\n")).unwrap();
        assert_eq!(parsed.get("refs/heads/main"), Some(&oid));
        assert!(parse_ref_listing("refs/heads/main\n").is_err());
        assert!(parse_ref_listing(&format!("refs/heads/main {}\n", "B".repeat(40))).is_err());
    }
}
