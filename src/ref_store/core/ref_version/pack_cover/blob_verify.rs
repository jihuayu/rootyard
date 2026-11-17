//! Live OpenDAL BlobStore read-back and real stock Git closure verification (Issue #184).
//!
//! Consumes a [`VerifiedFetchPlanProof`] + [`FetchPlan`] and downloads the planned
//! immutable `.pack` / `.idx` objects from [`BlobStore`] into a private `0o700`
//! [`DisposableViewRoot`] workspace, verifies backend identity, byte length,
//! SHA-256 read-back, thin-pack delta-base resolution (`git index-pack --fix-thin`),
//! and complete Git object closure (`git fsck --full --strict` + `git rev-list`).
use super::auth::{AuthorizationContext, FetchPlanError, ReadIsolationMode};
use super::model::{CoverArtifactPair, CoverHierarchyIndex};
use super::planner::FetchPlan;
use super::verifier::VerifiedFetchPlanProof;
use crate::blob_store::{
    BlobError, BlobLocator,
    disposable_view::{DisposableViewError, DisposableViewRoot, TempViewLease},
    opendal::BlobStore,
};
use crate::ref_store::core::types::{GitObjectFormat, GitOid, RefName};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const IO_CHUNK_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

/// Typed failure raised during OpenDAL Blob download or stock Git verification.
#[derive(Debug)]
pub enum BlobVerifyError {
    ProofMismatch,
    Plan(FetchPlanError),
    CoverMissing(&'static str),
    BackendIdentityMismatch,
    Blob(BlobError),
    DisposableView(DisposableViewError),
    IntegrityFailed(&'static str),
    GitCommandFailed { command: &'static str, detail: String },
    DeadlineExceeded,
    Io(String),
}

impl fmt::Display for BlobVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProofMismatch => f.write_str("fetch plan does not bind the supplied closure proof"),
            Self::Plan(err) => write!(f, "live authorization rejected fetch materialization: {err}"),
            Self::CoverMissing(msg) => write!(f, "planned cover missing: {msg}"),
            Self::BackendIdentityMismatch => f.write_str("cover pack backend identity mismatches opened BlobStore"),
            Self::Blob(err) => write!(f, "blob verification error: {err}"),
            Self::DisposableView(err) => write!(f, "disposable view error: {err}"),
            Self::IntegrityFailed(msg) => write!(f, "pack byte integrity check failed: {msg}"),
            Self::GitCommandFailed { command, detail } => write!(f, "git `{command}` failed: {detail}"),
            Self::DeadlineExceeded => f.write_str("blob verification deadline exceeded"),
            Self::Io(msg) => write!(f, "blob verification IO failed: {msg}"),
        }
    }
}

impl std::error::Error for BlobVerifyError {}

impl From<BlobError> for BlobVerifyError {
    fn from(value: BlobError) -> Self {
        Self::Blob(value)
    }
}

impl From<DisposableViewError> for BlobVerifyError {
    fn from(value: DisposableViewError) -> Self {
        Self::DisposableView(value)
    }
}

/// Verified temporary Git repository materialized solely from planned Blob packs.
pub struct MaterializedFetchVerification {
    lease: Arc<TempViewLease>,
    repo_path: PathBuf,
    pub blob_get_count: u64,
    pub blob_get_bytes: u64,
    pub verified_pack_count: usize,
    pub reachable_object_count: usize,
}

impl MaterializedFetchVerification {
    pub fn repo_path(&self) -> Result<&Path, BlobVerifyError> {
        self.lease.ensure_live()?;
        Ok(&self.repo_path)
    }

    pub fn reap(self) {
        drop(self.lease);
    }
}

/// Download verified packs from `store` into an isolated `0o700` view under `view_root`
/// and prove full Git pack/delta/object/fsck closure via stock `git`, re-checking live
/// authorization and retaining `TempViewLease` ownership across detached transfers.
pub async fn materialize_and_verify_fetch_plan(
    store: &BlobStore,
    view_root: &DisposableViewRoot,
    proof: &VerifiedFetchPlanProof,
    plan: &FetchPlan,
    live_auth: &AuthorizationContext,
    cover_index: &CoverHierarchyIndex,
    client_seed_packs: &[CoverArtifactPair],
    expected_refs: &[(RefName, GitOid)],
    deadline: Instant,
) -> Result<MaterializedFetchVerification, BlobVerifyError> {
    live_auth.validate(&plan.realm).map_err(BlobVerifyError::Plan)?;
    if !proof.binds(plan) || !proof.binds_live_auth(live_auth) {
        return Err(BlobVerifyError::ProofMismatch);
    }
    for want in &plan.wants {
        if !live_auth.can_see_ref(want.ref_name()) {
            return Err(BlobVerifyError::Plan(FetchPlanError::HiddenRefDenied));
        }
    }
    if plan.isolation.is_historical_pinned() && !live_auth.allow_historical_pins {
        return Err(BlobVerifyError::Plan(FetchPlanError::AuthDenied("historical pin reads not permitted")));
    }
    if matches!(plan.isolation, ReadIsolationMode::VersionSet { .. }) && !live_auth.allow_non_common_time_set {
        return Err(BlobVerifyError::Plan(FetchPlanError::NonCommonTimeDenied));
    }
    let expected_provider = store.provider().as_str();
    let expected_backend = store.backend_identity().as_hex();

    let mut reserved = plan.total_selected_bytes;
    for seed in client_seed_packs {
        reserved = reserved.saturating_add(seed.pack_locator.length()).saturating_add(seed.idx_locator.length());
    }
    let lease = Arc::new(view_root.create_view(
        "pack-cover-vrf",
        plan.realm.tenant_id(),
        plan.realm.repository_id(),
        reserved.saturating_mul(2).max(8 * 1024 * 1024),
        None,
    )?);
    let repo_path = lease.repo_path()?.to_path_buf();
    let fmt_flag = match plan.realm.object_format() {
        GitObjectFormat::Sha1 => "--object-format=sha1",
        GitObjectFormat::Sha256 => "--object-format=sha256",
    };
    run_git(&repo_path, &["init", "--bare", fmt_flag], None, deadline).await?;

    let mut blob_get_count = 0_u64;
    let mut blob_get_bytes = 0_u64;

    for seed in client_seed_packs {
        let fetched = download_and_install_pair(store, &lease, &repo_path, seed, deadline).await?;
        blob_get_count = blob_get_count.saturating_add(2);
        blob_get_bytes = blob_get_bytes.saturating_add(fetched);
    }

    for entry in &plan.selected_covers {
        let rec = cover_index.get(&entry.cover_id).ok_or(BlobVerifyError::CoverMissing("selected cover absent"))?;
        if rec.pack().provider() != expected_provider || rec.pack().backend_identity() != expected_backend {
            return Err(BlobVerifyError::BackendIdentityMismatch);
        }
        let fetched = download_and_install_pair(store, &lease, &repo_path, rec.artifacts(), deadline).await?;
        blob_get_count = blob_get_count.saturating_add(2);
        blob_get_bytes = blob_get_bytes.saturating_add(fetched);
    }

    for (ref_name, oid) in expected_refs {
        let hex = oid.as_hex();
        run_git(&repo_path, &["update-ref", ref_name.as_str(), &hex], None, deadline).await?;
    }
    run_git(&repo_path, &["fsck", "--full", "--strict"], None, deadline).await?;

    let has_objects = !plan.selected_covers.is_empty() || !client_seed_packs.is_empty();
    let reachable_object_count = if has_objects && !plan.resolved_want_commits.is_empty() {
        let mut rev_args: Vec<String> = vec!["rev-list".into(), "--objects".into()];
        for oid in &plan.resolved_want_commits {
            rev_args.push(oid.as_hex());
        }
        let arg_refs: Vec<&str> = rev_args.iter().map(String::as_str).collect();
        let objects_out = run_git(&repo_path, &arg_refs, None, deadline).await?;
        String::from_utf8_lossy(&objects_out).lines().filter(|l| !l.is_empty()).count()
    } else {
        0
    };
    Ok(MaterializedFetchVerification {
        lease,
        repo_path,
        blob_get_count,
        blob_get_bytes,
        verified_pack_count: plan.selected_covers.len(),
        reachable_object_count,
    })
}

async fn download_and_install_pair(
    store: &BlobStore,
    lease: &Arc<TempViewLease>,
    repo_path: &Path,
    pair: &CoverArtifactPair,
    deadline: Instant,
) -> Result<u64, BlobVerifyError> {
    if pair.is_thin_pack {
        let dir = lease.dir_path()?;
        let pack_stage = dir.join(format!("{}.thin.pack", pair.pack_stem));
        let idx_stage = dir.join(format!("{}.thin.idx", pair.pack_stem));
        fetch_verified(store, &pair.pack_locator, &pack_stage, deadline, Arc::clone(lease)).await?;
        fetch_verified(store, &pair.idx_locator, &idx_stage, deadline, Arc::clone(lease)).await?;
        let pack_bytes = tokio::fs::read(&pack_stage).await.map_err(|e| BlobVerifyError::Io(e.to_string()))?;
        if !pack_bytes.starts_with(b"PACK") {
            return Err(BlobVerifyError::IntegrityFailed("missing PACK header on thin pack"));
        }
        run_git(repo_path, &["index-pack", "--stdin", "--fix-thin", "--strict"], Some(&pack_bytes), deadline).await?;
        let _ = tokio::fs::remove_file(&pack_stage).await;
        let _ = tokio::fs::remove_file(&idx_stage).await;
    } else {
        let pack_rel = Path::new("objects/pack").join(format!("{}.pack", pair.pack_stem));
        let idx_rel = Path::new("objects/pack").join(format!("{}.idx", pair.pack_stem));
        let pack_dst = lease.resolve_repo_relative_path(&pack_rel)?;
        let idx_dst = lease.resolve_repo_relative_path(&idx_rel)?;
        fetch_verified(store, &pair.pack_locator, &pack_dst, deadline, Arc::clone(lease)).await?;
        fetch_verified(store, &pair.idx_locator, &idx_dst, deadline, Arc::clone(lease)).await?;
        let idx_arg = format!("objects/pack/{}.idx", pair.pack_stem);
        run_git(repo_path, &["verify-pack", "-v", &idx_arg], None, deadline).await?;
    }
    Ok(pair.pack_locator.length().saturating_add(pair.idx_locator.length()))
}

async fn fetch_verified(
    store: &BlobStore,
    locator: &BlobLocator,
    dst: &Path,
    deadline: Instant,
    lease_owner: Arc<TempViewLease>,
) -> Result<(), BlobVerifyError> {
    if Instant::now() >= deadline {
        return Err(BlobVerifyError::DeadlineExceeded);
    }
    store.get_to_file_with_owner(locator, dst, deadline, lease_owner).await?;
    let (actual_sha, actual_len) = hash_file_sha256(dst).await?;
    if actual_len != locator.length() || actual_sha != locator.sha256() {
        return Err(BlobVerifyError::IntegrityFailed("downloaded artifact SHA-256 or length mismatch"));
    }
    Ok(())
}

async fn hash_file_sha256(path: &Path) -> Result<(String, u64), BlobVerifyError> {
    let mut file = tokio::fs::File::open(path).await.map_err(|e| BlobVerifyError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buf = vec![0_u8; IO_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf).await.map_err(|e| BlobVerifyError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

async fn run_git(
    repo_dir: &Path,
    args: &[&str],
    stdin_data: Option<&[u8]>,
    deadline: Instant,
) -> Result<Vec<u8>, BlobVerifyError> {
    let timeout: Duration = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(BlobVerifyError::DeadlineExceeded)?;
    let cmd_name: &'static str = match args.first().copied() {
        Some("init") => "init",
        Some("index-pack") => "index-pack",
        Some("verify-pack") => "verify-pack",
        Some("update-ref") => "update-ref",
        Some("fsck") => "fsck",
        Some("rev-list") => "rev-list",
        _ => "git",
    };
    let mut cmd = Command::new("git");
    cmd.arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo_dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
        .env("GIT_TERMINAL_PROMPT", "0")
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child =
        cmd.spawn().map_err(|e| BlobVerifyError::GitCommandFailed { command: cmd_name, detail: e.to_string() })?;
    if let Some(bytes) = stdin_data
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin
            .write_all(bytes)
            .await
            .map_err(|e| BlobVerifyError::GitCommandFailed { command: cmd_name, detail: e.to_string() })?;
        drop(stdin);
    }
    let out = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| BlobVerifyError::DeadlineExceeded)?
        .map_err(|e| BlobVerifyError::GitCommandFailed { command: cmd_name, detail: e.to_string() })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        let detail = if stderr.is_empty() { format!("exit {}", out.status) } else { stderr };
        return Err(BlobVerifyError::GitCommandFailed { command: cmd_name, detail });
    }
    Ok(out.stdout)
}
