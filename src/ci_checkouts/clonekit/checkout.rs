//! Explicit opt-in CloneKit download, exact-OID incremental fetch, fsck, and stock Git fallback.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    builder::{CloneKitPublicationStore, RetentionPinGuard, RetentionPinLedger},
    grants::{
        CloneKitAuthorityOracle, DependencyVerificationReceipt, GrantVerificationContext, SignedCloneKitGrant,
        verify_grant, verify_tree_dependencies,
    },
    manifest::{
        CloneKitError, CloneKitManifest, CloneKitStatus, compute_file_sha256, default_git_timeout,
        ensure_not_cancelled, ensure_private_dir, run_git_command, write_atomic_private_file,
    },
};
use crate::blob_store::{
    disposable_view::{DisposableViewRoot, TempViewLease},
    opendal::BlobStore,
};

/// Explicit client policy governing CloneKit opt-in vs stock Git fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckoutPolicy {
    pub use_clonekit: bool,
    pub fallback_to_git_on_unusable_kit: bool,
    pub require_full_fsck: bool,
}

impl Default for CheckoutPolicy {
    fn default() -> Self {
        Self { use_clonekit: false, fallback_to_git_on_unusable_kit: true, require_full_fsck: true }
    }
}

/// Typed reason explaining why CloneKit fell back cleanly to stock Git.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackReason {
    OptOutStockGitRequested,
    MissingKit,
    EmptyRepository,
    CorruptKit,
    ExpiredKit,
    StaleKitGeneration,
    KitHistoryMismatch,
    InterruptedTransfer,
}

/// Actual execution path taken to materialize `target_oid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckoutStrategy {
    CloneKitExactHit { kit_generation: u64 },
    CloneKitIncremental { kit_generation: u64, base_commit_oid: String },
    StockGitDirect,
    StockGitFallback { reason: FallbackReason },
}

/// Quantitative resource and integrity telemetry from one CI checkout execution.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckoutTelemetry {
    pub strategy: CheckoutStrategy,
    pub kit_hit: bool,
    pub kit_bytes_downloaded: u64,
    pub delta_bytes_downloaded: u64,
    pub total_gets: u64,
    pub elapsed_ms: f64,
    pub verified_target_oid: String,
    pub dependency_receipt: DependencyVerificationReceipt,
}

/// Completed checkout workspace path (holding active `TempViewLease`) and verification telemetry.
pub struct CheckoutOutcome {
    pub workspace_dir: PathBuf,
    pub telemetry: CheckoutTelemetry,
    pub lease: TempViewLease,
}

/// Bounded inputs for running one exact-OID CI checkout with optional CloneKit acceleration.
pub struct CheckoutRequest<'a> {
    pub grant: &'a SignedCloneKitGrant,
    pub signing_secret: &'a [u8],
    pub expected_context: &'a GrantVerificationContext,
    pub authority: Arc<dyn CloneKitAuthorityOracle>,
    pub policy: CheckoutPolicy,
    pub git_binary: &'a Path,
    pub origin_remote: &'a str,
    pub http_bearer: Option<&'a str>,
    pub view_root: &'a DisposableViewRoot,
    pub pub_store: Option<&'a CloneKitPublicationStore>,
    pub manifest_override: Option<&'a CloneKitManifest>,
    pub blob_store: Option<&'a BlobStore>,
    pub pin_ledger: Option<&'a RetentionPinLedger>,
    pub lfs_objects_dir: Option<&'a Path>,
    pub destination_root: Option<&'a Path>,
    pub cancel: Option<CancellationToken>,
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), CloneKitError> {
    ensure_private_dir(dst)?;
    for entry in fs::read_dir(src).map_err(|e| CloneKitError::GitFailed(e.to_string()))? {
        let entry = entry.map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
        let (src_path, dst_path) = (entry.path(), dst.join(entry.file_name()));
        let meta = fs::symlink_metadata(&src_path).map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(CloneKitError::CorruptArtifact("symlink disallowed inside checkout workspace".into()));
        }
        if meta.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
        }
    }
    Ok(())
}

fn dir_object_bytes(repo_dir: &Path) -> u64 {
    fn walk(dir: &Path) -> u64 {
        let Ok(entries) = fs::read_dir(dir) else { return 0 };
        let mut total = 0u64;
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else { continue };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                total = total.saturating_add(walk(&path));
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
        total
    }
    walk(&repo_dir.join(".git").join("objects"))
}

fn run_git_fetch(req: &CheckoutRequest<'_>, work_repo: &Path, target_oid: &str) -> Result<(), CloneKitError> {
    let args = ["fetch", "--no-tags", req.origin_remote, target_oid];
    if let Some(token) = req.http_bearer {
        let hdr = format!("http.extraHeader=Authorization: Bearer {token}");
        let mut full = vec!["-c", &hdr];
        full.extend_from_slice(&args);
        run_git_command(req.git_binary, Some(work_repo), &full, req.cancel.as_ref())?;
    } else {
        run_git_command(req.git_binary, Some(work_repo), &args, req.cancel.as_ref())?;
    }
    Ok(())
}

struct FinalizeMeta {
    strategy: CheckoutStrategy,
    kit_hit: bool,
    kit_bytes: u64,
    delta_bytes: u64,
    total_gets: u64,
    started: Instant,
}

async fn finalize_workspace(
    req: &CheckoutRequest<'_>,
    work_repo: PathBuf,
    lease: TempViewLease,
    meta: FinalizeMeta,
) -> Result<CheckoutOutcome, CloneKitError> {
    let claims = &req.grant.claims;
    ensure_not_cancelled(req.cancel.as_ref())?;
    run_git_command(
        req.git_binary,
        Some(&work_repo),
        &["checkout", "--detach", &claims.target_oid],
        req.cancel.as_ref(),
    )?;
    let head_raw = run_git_command(
        req.git_binary,
        Some(&work_repo),
        &["rev-parse", "--verify", "HEAD^{commit}"],
        req.cancel.as_ref(),
    )?;
    let actual_head = String::from_utf8_lossy(&head_raw).trim().to_owned();
    if actual_head != claims.target_oid || !claims.object_format.valid_oid(&actual_head) {
        return Err(CloneKitError::IncompleteClosure(format!(
            "checked out HEAD {actual_head} != requested exact OID {}",
            claims.target_oid
        )));
    }
    if req.policy.require_full_fsck {
        run_git_command(req.git_binary, Some(&work_repo), &["fsck", "--full", "--strict"], req.cancel.as_ref())?;
    }
    let dependency_receipt =
        verify_tree_dependencies(req.git_binary, &work_repo, claims, req.authority.as_ref(), req.lfs_objects_dir)
            .await?;
    req.authority.check_active(claims).await?;
    ensure_not_cancelled(req.cancel.as_ref())?;

    let workspace_dir = if let Some(dst) = req.destination_root {
        copy_dir_recursive(&work_repo, dst)?;
        dst.to_path_buf()
    } else {
        work_repo
    };
    Ok(CheckoutOutcome {
        workspace_dir,
        telemetry: CheckoutTelemetry {
            strategy: meta.strategy,
            kit_hit: meta.kit_hit,
            kit_bytes_downloaded: meta.kit_bytes,
            delta_bytes_downloaded: meta.delta_bytes,
            total_gets: meta.total_gets,
            elapsed_ms: meta.started.elapsed().as_secs_f64() * 1000.0,
            verified_target_oid: claims.target_oid.clone(),
            dependency_receipt,
        },
        lease,
    })
}

/// Run plain stock Git clone/fetch checkout in a clean workspace for exact `target_oid`.
pub async fn run_stock_git_checkout(
    req: &CheckoutRequest<'_>,
    work_repo: PathBuf,
    lease: TempViewLease,
    strategy: CheckoutStrategy,
) -> Result<CheckoutOutcome, CloneKitError> {
    let started = Instant::now();
    let claims = &req.grant.claims;
    ensure_private_dir(&work_repo)?;
    run_git_command(
        req.git_binary,
        Some(&work_repo),
        &["init", "--quiet", claims.object_format.git_init_flag()],
        req.cancel.as_ref(),
    )?;
    run_git_fetch(req, &work_repo, &claims.target_oid)?;
    let bytes = dir_object_bytes(&work_repo);
    finalize_workspace(
        req,
        work_repo,
        lease,
        FinalizeMeta { strategy, kit_hit: false, kit_bytes: 0, delta_bytes: bytes, total_gets: 1, started },
    )
    .await
}

fn evaluate_manifest_fallback(
    manifest_opt: Option<&CloneKitManifest>,
    req: &CheckoutRequest<'_>,
) -> Result<Result<(), FallbackReason>, CloneKitError> {
    let claims = &req.grant.claims;
    let Some(m) = manifest_opt else {
        return Ok(Err(FallbackReason::MissingKit));
    };
    if m.tenant_id != claims.tenant_id {
        return Err(CloneKitError::CrossTenantDenied);
    }
    if m.repository_id != claims.repository_id || m.object_format != claims.object_format {
        return Err(CloneKitError::Unauthorized("manifest repo or object_format differs from grant"));
    }
    if m.verify_integrity().is_err() {
        return Ok(Err(FallbackReason::CorruptKit));
    }
    if m.status == CloneKitStatus::EmptyRepository {
        return Ok(Err(FallbackReason::EmptyRepository));
    }
    if m.status != CloneKitStatus::Active {
        return Ok(Err(FallbackReason::MissingKit));
    }
    if req.expected_context.now_unix >= m.expires_unix {
        return Ok(Err(FallbackReason::ExpiredKit));
    }
    if m.history_id != claims.history_id || m.storage_generation != claims.storage_generation {
        return Ok(Err(FallbackReason::KitHistoryMismatch));
    }
    if m.kit_generation < claims.min_kit_generation {
        return Ok(Err(FallbackReason::StaleKitGeneration));
    }
    Ok(Ok(()))
}

async fn download_and_verify_kit_files(
    req: &CheckoutRequest<'_>,
    manifest: &CloneKitManifest,
    stage_dir: &Path,
) -> Result<(PathBuf, PathBuf, u64, u64), CloneKitError> {
    ensure_not_cancelled(req.cancel.as_ref())?;
    let pack_meta = manifest.pack.as_ref().ok_or(CloneKitError::MissingKit)?;
    let idx_meta = manifest.idx.as_ref().ok_or(CloneKitError::MissingKit)?;
    let dest_pack = stage_dir.join(format!("kit-{}.pack", pack_meta.sha256));
    let dest_idx = stage_dir.join(format!("kit-{}.idx", idx_meta.sha256));
    let mut gets = 0u64;

    if let Some(blob_store) = req.blob_store {
        if let Some(expected_backend) = manifest.backend_identity_hex.as_deref()
            && expected_backend != blob_store.backend_identity().as_hex()
        {
            return Err(CloneKitError::ForeignBackend);
        }
        if let (Some(p_loc), Some(i_loc)) = (&pack_meta.blob_locator, &idx_meta.blob_locator) {
            let deadline = std::time::Instant::now() + default_git_timeout();
            blob_store.get_to_file(&p_loc.to_blob_locator()?, &dest_pack, deadline).await?;
            gets += 1;
            ensure_not_cancelled(req.cancel.as_ref())?;
            blob_store.get_to_file(&i_loc.to_blob_locator()?, &dest_idx, deadline).await?;
            gets += 1;
        }
    }
    if gets == 0 {
        let pub_store = req.pub_store.ok_or(CloneKitError::MissingKit)?;
        let (src_pack, src_idx) = pub_store.artifact_paths(manifest.repository_id, manifest.kit_generation);
        write_atomic_private_file(
            &dest_pack,
            &fs::read(&src_pack).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?,
        )?;
        ensure_not_cancelled(req.cancel.as_ref())?;
        write_atomic_private_file(
            &dest_idx,
            &fs::read(&src_idx).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?,
        )?;
        gets = 2;
    }

    let ((p_sha, p_len), (i_sha, i_len)) = (compute_file_sha256(&dest_pack)?, compute_file_sha256(&dest_idx)?);
    if p_sha != pack_meta.sha256 || p_len != pack_meta.length || i_sha != idx_meta.sha256 || i_len != idx_meta.length {
        return Err(CloneKitError::CorruptArtifact("downloaded clonekit pack/idx digest or size mismatch".into()));
    }
    Ok((dest_pack, dest_idx, p_len + i_len, gets))
}

fn fallback_error(reason: FallbackReason) -> CloneKitError {
    match reason {
        FallbackReason::OptOutStockGitRequested => CloneKitError::InvalidConfig("clonekit not requested"),
        FallbackReason::MissingKit => CloneKitError::MissingKit,
        FallbackReason::EmptyRepository => CloneKitError::EmptyRepository,
        FallbackReason::CorruptKit => CloneKitError::CorruptArtifact("clonekit verification failed".into()),
        FallbackReason::ExpiredKit => CloneKitError::GrantExpired,
        FallbackReason::StaleKitGeneration => CloneKitError::StaleGeneration { expected_min: 1, actual: 0 },
        FallbackReason::KitHistoryMismatch => {
            CloneKitError::HistoryChanged { expected: Uuid::nil(), actual: Uuid::nil() }
        }
        FallbackReason::InterruptedTransfer => CloneKitError::TransferCancelled,
    }
}

/// Execute an authenticated CI checkout using CloneKit when opted-in and valid, else explicit policy fallback.
pub async fn execute_ci_checkout(req: &CheckoutRequest<'_>) -> Result<CheckoutOutcome, CloneKitError> {
    let started = Instant::now();
    verify_grant(req.grant, req.signing_secret, req.expected_context, req.authority.as_ref()).await?;
    ensure_not_cancelled(req.cancel.as_ref())?;

    let claims = &req.grant.claims;
    let lease = req
        .view_root
        .create_view("ci-clonekit", claims.tenant_id, claims.repository_id, 0, Some(Duration::from_secs(300)))
        .map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
    let work_repo = lease.repo_path().map_err(|e| CloneKitError::GitFailed(e.to_string()))?.join("checkout");
    ensure_private_dir(&work_repo)?;

    if !req.policy.use_clonekit {
        return run_stock_git_checkout(req, work_repo, lease, CheckoutStrategy::StockGitDirect).await;
    }

    let allow_fallback = claims.allow_git_fallback && req.policy.fallback_to_git_on_unusable_kit;
    let loaded = match req.manifest_override {
        Some(m) => Some(m.clone()),
        None => match req.pub_store {
            Some(store) => match store.load_latest(claims.repository_id) {
                Ok(found) => found,
                Err(_) if allow_fallback => {
                    return run_stock_git_checkout(
                        req,
                        work_repo,
                        lease,
                        CheckoutStrategy::StockGitFallback { reason: FallbackReason::CorruptKit },
                    )
                    .await;
                }
                Err(err) => return Err(err),
            },
            None => None,
        },
    };
    if let Err(reason) = evaluate_manifest_fallback(loaded.as_ref(), req)? {
        return if allow_fallback {
            run_stock_git_checkout(req, work_repo, lease, CheckoutStrategy::StockGitFallback { reason }).await
        } else {
            Err(fallback_error(reason))
        };
    }

    let manifest = loaded.ok_or(CloneKitError::MissingKit)?;
    let _pin = match req.pin_ledger {
        Some(ledger) => Some(RetentionPinGuard::acquire(ledger, claims.repository_id, manifest.kit_generation)?),
        None => None,
    };
    let stage_dir = lease.dir_path().map_err(|e| CloneKitError::GitFailed(e.to_string()))?.join("kit-stage");
    ensure_private_dir(&stage_dir)?;
    let (staged_pack, staged_idx, kit_bytes, gets) = match download_and_verify_kit_files(req, &manifest, &stage_dir)
        .await
    {
        Ok(res) => res,
        Err(err @ (CloneKitError::TransferCancelled | CloneKitError::ForeignBackend)) => return Err(err),
        Err(err) if allow_fallback => {
            let reason = if matches!(err, CloneKitError::MissingKit) {
                FallbackReason::MissingKit
            } else {
                FallbackReason::CorruptKit
            };
            return run_stock_git_checkout(req, work_repo, lease, CheckoutStrategy::StockGitFallback { reason }).await;
        }
        Err(err) => return Err(err),
    };

    req.authority.check_active(claims).await?;
    ensure_not_cancelled(req.cancel.as_ref())?;
    run_git_command(
        req.git_binary,
        Some(&work_repo),
        &["init", "--quiet", claims.object_format.git_init_flag()],
        req.cancel.as_ref(),
    )?;

    let pack_sha = &manifest.pack.as_ref().ok_or(CloneKitError::MissingKit)?.sha256;
    let pack_dir = work_repo.join(".git").join("objects").join("pack");
    let (dst_pack, dst_idx) =
        (pack_dir.join(format!("pack-{pack_sha}.pack")), pack_dir.join(format!("pack-{pack_sha}.idx")));
    fs::copy(&staged_pack, &dst_pack).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
    fs::copy(&staged_idx, &dst_idx).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;

    let dst_idx_str = dst_idx.to_str().ok_or(CloneKitError::InvalidInput("non-utf8 idx path"))?;
    if let Err(err) = run_git_command(req.git_binary, Some(&work_repo), &["verify-pack", "-s", dst_idx_str], None) {
        return if allow_fallback {
            let clean_work = work_repo.with_file_name("checkout-fallback");
            run_stock_git_checkout(
                req,
                clean_work,
                lease,
                CheckoutStrategy::StockGitFallback { reason: FallbackReason::CorruptKit },
            )
            .await
        } else {
            Err(err)
        };
    }

    let base_oid = manifest.base_commit_oid.as_deref().ok_or(CloneKitError::MissingKit)?;
    run_git_command(
        req.git_binary,
        Some(&work_repo),
        &["update-ref", "refs/rootyard-clonekit-base", base_oid],
        req.cancel.as_ref(),
    )?;

    let before_delta = dir_object_bytes(&work_repo);
    let mut total_gets = gets;
    let strategy = if base_oid == claims.target_oid {
        CheckoutStrategy::CloneKitExactHit { kit_generation: manifest.kit_generation }
    } else {
        run_git_fetch(req, &work_repo, &claims.target_oid)?;
        total_gets += 1;
        CheckoutStrategy::CloneKitIncremental {
            kit_generation: manifest.kit_generation,
            base_commit_oid: base_oid.to_owned(),
        }
    };
    let delta_bytes = dir_object_bytes(&work_repo).saturating_sub(before_delta);
    let _ =
        run_git_command(req.git_binary, Some(&work_repo), &["update-ref", "-d", "refs/rootyard-clonekit-base"], None);

    finalize_workspace(
        req,
        work_repo,
        lease,
        FinalizeMeta { strategy, kit_hit: true, kit_bytes, delta_bytes, total_gets, started },
    )
    .await
}
