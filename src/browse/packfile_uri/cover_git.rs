//! Bounded Git `.pack`/`.idx` scanner, timeout/byte-capped helper subprocess
//! runner, and `#184` `VersionRecord` sealer.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use uuid::Uuid;

use crate::{
    cache_wake::replica_cache::error::is_lower_hex_exact,
    ref_store::{
        GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget,
        contract::{IssuerLane, RequestDigest},
        core::CommitMode,
        ref_version::{
            BaseRequestSelector, CommitSetHead, CommitSetInput, CommitSetVersionEntry, OperationDigestInput,
            PackSetEntry, RefVersionIntent, RefVersionKind, RefVersionRealm, VersionId, VersionRecord,
            VersionRecordInput, compute_commit_set_id, compute_pack_set_digest, derive_candidate_version_id,
            operation_digest,
        },
    },
};

use super::{
    pack_bijection::{
        parse_and_verify_idx_v2_oids, read_confined_regular_pack_artifact, verify_confined_pack_dir,
        verify_raw_pack_stream_bijection,
    },
    types::{
        DEFAULT_HELPER_TIMEOUT_MS, MAX_CLOSURE_COMMITS, MAX_CLOSURE_OBJECTS, MAX_HELPER_STDERR_BYTES,
        MAX_HELPER_STDIN_BYTES, MAX_HELPER_STDOUT_BYTES, MAX_PACK_OBJECTS_PER_PACK, MAX_SCANNED_PACK_FILES,
        MAX_SINGLE_IDX_BYTES, MAX_SINGLE_PACK_SCAN_BYTES, MAX_TOTAL_SCANNED_PACK_BYTES, OffloadPolicyConfig,
        PackObjectFormat, PackfileUriError,
    },
};

/// Hard resource budgets governing helper `git` subprocesses, `.pack`/`.idx` scans, and residual packs.
#[derive(Debug, Clone, Copy)]
pub struct HelperResourceLimits {
    pub timeout: Duration,
    pub max_stdout_bytes: u64,
    pub max_residual_pack_bytes: u64,
    pub max_scanned_packs: usize,
    pub max_single_pack_bytes: u64,
    pub max_single_idx_bytes: u64,
    pub max_total_scanned_bytes: u64,
    pub max_pack_objects: usize,
    pub max_closure_commits: usize,
    pub max_closure_objects: usize,
}

impl Default for HelperResourceLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(DEFAULT_HELPER_TIMEOUT_MS),
            max_stdout_bytes: MAX_HELPER_STDOUT_BYTES,
            max_residual_pack_bytes: MAX_HELPER_STDOUT_BYTES,
            max_scanned_packs: MAX_SCANNED_PACK_FILES,
            max_single_pack_bytes: MAX_SINGLE_PACK_SCAN_BYTES,
            max_single_idx_bytes: MAX_SINGLE_IDX_BYTES,
            max_total_scanned_bytes: MAX_TOTAL_SCANNED_PACK_BYTES,
            max_pack_objects: MAX_PACK_OBJECTS_PER_PACK,
            max_closure_commits: MAX_CLOSURE_COMMITS,
            max_closure_objects: MAX_CLOSURE_OBJECTS,
        }
    }
}

impl HelperResourceLimits {
    pub fn for_gateway(policy: &OffloadPolicyConfig, request_timeout: Duration, max_response_bytes: u64) -> Self {
        let policy_dl = Duration::from_millis(policy.request_deadline_ms);
        let timeout = request_timeout.min(policy_dl).min(Duration::from_millis(DEFAULT_HELPER_TIMEOUT_MS));
        let single_pack =
            policy.max_inflight_bytes.min(policy.max_pack_bytes_per_request).min(MAX_SINGLE_PACK_SCAN_BYTES);
        let res_cap = max_response_bytes.min(policy.max_v2_response_bytes).min(MAX_SINGLE_PACK_SCAN_BYTES);
        Self {
            timeout,
            max_residual_pack_bytes: res_cap,
            max_single_pack_bytes: single_pack,
            ..Self::default()
        }
    }
}

pub(super) struct DiscoveredPack {
    pub pack_oid: String,
    pub pack_hash_hex: String,
    pub pack_sha256_hex: String,
    pub idx_sha256_hex: String,
    pub pack_bytes: Bytes,
    pub idx_len: u64,
    pub object_count: usize,
    pub commits: Vec<String>,
    pub defined_oids: HashSet<String>,
    pub is_standalone: bool,
}

pub(super) fn internal_err(e: impl std::fmt::Display) -> PackfileUriError {
    PackfileUriError::Internal(e.to_string())
}

/// Executes a sandboxed helper `git` subprocess with hard timeout and stdin/stdout/stderr byte caps.
pub async fn run_git_bounded(
    git_bin: &Path,
    repo_dir: &Path,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    max_stdout_bytes: u64,
    timeout: Duration,
) -> Result<Vec<u8>, PackfileUriError> {
    if timeout.is_zero() {
        return Err(PackfileUriError::Timeout("helper git deadline already expired".to_owned()));
    }
    if max_stdout_bytes == 0 {
        return Err(PackfileUriError::CapacityExceeded("zero helper stdout byte budget".to_owned()));
    }
    if stdin_bytes.is_some_and(|b| b.len() > MAX_HELPER_STDIN_BYTES) {
        return Err(PackfileUriError::CapacityExceeded("helper git stdin exceeds bound".to_owned()));
    }
    let dev_null = if cfg!(unix) { "/dev/null" } else { "NUL" };
    let hooks_cfg = format!("core.hooksPath={dev_null}");
    let mut cmd = Command::new(git_bin);
    cmd.env_clear();
    #[cfg(unix)]
    cmd.env("PATH", "/usr/bin:/bin");
    #[cfg(not(unix))]
    {
        if let Some(p) = std::env::var_os("PATH") {
            cmd.env("PATH", p);
        }
        if let Some(sr) = std::env::var_os("SystemRoot") {
            cmd.env("SystemRoot", sr);
        }
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dev_null)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("LC_ALL", "C")
        .arg("-c")
        .arg(&hooks_cfg)
        .arg("-c")
        .arg("gc.auto=0")
        .arg("-c")
        .arg("maintenance.auto=false")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo_dir)
        .args(args)
        .stdin(if stdin_bytes.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().map_err(|e| PackfileUriError::Internal(format!("git spawn: {e}")))?;
    let mut stdout = child.stdout.take().ok_or_else(|| PackfileUriError::Internal("missing git stdout".to_owned()))?;
    let mut stderr = child.stderr.take().ok_or_else(|| PackfileUriError::Internal("missing git stderr".to_owned()))?;
    let mut child_stdin = child.stdin.take();

    let io_fut = async {
        let write_fut = async {
            if let Some(data) = stdin_bytes
                && let Some(mut sin) = child_stdin.take()
            {
                let _ = sin.write_all(data).await;
                let _ = sin.shutdown().await;
            }
        };
        let read_out = async {
            let mut buf = Vec::new();
            let mut limited = (&mut stdout).take(max_stdout_bytes.saturating_add(1));
            limited.read_to_end(&mut buf).await.map(|_| buf)
        };
        let read_err = async {
            let mut buf = Vec::new();
            let mut limited = (&mut stderr).take(MAX_HELPER_STDERR_BYTES);
            let _ = limited.read_to_end(&mut buf).await;
        };
        let (_, out_res, _) = tokio::join!(write_fut, read_out, read_err);
        let out_bytes = out_res.map_err(|e| PackfileUriError::Internal(format!("git stdout: {e}")))?;
        if out_bytes.len() as u64 > max_stdout_bytes {
            let _ = child.start_kill();
            return Err(PackfileUriError::CapacityExceeded("helper git stdout exceeded byte cap".to_owned()));
        }
        let status = child.wait().await.map_err(|e| PackfileUriError::Internal(format!("git wait: {e}")))?;
        if !status.success() {
            return Err(PackfileUriError::Internal("git helper command failed".to_owned()));
        }
        Ok(out_bytes)
    };

    match tokio::time::timeout(timeout, io_fut).await {
        Ok(res) => res,
        Err(_) => {
            let _ = child.start_kill();
            Err(PackfileUriError::Timeout("helper git subprocess timed out".to_owned()))
        }
    }
}

/// Computes a bounded residual `.pack` containing `(wants \ haves) \ offloaded_oids` strictly inside `authorized_oids`.
pub async fn build_residual_pack_bytes(
    git_bin: &Path,
    repo_dir: &Path,
    wants: &[String],
    haves: &[String],
    offloaded_oids: &HashSet<String>,
    authorized_oids: &HashSet<String>,
    limits: &HelperResourceLimits,
) -> Result<Vec<u8>, PackfileUriError> {
    let mut rev_spec = String::new();
    for w in wants {
        if !authorized_oids.contains(w) {
            return Err(PackfileUriError::Unauthorized);
        }
        rev_spec.push_str(w);
        rev_spec.push('\n');
    }
    for h in haves {
        if run_git_bounded(git_bin, repo_dir, &["cat-file", "-e", &format!("{h}^{{commit}}")], None, 1024, limits.timeout)
            .await
            .is_ok()
        {
            rev_spec.push('^');
            rev_spec.push_str(h);
            rev_spec.push('\n');
        }
    }
    let obj_out = run_git_bounded(
        git_bin,
        repo_dir,
        &["rev-list", "--objects", "--stdin"],
        Some(rev_spec.as_bytes()),
        limits.max_stdout_bytes,
        limits.timeout,
    )
    .await?;
    let mut pack_in = String::new();
    let mut seen = HashSet::new();
    for line in String::from_utf8_lossy(&obj_out).lines() {
        let Some(oid) = line.split_whitespace().next() else { continue };
        if !authorized_oids.contains(oid) {
            return Err(PackfileUriError::Unauthorized);
        }
        if !offloaded_oids.contains(oid) && seen.insert(oid.to_owned()) {
            if seen.len() > limits.max_closure_objects {
                return Err(PackfileUriError::CapacityExceeded("residual object count exceeds bound".to_owned()));
            }
            pack_in.push_str(oid);
            pack_in.push('\n');
        }
    }
    run_git_bounded(
        git_bin,
        repo_dir,
        &["pack-objects", "--stdout"],
        Some(pack_in.as_bytes()),
        limits.max_residual_pack_bytes,
        limits.timeout,
    )
    .await
}

pub(super) fn collect_bounded_pack_paths<I: IntoIterator<Item = std::io::Result<PathBuf>>>(
    entries: I,
    max_scanned_packs: usize,
) -> Result<Vec<PathBuf>, PackfileUriError> {
    let max_dir_entries = max_scanned_packs.saturating_mul(8).max(16);
    let mut dir_entries_seen: usize = 0;
    let mut paths: Vec<PathBuf> = Vec::with_capacity(max_scanned_packs.min(64));
    for entry_res in entries {
        let path = entry_res.map_err(|e| {
            PackfileUriError::Internal(format!("failed reading objects/pack directory entry: {e}"))
        })?;
        dir_entries_seen = dir_entries_seen.saturating_add(1);
        if dir_entries_seen > max_dir_entries {
            return Err(PackfileUriError::CapacityExceeded(
                "objects/pack directory entry count exceeds scan bound".to_owned(),
            ));
        }
        if path.extension().is_some_and(|ext| ext == "pack") {
            if paths.len() >= max_scanned_packs {
                return Err(PackfileUriError::CapacityExceeded(
                    "repository pack count exceeds scan bound".to_owned(),
                ));
            }
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

pub(super) async fn discover_repo_packs(
    git_bin: &Path,
    repo_dir: &Path,
    fmt: PackObjectFormat,
    limits: &HelperResourceLimits,
) -> Result<(Vec<DiscoveredPack>, bool), PackfileUriError> {
    let Some(pack_dir) = verify_confined_pack_dir(repo_dir)? else {
        return Ok((Vec::new(), false));
    };
    let rd = match std::fs::read_dir(&pack_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), false)),
        Err(e) => return Err(PackfileUriError::Internal(format!("failed to open objects/pack directory: {e}"))),
    };
    let mut saw_nonregular_artifact = false;
    let iter = rd.map(|res| {
        let entry = res?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if path.extension().is_some_and(|ext| ext == "pack" || ext == "idx") && (ft.is_symlink() || !ft.is_file()) {
            saw_nonregular_artifact = true;
        }
        Ok(path)
    });
    let paths = collect_bounded_pack_paths(iter, limits.max_scanned_packs)?;
    if saw_nonregular_artifact {
        return Err(PackfileUriError::IntegrityMismatch("non-regular pack or idx entry in objects/pack".to_owned()));
    }
    let (hex_len, trailer_len) = (fmt.oid_hex_len(), fmt.oid_hex_len() / 2);
    let (mut total_scanned, mut rejected_corrupt_pack, mut out) = (0u64, false, Vec::new());
    for pack_path in paths {
        let idx_path = pack_path.with_extension("idx");
        let (Some(pack_name), Some(idx_name)) = (pack_path.file_name(), idx_path.file_name()) else {
            rejected_corrupt_pack = true;
            continue;
        };
        let pack_bytes = match read_confined_regular_pack_artifact(
            &pack_dir,
            pack_name,
            limits.max_single_pack_bytes,
            &mut total_scanned,
            limits.max_total_scanned_bytes,
        ) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e @ PackfileUriError::CapacityExceeded(_)) => return Err(e),
            Err(PackfileUriError::IntegrityMismatch(_)) => {
                rejected_corrupt_pack = true;
                continue;
            }
            Err(e) => return Err(e),
        };
        let idx_bytes = match read_confined_regular_pack_artifact(
            &pack_dir,
            idx_name,
            limits.max_single_idx_bytes,
            &mut total_scanned,
            limits.max_total_scanned_bytes,
        ) {
            Ok(Some(b)) => b,
            Err(e @ PackfileUriError::CapacityExceeded(_)) => return Err(e),
            Ok(None) | Err(PackfileUriError::IntegrityMismatch(_)) => {
                rejected_corrupt_pack = true;
                continue;
            }
            Err(e) => return Err(e),
        };
        let (object_count, idx_oids) =
            match parse_and_verify_idx_v2_oids(&pack_bytes, &idx_bytes, fmt, limits.max_pack_objects) {
                Ok(pair) => pair,
                Err(e @ PackfileUriError::CapacityExceeded(_)) => return Err(e),
                Err(_) => {
                    rejected_corrupt_pack = true;
                    continue;
                }
            };
        let vp_out = match verify_raw_pack_stream_bijection(git_bin, repo_dir, &pack_bytes, &idx_bytes, limits).await {
            Ok(v) => v,
            Err(e @ (PackfileUriError::CapacityExceeded(_) | PackfileUriError::Timeout(_))) => return Err(e),
            Err(_) => {
                rejected_corrupt_pack = true;
                continue;
            }
        };
        let mut defined_oids = HashSet::with_capacity(object_count);
        let mut delta_bases = Vec::new();
        let mut commits = Vec::new();
        for line in String::from_utf8_lossy(&vp_out).lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5
                && matches!(parts[1], "commit" | "tree" | "blob" | "tag")
                && is_lower_hex_exact(parts[0], hex_len)
            {
                defined_oids.insert(parts[0].to_owned());
                if parts[1] == "commit" {
                    commits.push(parts[0].to_owned());
                }
                if parts.len() >= 7 && is_lower_hex_exact(parts[6], hex_len) {
                    delta_bases.push(parts[6].to_owned());
                }
            }
        }
        if defined_oids.len() != object_count || defined_oids != idx_oids {
            rejected_corrupt_pack = true;
            continue;
        }
        if commits.is_empty() {
            continue;
        }
        let is_standalone = delta_bases.iter().all(|base| defined_oids.contains(base));
        let pack_hash_hex = hex::encode(&pack_bytes[pack_bytes.len() - trailer_len..]);
        let pack_sha256_hex = hex::encode(Sha256::digest(&pack_bytes[..]));
        out.push(DiscoveredPack {
            pack_oid: pack_sha256_hex.clone(),
            pack_hash_hex,
            pack_sha256_hex,
            idx_sha256_hex: hex::encode(Sha256::digest(&idx_bytes[..])),
            pack_bytes,
            idx_len: idx_bytes.len() as u64,
            object_count,
            commits,
            defined_oids,
            is_standalone,
        });
    }
    Ok((out, rejected_corrupt_pack))
}

pub(super) fn seal_synth_version(
    realm: &RefVersionRealm,
    ref_name: &RefName,
    seq: i64,
    base: Option<&VersionRecord>,
    deps: Vec<VersionId>,
    tip_oid: GitOid,
    pack_entries: &[PackSetEntry],
) -> Result<VersionRecord, PackfileUriError> {
    let op_id = Uuid::new_v4();
    let req_d = RequestDigest::of("packfile-uri-op", &[&seq.to_be_bytes()]);
    let ref_gen = base.map_or(1, |b| b.ref_generation() + 1);
    let pre = match base.map(VersionRecord::target) {
        Some(RefTarget::Oid(o)) => RefPrecondition::Present(*o),
        _ => RefPrecondition::Absent,
    };
    let sel = base.map_or(BaseRequestSelector::ExplicitAbsent, |b| BaseRequestSelector::Present(b.version_id()));
    let target = RefTarget::Oid(tip_oid);
    let intent = RefVersionIntent::new(ref_name.clone(), RefVersionKind::Publish, pre, sel, target.clone());
    let lane = IssuerLane::new("smart-http-fetch").map_err(internal_err)?;
    let op = OperationDigestInput::new(
        *realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        lane,
        seq,
        op_id,
        seq,
        req_d,
        CommitMode::Atomic,
        HeadUpdate::Keep,
        vec![intent],
        req_d,
        Vec::new(),
    );
    let op_digest = operation_digest(&op).map_err(internal_err)?;
    let version_id = derive_candidate_version_id(&op, op_digest, ref_name, base.map(VersionRecord::ref_generation))
        .map_err(internal_err)?;
    let ce = CommitSetVersionEntry::new(ref_name.clone(), version_id, RefVersionKind::Publish, target.clone());
    let cs_id =
        compute_commit_set_id(&CommitSetInput::new(*realm, seq, op_id, op_digest, vec![ce], CommitSetHead::Absent))
            .map_err(internal_err)?;
    let ps_digest = compute_pack_set_digest(pack_entries).map_err(internal_err)?;
    VersionRecord::seal(VersionRecordInput {
        version_id,
        realm: *realm,
        ref_name: ref_name.clone(),
        ref_generation: ref_gen,
        operation_id: op_id,
        operation_digest: op_digest,
        authority_seq: seq,
        kind: RefVersionKind::Publish,
        target,
        base_version_id: base.map(VersionRecord::version_id),
        object_deps: deps,
        pack_set_digest: ps_digest,
        commit_set_id: cs_id,
    })
    .map_err(internal_err)
}
