//! Low-level Git `.pack`/`.idx` discovery, residual pack assembly, and
//! `#184` synthetic `VersionRecord` sealing helpers.

use std::{
    collections::HashSet,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::{
    GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget,
    contract::{IssuerLane, RequestDigest},
    core::CommitMode,
    ref_version::{
        BaseRequestSelector, CommitSetHead, CommitSetInput, CommitSetVersionEntry, OperationDigestInput, PackSetEntry,
        RefVersionIntent, RefVersionKind, RefVersionRealm, VersionId, VersionRecord, VersionRecordInput,
        compute_commit_set_id, compute_pack_set_digest, derive_candidate_version_id, operation_digest,
    },
};

use super::types::{PackObjectFormat, PackfileUriError};

pub(super) struct DiscoveredPack {
    pub pack_oid: String,
    pub pack_hash_hex: String,
    pub pack_sha256_hex: String,
    pub idx_sha256_hex: String,
    pub pack_bytes: Vec<u8>,
    pub idx_len: u64,
    pub commits: Vec<String>,
    pub defined_oids: HashSet<String>,
    pub is_standalone: bool,
}

pub(super) fn internal_err(e: impl std::fmt::Display) -> PackfileUriError {
    PackfileUriError::Internal(e.to_string())
}

pub(super) fn run_git(
    git_bin: &Path,
    repo_dir: &Path,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
) -> Result<Vec<u8>, PackfileUriError> {
    let mut cmd = Command::new(git_bin);
    cmd.arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo_dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.stdin(if stdin_bytes.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd.spawn().map_err(|e| PackfileUriError::Internal(format!("git spawn: {e}")))?;
    if let Some(data) = stdin_bytes
        && let Some(mut sin) = child.stdin.take()
    {
        sin.write_all(data).map_err(|e| PackfileUriError::Internal(format!("git stdin: {e}")))?;
    }
    let out = child.wait_with_output().map_err(|e| PackfileUriError::Internal(format!("git wait: {e}")))?;
    if !out.status.success() {
        return Err(PackfileUriError::Internal("git command failed".to_owned()));
    }
    Ok(out.stdout)
}

/// Computes a self-contained residual `.pack` containing `(wants \ haves) \ offloaded_oids`.
pub fn build_residual_pack_bytes(
    git_bin: &Path,
    repo_dir: &Path,
    wants: &[String],
    haves: &[String],
    offloaded_oids: &HashSet<String>,
) -> Result<Vec<u8>, PackfileUriError> {
    let mut rev_spec = String::new();
    for w in wants {
        rev_spec.push_str(w);
        rev_spec.push('\n');
    }
    for h in haves {
        if run_git(git_bin, repo_dir, &["cat-file", "-e", &format!("{h}^{{commit}}")], None).is_ok() {
            rev_spec.push('^');
            rev_spec.push_str(h);
            rev_spec.push('\n');
        }
    }
    let obj_out = run_git(git_bin, repo_dir, &["rev-list", "--objects", "--stdin"], Some(rev_spec.as_bytes()))?;
    let mut pack_in = String::new();
    let mut seen = HashSet::new();
    for line in String::from_utf8_lossy(&obj_out).lines() {
        let Some(oid) = line.split_whitespace().next() else { continue };
        if !offloaded_oids.contains(oid) && seen.insert(oid.to_owned()) {
            pack_in.push_str(oid);
            pack_in.push('\n');
        }
    }
    run_git(git_bin, repo_dir, &["pack-objects", "--stdout"], Some(pack_in.as_bytes()))
}

pub(super) fn discover_repo_packs(
    git_bin: &Path,
    repo_dir: &Path,
    fmt: PackObjectFormat,
) -> Result<Vec<DiscoveredPack>, PackfileUriError> {
    let Ok(rd) = std::fs::read_dir(repo_dir.join("objects").join("pack")) else {
        return Ok(Vec::new());
    };
    let mut paths: Vec<PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "pack"))
        .collect();
    paths.sort();
    let trailer_len = fmt.oid_hex_len() / 2;
    let mut out = Vec::new();
    for pack_path in paths {
        let idx_path = pack_path.with_extension("idx");
        let (Ok(pack_bytes), Ok(idx_bytes)) = (std::fs::read(&pack_path), std::fs::read(&idx_path)) else {
            continue;
        };
        if pack_bytes.len() < 12 + trailer_len || idx_bytes.is_empty() {
            continue;
        }
        let Ok(vp_out) = run_git(git_bin, repo_dir, &["verify-pack", "-v", idx_path.to_str().unwrap_or_default()], None)
        else {
            continue;
        };
        let mut defined_oids = HashSet::new();
        let mut delta_bases = Vec::new();
        let mut commits = Vec::new();
        for line in String::from_utf8_lossy(&vp_out).lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 && matches!(parts[1], "commit" | "tree" | "blob" | "tag") {
                defined_oids.insert(parts[0].to_owned());
                if parts[1] == "commit" {
                    commits.push(parts[0].to_owned());
                }
                if parts.len() >= 7 {
                    delta_bases.push(parts[6].to_owned());
                }
            }
        }
        if commits.is_empty() {
            continue;
        }
        let is_standalone = delta_bases.iter().all(|base| defined_oids.contains(base));
        let pack_hash_hex = hex::encode(&pack_bytes[pack_bytes.len() - trailer_len..]);
        let pack_sha256_hex = hex::encode(Sha256::digest(&pack_bytes));
        out.push(DiscoveredPack {
            pack_oid: pack_sha256_hex.clone(),
            pack_hash_hex,
            pack_sha256_hex,
            idx_sha256_hex: hex::encode(Sha256::digest(&idx_bytes)),
            pack_bytes,
            idx_len: idx_bytes.len() as u64,
            commits,
            defined_oids,
            is_standalone,
        });
    }
    Ok(out)
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
    let cs_id = compute_commit_set_id(&CommitSetInput::new(*realm, seq, op_id, op_digest, vec![ce], CommitSetHead::Absent))
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
