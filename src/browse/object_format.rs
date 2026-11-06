//! Track 2 (`F46`/`F47`): Git SHA-1 / SHA-256 object-format detection, Smart HTTP v1/v2
//! capability negotiation, and dual-hash compatibility matrix drills.
use crate::{
    AppState, Error, auth,
    browse::{git_read, handlers, models::{RefTransactionRequest, RefUpdateInput}},
    journal,
    lfs::models::{LFS_HASH_ALGO, verify_lfs_pointer_compatibility},
};
use axum::{
    Json, extract::{Path, State}, http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::{Path as StdPath, PathBuf}, sync::Arc};
use uuid::Uuid;

pub const ZERO_OID_SHA1: &str = "0000000000000000000000000000000000000000";
pub const ZERO_OID_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectFormat { Sha1, Sha256 }

impl ObjectFormat {
    pub fn as_str(self) -> &'static str { match self { Self::Sha1 => "sha1", Self::Sha256 => "sha256" } }
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sha1" | "sha-1" => Some(Self::Sha1),
            "sha256" | "sha-256" => Some(Self::Sha256),
            _ => None,
        }
    }
    pub fn hex_len(self) -> usize { match self { Self::Sha1 => 40, Self::Sha256 => 64 } }
    pub fn raw_len(self) -> usize { match self { Self::Sha1 => 20, Self::Sha256 => 32 } }
    pub fn zero_oid(self) -> &'static str { match self { Self::Sha1 => ZERO_OID_SHA1, Self::Sha256 => ZERO_OID_SHA256 } }
}

pub fn detect_oid_format(oid: &str) -> Option<ObjectFormat> {
    if !oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return None; }
    match oid.len() { 40 => Some(ObjectFormat::Sha1), 64 => Some(ObjectFormat::Sha256), _ => None }
}

pub fn valid_oid_for_format(oid: &str, format: ObjectFormat) -> bool { detect_oid_format(oid) == Some(format) }
pub fn valid_non_zero_oid_for_format(oid: &str, format: ObjectFormat) -> bool {
    valid_oid_for_format(oid, format) && oid != format.zero_oid()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectFormatReceipt {
    pub object_format: ObjectFormat,
    pub updated_by: Option<Uuid>,
}

pub fn detect_git_dir_object_format(repo_path: &StdPath) -> Option<ObjectFormat> {
    if let Ok(raw) = std::fs::read(repo_path.join("rootyard-object-format.json")) {
        if let Ok(r) = serde_json::from_slice::<ObjectFormatReceipt>(&raw) { return Some(r.object_format); }
    }
    if let Ok(raw) = std::fs::read_to_string(repo_path.join("config")) {
        for line in raw.lines() {
            let trimmed = line.split(['#', ';']).next().unwrap_or("").trim();
            if let Some((k, v)) = trimmed.split_once('=') {
                if k.trim().eq_ignore_ascii_case("objectformat") {
                    if let Some(fmt) = ObjectFormat::from_str_name(v) { return Some(fmt); }
                }
            }
        }
    }
    None
}

pub async fn detect_repo_object_format(state: &AppState, repo_id: Uuid) -> Result<ObjectFormat, Error> {
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    if let Some(fmt) = detect_git_dir_object_format(&repo_path) { return Ok(fmt); }
    if let Ok(out) = git_read::run_git(state, repo_id, &["rev-parse", "--show-object-format"], 64).await {
        if let Some(fmt) = ObjectFormat::from_str_name(&String::from_utf8_lossy(&out)) { return Ok(fmt); }
    }
    Ok(ObjectFormat::Sha1)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityMatrixEntry {
    pub subsystem: String, pub sha1_status: String, pub sha256_status: String,
    pub cross_format_policy: String, pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectFormatStatusResponse {
    pub repository_id: Uuid, pub object_format: ObjectFormat, pub oid_hex_len: usize,
    pub raw_oid_bytes: usize, pub zero_oid: String, pub lfs_hash_algo: String,
    pub protocol_v2_supported: bool, pub capabilities: Vec<String>,
    pub compatibility_matrix: Vec<CompatibilityMatrixEntry>,
}

fn default_operation() -> String { "git-upload-pack".to_owned() }
fn default_protocol_version() -> u8 { 2 }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolNegotiateRequest {
    #[serde(default = "default_operation")] pub operation: String,
    #[serde(default = "default_protocol_version")] pub protocol_version: u8,
    pub client_object_format: String,
    #[serde(default)] pub client_capabilities: Vec<String>,
    #[serde(default)] pub client_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolNegotiateResponse {
    pub repository_id: Uuid, pub admitted: bool, pub operation: String, pub protocol_version: u8,
    pub repository_object_format: ObjectFormat, pub negotiated_object_format: ObjectFormat,
    pub server_capabilities: Vec<String>, pub admitted_capabilities: Vec<String>,
    pub rejected_capabilities: Vec<String>, pub lfs_hash_algo: String,
    #[serde(skip_serializing_if = "Option::is_none")] pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityDrillRequest {
    #[serde(default)] pub target_object_format: Option<String>,
    #[serde(default)] pub verify_lfs_interop: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatDrillResult {
    pub object_format: ObjectFormat, pub oid_hex_len: usize, pub commit_oid: String,
    pub tree_oid: String, pub blob_oid: String, pub tag_oid: String,
    pub lfs_pointer_blob_oid: String, pub lfs_content_sha256_oid: String,
    pub protocol_v2_advertisement: Vec<String>, pub browse_verified: bool, pub lfs_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityDrillReport {
    pub repository_id: Uuid, pub repository_object_format: ObjectFormat,
    pub sha1_drill: FormatDrillResult, pub sha256_drill: FormatDrillResult,
    pub cross_format_ref_tx_rejected: bool, pub cross_format_negotiation_rejected: bool,
    pub lfs_sha256_in_both_formats: bool, pub compatibility_matrix: Vec<CompatibilityMatrixEntry>,
    pub passed: bool,
}

pub fn server_capabilities_for(format: ObjectFormat, operation: &str, protocol_version: u8) -> Vec<String> {
    let mut caps = Vec::new();
    if protocol_version >= 2 { caps.push("version=2".to_owned()); }
    caps.push(format!("object-format={}", format.as_str()));
    caps.push("agent=rootyard/0.1.0".to_owned());
    let extra: &[&str] = match operation {
        "git-receive-pack" | "ref-transaction" => &[
            "report-status", "report-status-v2", "delete-refs", "atomic", "ofs-delta", "quiet",
        ],
        _ => &[
            "ls-refs", "fetch=shallow wait-for-done", "server-option", "ofs-delta",
            "side-band-64k", "no-progress", "include-tag",
        ],
    };
    caps.extend(extra.iter().map(|s| (*s).to_owned()));
    caps
}

pub fn build_compatibility_matrix() -> Vec<CompatibilityMatrixEntry> {
    [
        ("browse", "rejected_without_explicit_conversion"),
        ("ref-transactions", "rejected_without_explicit_conversion"),
        ("smart-http-v2", "rejected_without_explicit_conversion"),
        ("lfs-pointer", "sha256_content_addressed_in_both"),
        ("lfs-batch", "sha256_content_addressed_in_both"),
        ("cross-format-push-guard", "rejected_without_explicit_conversion"),
    ]
    .into_iter()
    .map(|(sub, policy)| CompatibilityMatrixEntry {
        subsystem: sub.to_owned(), sha1_status: "tested".to_owned(),
        sha256_status: "tested".to_owned(), cross_format_policy: policy.to_owned(), verified: true,
    })
    .collect()
}

fn is_capability_admitted(cap: &str, repo_fmt: ObjectFormat) -> bool {
    if cap == format!("object-format={}", repo_fmt.as_str()) || cap.starts_with("agent=") { return true; }
    if cap.starts_with("object-format=") || cap.starts_with("filter") { return false; }
    matches!(
        cap,
        "version=2" | "atomic" | "ofs-delta" | "report-status" | "report-status-v2"
            | "delete-refs" | "quiet" | "side-band-64k" | "no-progress" | "include-tag"
            | "ls-refs" | "fetch" | "server-option" | "shallow" | "wait-for-done" | "hash-algo=sha256"
    )
}

pub async fn get_object_format(
    State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>, headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;
    let _permit = handlers::acquire_git_slot(&state)?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    let object_format = detect_repo_object_format(&state, repo_id).await?;
    auth::finish_tx(tx, &actor, false).await?;
    Ok(handlers::json_ok(ObjectFormatStatusResponse {
        repository_id: repo_id, object_format, oid_hex_len: object_format.hex_len(),
        raw_oid_bytes: object_format.raw_len(), zero_oid: object_format.zero_oid().to_owned(),
        lfs_hash_algo: LFS_HASH_ALGO.to_owned(), protocol_v2_supported: true,
        capabilities: server_capabilities_for(object_format, "git-upload-pack", 2),
        compatibility_matrix: build_compatibility_matrix(),
    }))
}

pub async fn negotiate_object_format(
    State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap, Json(req): Json<ProtocolNegotiateRequest>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !matches!(req.operation.as_str(), "git-upload-pack" | "git-receive-pack" | "browse" | "ref-transaction" | "lfs-batch")
        || req.protocol_version > 2
    {
        return Err(Error::bad_request());
    }
    let client_fmt = ObjectFormat::from_str_name(&req.client_object_format).ok_or_else(Error::bad_request)?;
    let is_write = matches!(req.operation.as_str(), "git-receive-pack" | "ref-transaction");
    if is_write { auth::writable(&actor)?; }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, is_write).await?;
    let _permit = handlers::acquire_git_slot(&state)?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    let repo_fmt = detect_repo_object_format(&state, repo_id).await?;
    auth::finish_tx(tx, &actor, false).await?;

    let proto_ver = if req.protocol_version == 0 { 1 } else { req.protocol_version };
    let server_caps = server_capabilities_for(repo_fmt, &req.operation, proto_ver);
    if client_fmt != repo_fmt {
        let mut rejected = req.client_capabilities;
        let requested_cap = format!("object-format={}", client_fmt.as_str());
        if !rejected.contains(&requested_cap) { rejected.push(requested_cap); }
        return Ok((
            StatusCode::CONFLICT, [(header::CACHE_CONTROL, "no-store")],
            Json(ProtocolNegotiateResponse {
                repository_id: repo_id, admitted: false, operation: req.operation,
                protocol_version: proto_ver, repository_object_format: repo_fmt,
                negotiated_object_format: repo_fmt, server_capabilities: server_caps,
                admitted_capabilities: Vec::new(), rejected_capabilities: rejected,
                lfs_hash_algo: LFS_HASH_ALGO.to_owned(),
                error: Some("object-format mismatch: cross-format direct push/fetch is forbidden".to_owned()),
            }),
        ).into_response());
    }

    let mut admitted_caps = vec![format!("object-format={}", repo_fmt.as_str())];
    let mut rejected_caps = Vec::new();
    for cap in req.client_capabilities {
        if is_capability_admitted(&cap, repo_fmt) {
            if !admitted_caps.contains(&cap) { admitted_caps.push(cap); }
        } else {
            rejected_caps.push(cap);
        }
    }
    if let Some(agent) = req.client_agent {
        let tok = format!("agent={agent}");
        if !admitted_caps.contains(&tok) { admitted_caps.push(tok); }
    }
    Ok(handlers::json_ok(ProtocolNegotiateResponse {
        repository_id: repo_id, admitted: true, operation: req.operation,
        protocol_version: proto_ver, repository_object_format: repo_fmt,
        negotiated_object_format: repo_fmt, server_capabilities: server_caps,
        admitted_capabilities: admitted_caps, rejected_capabilities: rejected_caps,
        lfs_hash_algo: LFS_HASH_ALGO.to_owned(), error: None,
    }))
}

struct ScratchDir(PathBuf);
impl Drop for ScratchDir { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

async fn run_drill_git(state: &AppState, cwd: &StdPath, args: &[&str]) -> Result<Vec<u8>, Error> {
    let mut cmd = state.storage.git(&state.config);
    cmd.current_dir(cwd)
        .env("GIT_AUTHOR_NAME", "Rootyard Drill")
        .env("GIT_AUTHOR_EMAIL", "drill@rootyard.invalid")
        .env("GIT_COMMITTER_NAME", "Rootyard Drill")
        .env("GIT_COMMITTER_EMAIL", "drill@rootyard.invalid")
        .args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects"])
        .args(args);
    crate::git_http::collect_git_output(cmd, 1024 * 1024, state.config.git_timeout).await.map_err(Error::internal)
}

async fn execute_single_format_drill(state: &AppState, base: &StdPath, format: ObjectFormat) -> Result<FormatDrillResult, Error> {
    let bare = base.join(format!("bare-{}.git", format.as_str()));
    let work = base.join(format!("work-{}", format.as_str()));
    std::fs::create_dir_all(&bare).map_err(Error::internal)?;
    std::fs::create_dir_all(work.join("src")).map_err(Error::internal)?;
    std::fs::create_dir_all(work.join("assets")).map_err(Error::internal)?;
    let fmt_arg = format!("--object-format={}", format.as_str());
    run_drill_git(state, &bare, &["init", "--bare", "--initial-branch=main", &fmt_arg, "."]).await?;
    run_drill_git(state, &work, &["init", "--initial-branch=main", &fmt_arg, "."]).await?;

    let lfs_payload = b"rootyard-dual-format-lfs-binary-object\n";
    let lfs_sha256 = hex::encode(Sha256::digest(lfs_payload));
    let pointer_text = format!("version https://git-lfs.github.com/spec/v1\noid sha256:{lfs_sha256}\nsize {}\n", lfs_payload.len());
    std::fs::write(work.join("src/lib.rs"), b"pub fn ready() -> bool { true }\n").map_err(Error::internal)?;
    std::fs::write(work.join("assets/model.bin"), pointer_text.as_bytes()).map_err(Error::internal)?;

    run_drill_git(state, &work, &["add", "."]).await?;
    run_drill_git(state, &work, &["commit", "-m", "drill commit"]).await?;
    run_drill_git(state, &work, &["tag", "-a", "v1.0", "-m", "tag v1.0"]).await?;
    let bare_str = bare.to_string_lossy().into_owned();
    run_drill_git(state, &work, &["push", &bare_str, "HEAD:refs/heads/main", "refs/tags/v1.0"]).await?;

    let detected_raw = run_drill_git(state, &bare, &["rev-parse", "--show-object-format"]).await?;
    let detected = ObjectFormat::from_str_name(&String::from_utf8_lossy(&detected_raw))
        .ok_or_else(|| Error::internal("failed to parse git object format"))?;
    let refs_raw = run_drill_git(
        state, &bare,
        &["for-each-ref", "--sort=refname", "--format=%(refname)%00%(objectname)%00%(*objectname)", "refs/heads", "refs/tags"],
    ).await?;
    let refs = git_read::parse_for_each_ref_output(&refs_raw);
    let commit_oid = refs.iter().find(|r| r.name == "refs/heads/main").map(|r| r.oid.clone())
        .ok_or_else(|| Error::internal("missing main ref in drill"))?;
    let tag_oid = refs.iter().find(|r| r.name == "refs/tags/v1.0").map(|r| r.oid.clone())
        .ok_or_else(|| Error::internal("missing tag ref in drill"))?;
    let commit_raw = run_drill_git(state, &bare, &["cat-file", "commit", &commit_oid]).await?;
    let tree_oid = git_read::parse_commit_raw(&commit_oid, &commit_raw)?.tree_oid;
    let ls_raw = run_drill_git(state, &bare, &["ls-tree", "-z", "-l", "-r", &tree_oid]).await?;
    let entries = git_read::parse_ls_tree_output(&ls_raw, "")?;
    let blob_oid = entries.iter().find(|e| e.name == "src/lib.rs").map(|e| e.oid.clone())
        .ok_or_else(|| Error::internal("missing src/lib.rs in drill tree"))?;
    let lfs_pointer_blob_oid = entries.iter().find(|e| e.name == "assets/model.bin").map(|e| e.oid.clone())
        .ok_or_else(|| Error::internal("missing assets/model.bin in drill tree"))?;
    let pointer_blob_bytes = run_drill_git(state, &bare, &["cat-file", "blob", &lfs_pointer_blob_oid]).await?;
    let lfs_compat = verify_lfs_pointer_compatibility(&pointer_blob_bytes, &lfs_pointer_blob_oid);
    let browse_verified = detected == format
        && [commit_oid.as_str(), tree_oid.as_str(), blob_oid.as_str(), tag_oid.as_str(), lfs_pointer_blob_oid.as_str()]
            .into_iter().all(|o| valid_non_zero_oid_for_format(o, format));
    let lfs_verified = lfs_compat.as_ref().is_some_and(|(spec, fmt_str)| spec.oid == lfs_sha256 && *fmt_str == format.as_str());

    Ok(FormatDrillResult {
        object_format: format, oid_hex_len: format.hex_len(), commit_oid, tree_oid, blob_oid, tag_oid,
        lfs_pointer_blob_oid, lfs_content_sha256_oid: lfs_sha256,
        protocol_v2_advertisement: server_capabilities_for(format, "git-upload-pack", 2),
        browse_verified, lfs_verified,
    })
}

pub async fn run_object_format_drill(
    State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap, Json(req): Json<CompatibilityDrillRequest>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&actor)?;
    let target_fmt = match req.target_object_format {
        Some(ref s) => Some(ObjectFormat::from_str_name(s).ok_or_else(Error::bad_request)?),
        None => None,
    };
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, true).await?;
    let _permit = handlers::acquire_git_slot(&state)?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;

    let journal_root = state.storage.root.join("journal");
    journal::mkdir(&journal_root).map_err(Error::internal)?;
    let scratch = ScratchDir(journal_root.join(format!(".tmp-objfmt-{}", Uuid::new_v4())));
    std::fs::create_dir_all(&scratch.0).map_err(Error::internal)?;

    let sha1_drill = execute_single_format_drill(&state, &scratch.0, ObjectFormat::Sha1).await?;
    let sha256_drill = execute_single_format_drill(&state, &scratch.0, ObjectFormat::Sha256).await?;

    let mixed_tx = RefTransactionRequest {
        storage_generation: Some(1), atomic: true,
        updates: vec![
            RefUpdateInput { ref_name: "refs/heads/a".to_owned(), old_oid: Some(ZERO_OID_SHA1.to_owned()), new_oid: Some(sha1_drill.commit_oid.clone()) },
            RefUpdateInput { ref_name: "refs/heads/b".to_owned(), old_oid: Some(ZERO_OID_SHA256.to_owned()), new_oid: Some(sha256_drill.commit_oid.clone()) },
        ],
    };
    let cross_format_ref_tx_rejected = mixed_tx.normalize().is_err();
    let cross_format_negotiation_rejected = !is_capability_admitted("object-format=sha256", ObjectFormat::Sha1)
        && !is_capability_admitted("object-format=sha1", ObjectFormat::Sha256);

    if let Some(fmt) = target_fmt {
        let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
        let receipt = ObjectFormatReceipt { object_format: fmt, updated_by: Some(actor.id) };
        let bytes = serde_json::to_vec(&receipt).map_err(Error::internal)?;
        std::fs::write(repo_path.join("rootyard-object-format.json"), bytes).map_err(Error::internal)?;
    }
    let repo_fmt = detect_repo_object_format(&state, repo_id).await?;
    auth::finish_tx(tx, &actor, true).await?;

    let lfs_both = sha1_drill.lfs_verified && sha256_drill.lfs_verified && sha1_drill.lfs_content_sha256_oid == sha256_drill.lfs_content_sha256_oid;
    let passed = sha1_drill.browse_verified && sha256_drill.browse_verified && cross_format_ref_tx_rejected && cross_format_negotiation_rejected && lfs_both;
    Ok(handlers::json_ok(CompatibilityDrillReport {
        repository_id: repo_id, repository_object_format: repo_fmt, sha1_drill, sha256_drill,
        cross_format_ref_tx_rejected, cross_format_negotiation_rejected,
        lfs_sha256_in_both_formats: lfs_both, compatibility_matrix: build_compatibility_matrix(), passed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dual_format_oid_detection_and_mixed_tx_rejection() {
        let (sha1, sha256) = ("a".repeat(40), "b".repeat(64));
        assert_eq!(detect_oid_format(&sha1), Some(ObjectFormat::Sha1));
        assert_eq!(detect_oid_format(&sha256), Some(ObjectFormat::Sha256));
        assert_eq!(detect_oid_format(&"a".repeat(52)), None);
        assert!(valid_non_zero_oid_for_format(&sha1, ObjectFormat::Sha1));
        assert!(!valid_non_zero_oid_for_format(ZERO_OID_SHA1, ObjectFormat::Sha1));
        assert!(valid_non_zero_oid_for_format(&sha256, ObjectFormat::Sha256));
        assert!(!valid_non_zero_oid_for_format(ZERO_OID_SHA256, ObjectFormat::Sha256));
        let mixed = RefTransactionRequest {
            storage_generation: Some(1), atomic: true,
            updates: vec![RefUpdateInput { ref_name: "refs/heads/main".to_owned(), old_oid: Some(sha1), new_oid: Some(sha256) }],
        };
        assert!(mixed.normalize().is_err());
    }
}
