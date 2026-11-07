//! Durable CI pin/checkout sidecar handoff for online repository migration.
//!
//! The source's `ci-pins/<repo>` directory carries the exact pin intents and
//! pinned receipts that authorize CI checkout issuance. Those files are not
//! part of the Git repository, so a bare ref transfer would leave a migrated
//! primary unable to verify a previously issued pin. This module captures the
//! directory together with the measured final ref manifest, transfers it inside
//! the authenticated snapshot/delta frame, validates it against the target
//! tenant, repository, job, object id, object format, generation, operation and
//! journal sequence, and only publishes it after the cutover has committed.
//!
//! Released pins and cancelled jobs are tombstones: an intent whose retained CI
//! root is no longer in the measured manifest is dropped, never recreated. A
//! receipt without its retained root, an unmanaged CI root, a symlink, a
//! non-canonical path or a mismatched descriptor fails closed.
use crate::{
    AppState, Error, journal,
    sharding::{
        faults,
        models::conflict,
        replication::{self, RefManifest},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path as FsPath, PathBuf},
};
use uuid::Uuid;

pub(crate) const SIDECAR_VERSION: u32 = 1;
const CI_PREFIX: &str = "refs/rootyard-ci/jobs/";
const RETAINED_PREFIX: &str = "refs/rootyard-";
const MAX_SIDECAR_FILES: usize = crate::ci_pins::MAX_PINS * 2 + 16;
const MAX_SIDECAR_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SidecarFile {
    pub(crate) name: String,
    pub(crate) sha256: String,
    pub(crate) content: String,
}

/// A complete, deterministic image of the repository CI pin sidecars at the
/// measured final manifest. `files` is sorted by canonical name.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SidecarBundle {
    pub(crate) version: u32,
    pub(crate) repository_id: Uuid,
    pub(crate) operation_id: Uuid,
    pub(crate) source_generation: i64,
    pub(crate) target_generation: i64,
    pub(crate) refs_sha256: String,
    pub(crate) journal_sequence: i64,
    pub(crate) files: Vec<SidecarFile>,
    /// Every `refs/rootyard-*` root outside the CI job namespace that the
    /// measured manifest retained (backup, snapshot and hidden retention roots).
    pub(crate) retained_refs: Vec<String>,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_directory(path: &FsPath) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(conflict("unsafe CI sidecar directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::internal(error)),
    }
}

fn sync_directory(path: &FsPath) -> Result<(), Error> {
    File::open(path).and_then(|file| file.sync_all()).map_err(Error::internal)
}

fn sidecar_directory(root: &FsPath, repo_id: Uuid) -> PathBuf {
    root.join("ci-pins").join(repo_id.to_string())
}

fn canonical_job(name: &str, suffix: &str) -> Result<Uuid, Error> {
    let Some(raw) = name.strip_suffix(suffix) else {
        return Err(conflict("non-canonical CI sidecar filename"));
    };
    if raw.is_empty() || raw.contains('/') || raw.contains('\0') {
        return Err(conflict("unsafe CI sidecar filename"));
    }
    let job: Uuid = raw.parse().map_err(|_| conflict("non-canonical CI sidecar identity"))?;
    if name != format!("{job}{suffix}") {
        return Err(conflict("non-canonical CI sidecar identity"));
    }
    Ok(job)
}

struct Scanned {
    intents: BTreeMap<Uuid, (crate::ci_pins::Intent, Vec<u8>)>,
    receipts: BTreeMap<Uuid, Vec<u8>>,
}

fn scan_source(
    root: &FsPath,
    repo_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    source_generation: i64,
) -> Result<Scanned, Error> {
    let mut scanned = Scanned { intents: BTreeMap::new(), receipts: BTreeMap::new() };
    let directory = sidecar_directory(root, repo_id);
    if !safe_directory(&directory)? {
        return Ok(scanned);
    }
    let mut files = 0usize;
    let mut bytes = 0usize;
    for entry in fs::read_dir(&directory).map_err(Error::internal)? {
        let entry = entry.map_err(Error::internal)?;
        let name = entry.file_name().into_string().map_err(|_| conflict("non UTF-8 CI sidecar filename"))?;
        if name.starts_with(".tmp-") {
            continue;
        }
        files += 1;
        if files > MAX_SIDECAR_FILES {
            return Err(conflict("CI sidecar directory exceeds limit"));
        }
        let kind = entry.file_type().map_err(Error::internal)?;
        if !kind.is_file() || kind.is_symlink() {
            return Err(conflict("CI sidecar entry is not a regular file"));
        }
        let content = journal::read(&entry.path()).map_err(Error::internal)?;
        bytes = bytes.checked_add(content.len()).ok_or_else(|| conflict("CI sidecar bytes overflow"))?;
        if bytes > MAX_SIDECAR_BYTES {
            return Err(conflict("CI sidecar bytes exceed limit"));
        }
        let intent: crate::ci_pins::Intent =
            serde_json::from_slice(&content).map_err(|_| conflict("corrupt CI sidecar descriptor"))?;
        intent.validate().map_err(|_| conflict("invalid CI sidecar descriptor"))?;
        if name.ends_with(".pinned.json") {
            let job = canonical_job(&name, ".pinned.json")?;
            if scanned.receipts.insert(job, content).is_some() {
                return Err(conflict("duplicate CI pinned receipt"));
            }
            continue;
        }
        let job = canonical_job(&name, ".json")?;
        if intent.job_id != job
            || intent.repository_id != repo_id
            || intent.owner_id != owner_id
            || intent.object_format != object_format
            || intent.storage_generation != source_generation
            || intent.retention_ref != format!("{CI_PREFIX}{job}")
        {
            return Err(conflict("CI sidecar descriptor differs from its tenant or generation"));
        }
        if scanned.intents.insert(job, (intent, content)).is_some() {
            return Err(conflict("duplicate CI pin intent"));
        }
    }
    for (job, receipt) in &scanned.receipts {
        let Some((intent, _)) = scanned.intents.get(job) else {
            return Err(conflict("CI pinned receipt has no matching intent"));
        };
        if receipt != &serde_json::to_vec(intent).map_err(Error::internal)? {
            return Err(conflict("CI pinned receipt differs from its intent"));
        }
    }
    Ok(scanned)
}

fn manifest_ci_roots(manifest: &RefManifest) -> Result<BTreeMap<String, String>, Error> {
    let mut roots = BTreeMap::new();
    for (name, entry) in &manifest.refs {
        if !name.starts_with(CI_PREFIX) {
            continue;
        }
        if entry.symref.is_some() {
            return Err(conflict("CI retention root is symbolic"));
        }
        let job = name
            .strip_prefix(CI_PREFIX)
            .and_then(|raw| raw.parse::<Uuid>().ok())
            .ok_or_else(|| conflict("unmanaged CI retention root"))?;
        if name.as_str() != format!("{CI_PREFIX}{job}") {
            return Err(conflict("unmanaged CI retention root"));
        }
        roots.insert(name.clone(), entry.oid.clone());
    }
    Ok(roots)
}

/// Validate the source directory before any snapshot or drain starts, so a
/// symlink or a descriptor for another tenant/generation fails closed while the
/// source is still writable and no operation has drained it.
pub(crate) fn precheck(
    state: &AppState,
    repo_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    source_generation: i64,
) -> Result<(), Error> {
    scan_source(&state.storage.root, repo_id, owner_id, object_format, source_generation)?;
    Ok(())
}

/// Capture the exact sidecar image for the measured final manifest. Intents
/// without their retained root are released/cancelled tombstones and are
/// intentionally omitted; a receipt without its root is corruption.
pub(crate) fn capture(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    source_generation: i64,
    journal_sequence: i64,
    manifest: &RefManifest,
) -> Result<SidecarBundle, Error> {
    manifest.validate()?;
    if journal_sequence < 0 {
        return Err(conflict("invalid CI sidecar journal sequence"));
    }
    let scanned = scan_source(&state.storage.root, repo_id, owner_id, object_format, source_generation)?;
    let roots = manifest_ci_roots(manifest)?;
    let mut files = Vec::new();
    for (job, (intent, content)) in &scanned.intents {
        let Some(oid) = roots.get(&intent.retention_ref) else {
            if scanned.receipts.contains_key(job) {
                return Err(conflict("CI pinned receipt has no retained root"));
            }
            continue;
        };
        if oid != &intent.target_oid {
            return Err(conflict("CI intent differs from the measured retained root"));
        }
        files.push(SidecarFile {
            name: format!("{job}.json"),
            sha256: digest(content),
            content: String::from_utf8(content.clone()).map_err(|_| conflict("CI sidecar is not UTF-8 JSON"))?,
        });
        if let Some(receipt) = scanned.receipts.get(job) {
            files.push(SidecarFile {
                name: format!("{job}.pinned.json"),
                sha256: digest(receipt),
                content: String::from_utf8(receipt.clone()).map_err(|_| conflict("CI sidecar is not UTF-8 JSON"))?,
            });
        }
    }
    for retention in roots.keys() {
        let represented = scanned.intents.values().any(|(intent, _)| &intent.retention_ref == retention);
        if !represented {
            return Err(conflict("unmanaged CI retention root has no source intent"));
        }
    }
    files.sort_by(|left, right| left.name.cmp(&right.name));
    let mut retained_refs: Vec<String> = manifest
        .refs
        .keys()
        .filter(|name| name.starts_with(RETAINED_PREFIX) && !name.starts_with(CI_PREFIX))
        .cloned()
        .collect();
    retained_refs.sort();
    Ok(SidecarBundle {
        version: SIDECAR_VERSION,
        repository_id: repo_id,
        operation_id,
        source_generation,
        target_generation: source_generation + 1,
        refs_sha256: manifest.digest(),
        journal_sequence,
        files,
        retained_refs,
    })
}

fn validate_bundle(
    bundle: &SidecarBundle,
    repo_id: Uuid,
    operation_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    source_generation: i64,
    manifest: &RefManifest,
    refs_sha256: &str,
    journal_sequence: i64,
) -> Result<(), Error> {
    if bundle.version != SIDECAR_VERSION
        || bundle.repository_id != repo_id
        || bundle.operation_id != operation_id
        || bundle.source_generation != source_generation
        || bundle.target_generation != source_generation + 1
        || bundle.refs_sha256 != refs_sha256
        || bundle.journal_sequence != journal_sequence
        || !valid_digest(&bundle.refs_sha256)
        || manifest.digest() != refs_sha256
        || bundle.files.len() > MAX_SIDECAR_FILES
    {
        return Err(conflict("CI sidecar bundle differs from the measured transfer"));
    }
    let roots = manifest_ci_roots(manifest)?;
    let mut names = BTreeSet::new();
    let mut intents: BTreeMap<Uuid, crate::ci_pins::Intent> = BTreeMap::new();
    let mut receipts: BTreeSet<Uuid> = BTreeSet::new();
    let mut total = 0usize;
    for file in &bundle.files {
        total = total.checked_add(file.content.len()).ok_or_else(|| conflict("CI sidecar bytes overflow"))?;
        if total > MAX_SIDECAR_BYTES || digest(file.content.as_bytes()) != file.sha256 {
            return Err(conflict("CI sidecar content digest mismatch"));
        }
        if !names.insert(file.name.clone()) {
            return Err(conflict("duplicate CI sidecar filename"));
        }
        let receipt = file.name.ends_with(".pinned.json");
        let job = canonical_job(&file.name, if receipt { ".pinned.json" } else { ".json" })?;
        let intent: crate::ci_pins::Intent =
            serde_json::from_str(&file.content).map_err(|_| conflict("corrupt transferred CI descriptor"))?;
        intent.validate().map_err(|_| conflict("invalid transferred CI descriptor"))?;
        if intent.job_id != job
            || intent.repository_id != repo_id
            || intent.owner_id != owner_id
            || intent.object_format != object_format
            || intent.storage_generation != source_generation
            || intent.retention_ref != format!("{CI_PREFIX}{job}")
        {
            return Err(conflict("transferred CI descriptor differs from its tenant or generation"));
        }
        let oid = roots
            .get(&intent.retention_ref)
            .ok_or_else(|| conflict("transferred CI intent has no measured retained root"))?;
        if oid != &intent.target_oid {
            return Err(conflict("transferred CI intent differs from the measured root"));
        }
        if receipt {
            let source = intents.get(&job).ok_or_else(|| conflict("transferred CI receipt has no intent"))?;
            if source != &intent {
                return Err(conflict("transferred CI receipt differs from its intent"));
            }
            receipts.insert(job);
        } else if intents.insert(job, intent).is_some() {
            return Err(conflict("duplicate transferred CI intent"));
        }
    }
    if receipts.len() > intents.len() {
        return Err(conflict("transferred CI receipts exceed intents"));
    }
    for retention in roots.keys() {
        let represented = intents.values().any(|intent| &intent.retention_ref == retention);
        if !represented {
            return Err(conflict("transferred CI bundle omits a measured retention root"));
        }
    }
    for name in &bundle.retained_refs {
        if !name.starts_with(RETAINED_PREFIX) || !manifest.refs.contains_key(name) {
            return Err(conflict("transferred sidecar omits a measured retained root"));
        }
    }
    Ok(())
}

pub(crate) fn progress_path(state: &AppState, operation_id: Uuid) -> Result<PathBuf, Error> {
    Ok(replication::staging_root(state)?.join(format!("{operation_id}.sidecar.json")))
}

pub(crate) fn staged_path(state: &AppState, operation_id: Uuid) -> Result<PathBuf, Error> {
    Ok(replication::staging_root(state)?.join(format!("{operation_id}.sidecar")))
}

/// Persist the captured sidecar image before its transfer so a restart can
/// prove the exact measured operation sequence it is resuming.
pub(crate) fn write_progress(state: &AppState, bundle: &SidecarBundle) -> Result<(), Error> {
    let bytes = serde_json::to_vec(bundle).map_err(Error::internal)?;
    if bytes.len() > MAX_SIDECAR_BYTES {
        return Err(conflict("CI sidecar progress exceeds limit"));
    }
    journal::atomic(&progress_path(state, bundle.operation_id)?, &bytes, true).map_err(Error::internal)
}

pub(crate) fn read_progress(
    state: &AppState,
    operation_id: Uuid,
    repository_id: Uuid,
) -> Result<Option<SidecarBundle>, Error> {
    let path = progress_path(state, operation_id)?;
    if !journal::exists(&path).map_err(Error::internal)? {
        return Ok(None);
    }
    let bytes = journal::read(&path).map_err(Error::internal)?;
    let bundle: SidecarBundle = serde_json::from_slice(&bytes).map_err(|_| conflict("corrupt CI sidecar progress"))?;
    if bundle.repository_id != repository_id || bundle.operation_id != operation_id {
        return Err(conflict("CI sidecar progress belongs to another operation"));
    }
    Ok(Some(bundle))
}

/// Validate and durably stage a transferred bundle. The live `ci-pins`
/// directory is not touched here: only a committed cutover may publish.
pub(crate) fn stage_incoming(
    state: &AppState,
    bundle: &SidecarBundle,
    repo_id: Uuid,
    operation_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    manifest: &RefManifest,
) -> Result<(), Error> {
    validate_bundle(
        bundle,
        repo_id,
        operation_id,
        owner_id,
        object_format,
        bundle.source_generation,
        manifest,
        &bundle.refs_sha256,
        bundle.journal_sequence,
    )?;
    let root = replication::staging_root(state)?;
    let temporary = root.join(format!(".{operation_id}.sidecar.tmp-{}", Uuid::new_v4()));
    if safe_directory(&temporary)? {
        fs::remove_dir_all(&temporary).map_err(Error::internal)?;
    }
    fs::create_dir(&temporary).map_err(Error::internal)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700)).map_err(Error::internal)?;
    let result = (|| {
        for file in &bundle.files {
            let path = temporary.join(&file.name);
            if path.parent() != Some(temporary.as_path()) {
                return Err(conflict("transferred CI sidecar path escapes its directory"));
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
                .map_err(Error::internal)?;
            output.write_all(file.content.as_bytes()).map_err(Error::internal)?;
            output.sync_all().map_err(Error::internal)?;
        }
        let manifest_path = temporary.join("bundle.json");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&manifest_path)
            .map_err(Error::internal)?;
        output.write_all(&serde_json::to_vec(bundle).map_err(Error::internal)?).map_err(Error::internal)?;
        output.sync_all().map_err(Error::internal)?;
        sync_directory(&temporary)?;
        Ok::<_, Error>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    let final_path = staged_path(state, operation_id)?;
    if safe_directory(&final_path)? {
        fs::remove_dir_all(&final_path).map_err(Error::internal)?;
    }
    fs::rename(&temporary, &final_path).map_err(Error::internal)?;
    sync_directory(&root)?;
    write_progress(state, bundle)?;
    Ok(())
}

fn desired_files(
    bundle: &SidecarBundle,
    owner_id: Uuid,
    object_format: &str,
    generation: i64,
    manifest: &RefManifest,
) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    let roots = manifest_ci_roots(manifest)?;
    let mut intents: BTreeMap<Uuid, crate::ci_pins::Intent> = BTreeMap::new();
    let mut receipts: BTreeSet<Uuid> = BTreeSet::new();
    for file in &bundle.files {
        let is_receipt = file.name.ends_with(".pinned.json");
        let job = canonical_job(&file.name, if is_receipt { ".pinned.json" } else { ".json" })?;
        if is_receipt {
            receipts.insert(job);
        } else {
            let intent: crate::ci_pins::Intent =
                serde_json::from_str(&file.content).map_err(|_| conflict("corrupt staged CI descriptor"))?;
            intents.insert(job, intent);
        }
    }
    let mut desired = BTreeMap::new();
    for (job, intent) in intents {
        if intent.repository_id != bundle.repository_id
            || intent.owner_id != owner_id
            || intent.object_format != object_format
            || intent.storage_generation != bundle.source_generation
            || intent.job_id != job
        {
            return Err(conflict("staged CI descriptor differs from the target tenant"));
        }
        let Some(oid) = roots.get(&intent.retention_ref) else {
            // The retention root was released after the cutover committed.
            // Never resurrect its intent or receipt on the new primary.
            continue;
        };
        if oid != &intent.target_oid {
            return Err(conflict("staged CI intent differs from the target retained root"));
        }
        // Preserve the exact old-generation intent and receipt as retention
        // evidence. They intentionally do not authorize a checkout under the
        // new generation: a fresh job/attempt must issue a fresh pin.
        let _ = generation;
        desired.insert(format!("{job}.json"), serde_json::to_vec(&intent).map_err(Error::internal)?);
        if receipts.contains(&job) {
            desired.insert(format!("{job}.pinned.json"), serde_json::to_vec(&intent).map_err(Error::internal)?);
        }
    }
    for name in &bundle.retained_refs {
        if !manifest.refs.contains_key(name) {
            return Err(conflict("target lost a retained backup or snapshot root"));
        }
    }
    Ok(desired)
}

fn publish_directory(root: &FsPath, repo_id: Uuid, desired: &BTreeMap<String, Vec<u8>>) -> Result<(), Error> {
    let base = root.join("ci-pins");
    if !safe_directory(&base)? {
        journal::mkdir(&base).map_err(Error::internal)?;
    }
    let temporary = base.join(format!(".{repo_id}.stage-{}", Uuid::new_v4()));
    fs::create_dir(&temporary).map_err(Error::internal)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700)).map_err(Error::internal)?;
    let result = (|| {
        for (name, content) in desired {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(temporary.join(name))
                .map_err(Error::internal)?;
            file.write_all(content).map_err(Error::internal)?;
            file.sync_all().map_err(Error::internal)?;
        }
        sync_directory(&temporary)?;
        Ok::<_, Error>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    let destination = base.join(repo_id.to_string());
    let had_previous = safe_directory(&destination)?;
    if had_previous {
        if same_directory(&destination, &temporary)? {
            let _ = fs::remove_dir_all(&temporary);
            return Ok(());
        }
        let retired = base.join(format!(".{repo_id}.retired-{}", Uuid::new_v4()));
        fs::rename(&destination, &retired).map_err(Error::internal)?;
        if let Err(error) = fs::rename(&temporary, &destination) {
            let _ = fs::rename(&retired, &destination);
            return Err(Error::internal(error));
        }
        sync_directory(&base)?;
        let _ = fs::remove_dir_all(&retired);
        return Ok(());
    }
    fs::rename(&temporary, &destination).map_err(Error::internal)?;
    sync_directory(&base)?;
    Ok(())
}

fn same_directory(left: &FsPath, right: &FsPath) -> Result<bool, Error> {
    let read = |path: &FsPath| -> Result<BTreeMap<String, Vec<u8>>, Error> {
        let mut values = BTreeMap::new();
        for entry in fs::read_dir(path).map_err(Error::internal)? {
            let entry = entry.map_err(Error::internal)?;
            let kind = entry.file_type().map_err(Error::internal)?;
            if !kind.is_file() || kind.is_symlink() {
                return Ok(BTreeMap::new());
            }
            let name = entry.file_name().into_string().map_err(|_| conflict("non UTF-8 CI sidecar filename"))?;
            values.insert(name, journal::read(&entry.path()).map_err(Error::internal)?);
        }
        Ok(values)
    };
    Ok(read(left)? == read(right)?)
}

/// Publish a committed operation's staged bundle. Returns whether a staged
/// directory existed.
pub(crate) async fn finalize(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
    generation: i64,
    require_staged: bool,
) -> Result<bool, Error> {
    let staged = staged_path(state, operation_id)?;
    if !safe_directory(&staged)? {
        if require_staged {
            return Err(conflict("target CI sidecar staging is missing"));
        }
        return Ok(false);
    }
    let manifest_path = staged.join("bundle.json");
    if !journal::exists(&manifest_path).map_err(Error::internal)? {
        return Err(conflict("target CI sidecar staging has no bundle"));
    }
    let bundle: SidecarBundle = serde_json::from_slice(&journal::read(&manifest_path).map_err(Error::internal)?)
        .map_err(|_| conflict("corrupt staged CI sidecar bundle"))?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_one(
            "SELECT owner_id,object_format FROM repositories WHERE id=$1 AND storage_generation=$2",
            &[&repo_id, &generation],
        )
        .await
        .map_err(|_| conflict("repository generation changed before CI sidecar publication"))?;
    let owner_id: Uuid = row.get(0);
    let object_format: String = row.get(1);
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let manifest = replication::read_manifest_plain(state, &repo_path).await?;
    validate_bundle(
        &bundle,
        repo_id,
        operation_id,
        owner_id,
        &object_format,
        bundle.source_generation,
        &manifest,
        &bundle.refs_sha256,
        bundle.journal_sequence,
    )?;
    if bundle.target_generation != generation || bundle.source_generation + 1 != generation {
        return Err(conflict("staged CI sidecar generation differs from the target"));
    }
    let desired = desired_files(&bundle, owner_id, &object_format, generation, &manifest)?;
    faults::hit(
        &state.storage.root,
        "target-sidecar-before-publish",
        serde_json::json!({"repository_id": repo_id, "operation_id": operation_id, "files": desired.len()}),
    );
    publish_directory(&state.storage.root, repo_id, &desired)?;
    let _ = fs::remove_dir_all(&staged);
    let _ = fs::remove_file(progress_path(state, operation_id)?);
    Ok(true)
}

/// Startup recovery: republish a committed cutover whose sidecar finalization
/// was interrupted, and discard staging for operations that never committed.
pub async fn reconcile_startup(state: &AppState) -> Result<(), Error> {
    let Ok(Some(node_id)) = crate::sharding::transport::node_id() else {
        return Ok(());
    };
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT DISTINCT ON (o.repository_id) o.id,o.repository_id,p.storage_generation \
             FROM shard_replication_operations o \
             JOIN repository_shard_routes r ON r.repository_id=o.repository_id \
             JOIN repositories p ON p.id=o.repository_id \
             WHERE o.target_node_id=$1 AND o.state='completed' \
               AND r.primary_node_id=$1 AND p.storage_generation=o.source_generation+1 \
             ORDER BY o.repository_id,o.updated_at DESC LIMIT 32",
            &[&node_id],
        )
        .await
        .map_err(Error::internal)?;
    let mut committed = BTreeSet::new();
    for row in rows {
        let operation_id: Uuid = row.get(0);
        let repository_id: Uuid = row.get(1);
        let generation: i64 = row.get(2);
        committed.insert(operation_id);
        if let Err(error) = finalize(state, repository_id, operation_id, generation, false).await {
            eprintln!("rootyard: CI sidecar finalization for {} deferred: {}", operation_id, error.1);
        }
    }
    let staging = replication::staging_root(state)?;
    for entry in fs::read_dir(&staging).map_err(Error::internal)? {
        let entry = entry.map_err(Error::internal)?;
        let name = entry.file_name().into_string().map_err(|_| conflict("non UTF-8 staging filename"))?;
        let Some(raw) = name.strip_suffix(".sidecar") else {
            continue;
        };
        let Ok(operation_id) = raw.parse::<Uuid>() else {
            continue;
        };
        if committed.contains(&operation_id) {
            continue;
        }
        let kind = entry.file_type().map_err(Error::internal)?;
        if kind.is_dir() && !kind.is_symlink() {
            let _ = fs::remove_dir_all(entry.path());
        } else {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}
