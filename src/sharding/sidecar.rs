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
//! non-canonical path or a mismatched descriptor fails closed. Publication is
//! serialized with ordinary pin issuance by the repository exclusive guard and
//! merges every legitimately accepted new-generation live intent instead of
//! replacing the live directory with the old source image.
use crate::{
    AppState, Error, journal,
    sharding::{
        faults, locks,
        models::conflict,
        replication::{self, RefManifest},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublishedFile {
    name: String,
    sha256: String,
}

/// Durable proof that a committed operation's sidecar image was published.
/// Retries after a lost HTTP response and startup recovery consult this receipt
/// instead of treating an intentionally removed staging directory as failure.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublicationReceipt {
    version: u32,
    repository_id: Uuid,
    operation_id: Uuid,
    target_generation: i64,
    refs_sha256: String,
    journal_sequence: i64,
    route_epoch: i64,
    fencing_token: i64,
    files: Vec<PublishedFile>,
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

fn read_sidecar_directory(
    directory: &FsPath,
    repo_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    expected_generation: Option<i64>,
) -> Result<Scanned, Error> {
    let mut scanned = Scanned { intents: BTreeMap::new(), receipts: BTreeMap::new() };
    if !safe_directory(directory)? {
        return Ok(scanned);
    }
    let mut files = 0usize;
    let mut bytes = 0usize;
    for entry in fs::read_dir(directory).map_err(Error::internal)? {
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
        if let Some(generation) = expected_generation
            && (intent.storage_generation <= 0 || intent.storage_generation > generation)
        {
            return Err(conflict("CI sidecar has a future or invalid historical generation"));
        }
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

fn scan_source(
    root: &FsPath,
    repo_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    source_generation: i64,
) -> Result<Scanned, Error> {
    read_sidecar_directory(&sidecar_directory(root, repo_id), repo_id, owner_id, object_format, Some(source_generation))
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

fn bundle_intents(
    bundle: &SidecarBundle,
    repo_id: Uuid,
    operation_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    source_generation: i64,
) -> Result<(BTreeMap<Uuid, crate::ci_pins::Intent>, BTreeSet<Uuid>), Error> {
    if bundle.version != SIDECAR_VERSION
        || bundle.repository_id != repo_id
        || bundle.operation_id != operation_id
        || bundle.source_generation != source_generation
        || bundle.target_generation != source_generation + 1
        || bundle.files.len() > MAX_SIDECAR_FILES
        || bundle.journal_sequence < 0
        || !valid_digest(&bundle.refs_sha256)
    {
        return Err(conflict("CI sidecar bundle differs from the measured transfer"));
    }
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
            || intent.storage_generation <= 0
            || intent.storage_generation > source_generation
            || intent.retention_ref != format!("{CI_PREFIX}{job}")
        {
            return Err(conflict("transferred CI descriptor differs from its tenant or generation"));
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
    Ok((intents, receipts))
}

/// Strict transfer-time validation: the bundle must describe the exact
/// measured refs digest and every measured CI retention root.
fn validate_bundle_stage(
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
    let (intents, _) = bundle_intents(bundle, repo_id, operation_id, owner_id, object_format, source_generation)?;
    if bundle.refs_sha256 != refs_sha256
        || manifest.digest() != refs_sha256
        || bundle.journal_sequence != journal_sequence
    {
        return Err(conflict("CI sidecar bundle differs from the measured transfer"));
    }
    let roots = manifest_ci_roots(manifest)?;
    for intent in intents.values() {
        let oid = roots
            .get(&intent.retention_ref)
            .ok_or_else(|| conflict("transferred CI intent has no measured retained root"))?;
        if oid != &intent.target_oid {
            return Err(conflict("transferred CI intent differs from the measured root"));
        }
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

fn receipt_path(state: &AppState, operation_id: Uuid) -> Result<PathBuf, Error> {
    Ok(replication::staging_root(state)?.join(format!("{operation_id}.sidecar.published.json")))
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

/// Decode a persisted progress record and prove it belongs to this exact
/// operation and repository, so evidence written for another handoff can never
/// be read as proof for this one.
fn decode_progress(bytes: &[u8], operation_id: Uuid, repository_id: Uuid) -> Result<SidecarBundle, Error> {
    let bundle: SidecarBundle = serde_json::from_slice(bytes).map_err(|_| conflict("corrupt CI sidecar progress"))?;
    if bundle.repository_id != repository_id || bundle.operation_id != operation_id {
        return Err(conflict("CI sidecar progress belongs to another operation"));
    }
    Ok(bundle)
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
    decode_progress(&bytes, operation_id, repository_id).map(Some)
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
    validate_bundle_stage(
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

/// New-generation files written by the new primary after cutover. They are
/// legitimate and must survive finalization; they are only accepted when their
/// retained root is in the current manifest and their receipt matches.
fn scan_live_new_generation(
    directory: &FsPath,
    repo_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    target_generation: i64,
    source_generation: i64,
    manifest: &RefManifest,
) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    let scanned = read_sidecar_directory(directory, repo_id, owner_id, object_format, None)?;
    let roots = manifest_ci_roots(manifest)?;
    let mut values = BTreeMap::new();
    for (job, (intent, content)) in &scanned.intents {
        if intent.storage_generation <= source_generation {
            // Historical retention evidence is carried verbatim by the
            // bundle and must not be reclassified as a fresh target pin.
            continue;
        }
        if intent.storage_generation != target_generation {
            return Err(conflict("live CI sidecar has an unexpected storage generation"));
        }
        let Some(oid) = roots.get(&intent.retention_ref) else {
            return Err(conflict("live CI intent has no retained root"));
        };
        if oid != &intent.target_oid {
            return Err(conflict("live CI intent differs from its retained root"));
        }
        values.insert(format!("{job}.json"), content.clone());
        if let Some(receipt) = scanned.receipts.get(job) {
            values.insert(format!("{job}.pinned.json"), receipt.clone());
        }
    }
    for job in scanned.receipts.keys() {
        if !scanned.intents.contains_key(job) {
            return Err(conflict("live CI receipt has no intent"));
        }
    }
    Ok(values)
}

fn desired_files(
    bundle: &SidecarBundle,
    repo_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    live: &BTreeMap<String, Vec<u8>>,
    manifest: &RefManifest,
) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    let (intents, receipts) =
        bundle_intents(bundle, repo_id, bundle.operation_id, owner_id, object_format, bundle.source_generation)?;
    let roots = manifest_ci_roots(manifest)?;
    let mut desired: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (job, intent) in intents {
        let Some(oid) = roots.get(&intent.retention_ref) else {
            if receipts.contains(&job) {
                return Err(conflict("CI pinned receipt has no retained root"));
            }
            continue;
        };
        if oid != &intent.target_oid {
            return Err(conflict("CI intent differs from the target retained root"));
        }
        let bytes = serde_json::to_vec(&intent).map_err(Error::internal)?;
        if let Some(existing) = desired.insert(format!("{job}.json"), bytes.clone())
            && existing != bytes
        {
            return Err(conflict("conflicting CI intent images during finalization"));
        }
        if receipts.contains(&job) {
            desired.insert(format!("{job}.pinned.json"), bytes);
        }
    }
    for (name, content) in live {
        if let Some(existing) = desired.insert(name.clone(), content.clone())
            && existing != *content
        {
            return Err(conflict("new-primary CI pin conflicts with transferred evidence"));
        }
    }
    for name in &bundle.retained_refs {
        if !manifest.refs.contains_key(name) {
            return Err(conflict("target lost a retained backup or snapshot root"));
        }
    }
    Ok(desired)
}

fn directory_image(path: &FsPath) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    let mut values = BTreeMap::new();
    for entry in fs::read_dir(path).map_err(Error::internal)? {
        let entry = entry.map_err(Error::internal)?;
        let name = entry.file_name().into_string().map_err(|_| conflict("non UTF-8 CI sidecar filename"))?;
        if name.starts_with(".tmp-") {
            continue;
        }
        let kind = entry.file_type().map_err(Error::internal)?;
        if !kind.is_file() || kind.is_symlink() {
            return Err(conflict("unsafe entry in live CI sidecar directory"));
        }
        values.insert(name, journal::read(&entry.path()).map_err(Error::internal)?);
    }
    Ok(values)
}

fn rename_exchange(left: &FsPath, right: &FsPath) -> std::io::Result<()> {
    let left = CString::new(left.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
    let right = CString::new(right.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
    // RENAME_EXCHANGE is 2 on Linux; the syscall atomically swaps both names.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            left.as_ptr(),
            libc::AT_FDCWD,
            right.as_ptr(),
            2 as libc::c_uint,
        )
    };
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

fn publish_directory(root: &FsPath, repo_id: Uuid, desired: &BTreeMap<String, Vec<u8>>) -> Result<(), Error> {
    let base = root.join("ci-pins");
    if !safe_directory(&base)? {
        journal::mkdir(&base).map_err(Error::internal)?;
    }
    if let Ok(meta) = fs::symlink_metadata(&base)
        && (meta.file_type().is_symlink() || meta.uid() != unsafe { libc::geteuid() })
    {
        return Err(conflict("unsafe live CI sidecar root"));
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
    if !safe_directory(&destination)? {
        fs::rename(&temporary, &destination).map_err(Error::internal)?;
        sync_directory(&base)?;
        return Ok(());
    }
    let desired_image: BTreeMap<String, Vec<u8>> =
        desired.iter().map(|(name, value)| (name.clone(), value.clone())).collect();
    if directory_image(&destination)? == desired_image {
        let _ = fs::remove_dir_all(&temporary);
        return Ok(());
    }
    match rename_exchange(&temporary, &destination) {
        Ok(()) => {
            sync_directory(&base)?;
            let _ = fs::remove_dir_all(&temporary);
            Ok(())
        }
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) || error.raw_os_error() == Some(libc::ENOSYS) => {
            let retired = base.join(format!(".{repo_id}.retired-{}", Uuid::new_v4()));
            fs::rename(&destination, &retired).map_err(Error::internal)?;
            if let Err(second) = fs::rename(&temporary, &destination) {
                let _ = fs::rename(&retired, &destination);
                return Err(Error::internal(second));
            }
            sync_directory(&base)?;
            let _ = fs::remove_dir_all(&retired);
            Ok(())
        }
        Err(error) => Err(Error::internal(error)),
    }
}

async fn operation_context(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
    generation: i64,
    expected_route: Option<(i64, i64)>,
) -> Result<(Uuid, i64, String, i64, i64, i64, String), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT o.state,o.source_generation,o.refs_sha256,o.journal_sequence,o.target_node_id, \
                    p.owner_id,p.object_format,p.storage_generation, \
                    r.primary_node_id,r.route_epoch,r.fencing_token,r.draining,r.read_only_degraded \
             FROM shard_replication_operations o \
             JOIN repositories p ON p.id=o.repository_id \
             LEFT JOIN repository_shard_routes r ON r.repository_id=o.repository_id \
             WHERE o.id=$1 AND o.repository_id=$2",
            &[&operation_id, &repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let op_state: String = row.get(0);
    let source_generation: i64 = row.get(1);
    let refs_sha256: Option<String> = row.get(2);
    let journal_sequence: Option<i64> = row.get(3);
    let target: String = row.get(4);
    let owner_id: Uuid = row.get(5);
    let object_format: String = row.get(6);
    let repo_generation: i64 = row.get(7);
    let primary: Option<String> = row.get(8);
    let route_epoch: Option<i64> = row.get(9);
    let fencing_token: Option<i64> = row.get(10);
    let draining: Option<bool> = row.get(11);
    let degraded: Option<bool> = row.get(12);
    let node = crate::sharding::transport::node_id()?.unwrap_or_default();
    let (Some(primary), Some(route_epoch), Some(fencing_token)) = (primary, route_epoch, fencing_token) else {
        return Err(conflict("committed cutover has no shard route"));
    };
    if op_state != "completed"
        || target != node
        || primary != node
        || draining != Some(false)
        || degraded != Some(false)
        || source_generation + 1 != generation
        || repo_generation != generation
    {
        return Err(conflict("CI sidecar finalization differs from the committed route"));
    }
    if let Some((expected_epoch, expected_token)) = expected_route
        && (route_epoch != expected_epoch || fencing_token != expected_token)
    {
        return Err(conflict("CI sidecar finalization envelope raced the shard route"));
    }
    let refs_sha256 = refs_sha256.ok_or_else(|| conflict("committed operation has no ref digest"))?;
    Ok((
        owner_id,
        source_generation,
        object_format,
        route_epoch,
        fencing_token,
        journal_sequence.unwrap_or(-1),
        refs_sha256,
    ))
}

async fn verify_published_receipt(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
    generation: i64,
    expected_route: Option<(i64, i64)>,
    require_staged: bool,
) -> Result<bool, Error> {
    let path = receipt_path(state, operation_id)?;
    if !journal::exists(&path).map_err(Error::internal)? {
        return if require_staged { Err(conflict("target CI sidecar staging is missing")) } else { Ok(false) };
    }
    let receipt: PublicationReceipt = serde_json::from_slice(&journal::read(&path).map_err(Error::internal)?)
        .map_err(|_| conflict("corrupt CI sidecar publication receipt"))?;
    let (owner_id, source_generation, object_format, route_epoch, fencing_token, sequence, refs_sha256) =
        operation_context(state, repo_id, operation_id, generation, expected_route).await?;
    if receipt.version != SIDECAR_VERSION
        || receipt.repository_id != repo_id
        || receipt.operation_id != operation_id
        || receipt.target_generation != generation
        || receipt.journal_sequence != sequence
        || receipt.refs_sha256 != refs_sha256
        || receipt.route_epoch != route_epoch
        || receipt.fencing_token != fencing_token
    {
        return Err(conflict("CI sidecar publication receipt differs from the committed operation"));
    }
    let guard = locks::exclusive(state, repo_id).await?;
    guard.ensure_active()?;
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let manifest = replication::read_manifest_plain(state, &repo_path).await?;
    let _ = (source_generation, object_format, owner_id);
    let directory = sidecar_directory(&state.storage.root, repo_id);
    if !safe_directory(&directory)? {
        // Every receipt file may have been legitimately released already.
        let all_released = receipt.files.iter().all(|file| {
            let job = file
                .name
                .strip_suffix(".pinned.json")
                .or_else(|| file.name.strip_suffix(".json"))
                .and_then(|raw| raw.parse::<Uuid>().ok());
            job.is_some_and(|job| !manifest.refs.contains_key(&format!("{CI_PREFIX}{job}")))
        });
        if all_released {
            return Ok(true);
        }
        return Err(conflict("CI sidecar publication receipt has no live directory"));
    }
    for file in &receipt.files {
        let path = directory.join(&file.name);
        match journal::read(&path) {
            Ok(content) => {
                if digest(&content) != file.sha256 {
                    return Err(conflict("published CI sidecar file changed"));
                }
            }
            Err(_) => {
                // A legitimate post-publication release removes the intent,
                // receipt and retained root together. Never re-publish it; a
                // missing file whose retained root still exists is corruption.
                let job = file
                    .name
                    .strip_suffix(".pinned.json")
                    .or_else(|| file.name.strip_suffix(".json"))
                    .and_then(|raw| raw.parse::<Uuid>().ok())
                    .ok_or_else(|| conflict("publication receipt has a non-canonical file"))?;
                if manifest.refs.contains_key(&format!("{CI_PREFIX}{job}")) {
                    return Err(conflict("published CI sidecar file is missing"));
                }
            }
        }
    }
    guard.ensure_active()?;
    Ok(true)
}

fn write_receipt(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
    generation: i64,
    refs_sha256: &str,
    journal_sequence: i64,
    route_epoch: i64,
    fencing_token: i64,
    desired: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Error> {
    let receipt = PublicationReceipt {
        version: SIDECAR_VERSION,
        repository_id: repo_id,
        operation_id,
        target_generation: generation,
        refs_sha256: refs_sha256.to_owned(),
        journal_sequence,
        route_epoch,
        fencing_token,
        files: desired
            .iter()
            .map(|(name, content)| PublishedFile { name: name.clone(), sha256: digest(content) })
            .collect(),
    };
    journal::atomic(&receipt_path(state, operation_id)?, &serde_json::to_vec(&receipt).map_err(Error::internal)?, true)
        .map_err(Error::internal)
}

/// True while a committed cutover has not yet published its non-empty source
/// sidecar image. The new primary must return a bounded 503 to fresh pin
/// issuance instead of reporting the staged old roots as unmanaged corruption.
/// A repository whose staged image is empty has no old roots to hand off, so a
/// fresh pin may be accepted and merged by the following finalize.
pub(crate) async fn handoff_pending(state: &AppState, repo_id: Uuid) -> Result<bool, Error> {
    let Some(node_id) = crate::sharding::transport::node_id()? else {
        return Ok(false);
    };
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT o.id FROM shard_replication_operations o              JOIN repositories p ON p.id=o.repository_id              JOIN repository_shard_routes r ON r.repository_id=o.repository_id              WHERE o.repository_id=$1 AND o.target_node_id=$2 AND o.state='completed'                AND r.primary_node_id=$2 AND p.storage_generation=o.source_generation+1              ORDER BY o.updated_at DESC,o.id DESC LIMIT 1",
            &[&repo_id, &node_id],
        )
        .await
        .map_err(Error::internal)?;
    let Some(row) = row else { return Ok(false) };
    let operation_id: Uuid = row.get(0);
    if journal::exists(&receipt_path(state, operation_id)?).map_err(Error::internal)? {
        return Ok(false);
    }
    let staged = staged_path(state, operation_id)?;
    if !safe_directory(&staged)? || !journal::exists(&staged.join("bundle.json")).map_err(Error::internal)? {
        // Completed cutover with no publication proof: block rather than let
        // a new pin trip over unmanaged retained roots.
        return Ok(true);
    }
    let bundle: SidecarBundle =
        serde_json::from_slice(&journal::read(&staged.join("bundle.json")).map_err(Error::internal)?)
            .map_err(|_| conflict("corrupt staged CI sidecar bundle"))?;
    Ok(!bundle.files.is_empty())
}

/// Publish a committed operation's staged bundle under the repository exclusive
/// guard, merging any legitimate new-generation live pins accepted after
/// cutover. Returns whether the operation was already published or staged.
pub(crate) async fn finalize(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
    generation: i64,
    expected_route: Option<(i64, i64)>,
    require_staged: bool,
) -> Result<bool, Error> {
    let staged = staged_path(state, operation_id)?;
    if !safe_directory(&staged)? || !journal::exists(&staged.join("bundle.json")).map_err(Error::internal)? {
        let published =
            verify_published_receipt(state, repo_id, operation_id, generation, expected_route, require_staged)
                .await?;
        if !published {
            // The progress record proves that a measured image was staged for
            // this operation. With no staged directory and no publication
            // receipt the handoff evidence was lost without a commit, so fail
            // closed instead of reporting that there is nothing to publish.
            if read_progress(state, operation_id, repo_id)?.is_some() {
                return Err(conflict("staged CI sidecar image vanished before publication"));
            }
        }
        return Ok(published);
    }
    let bundle: SidecarBundle =
        serde_json::from_slice(&journal::read(&staged.join("bundle.json")).map_err(Error::internal)?)
            .map_err(|_| conflict("corrupt staged CI sidecar bundle"))?;
    let guard = locks::exclusive(state, repo_id).await?;
    guard.ensure_active()?;
    let (owner_id, source_generation, object_format, route_epoch, fencing_token, sequence, refs_sha256) =
        operation_context(state, repo_id, operation_id, generation, expected_route).await?;
    if bundle.source_generation != source_generation
        || bundle.target_generation != generation
        || bundle.journal_sequence != sequence
        || bundle.refs_sha256 != refs_sha256
    {
        return Err(conflict("staged CI sidecar differs from the committed operation sequence"));
    }
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let manifest = replication::read_manifest_plain(state, &repo_path).await?;
    bundle_intents(&bundle, repo_id, operation_id, owner_id, &object_format, source_generation)?;
    let live = scan_live_new_generation(
        &sidecar_directory(&state.storage.root, repo_id),
        repo_id,
        owner_id,
        &object_format,
        generation,
        source_generation,
        &manifest,
    )?;
    let desired = desired_files(&bundle, repo_id, owner_id, &object_format, &live, &manifest)?;
    faults::hit(
        &state.storage.root,
        "target-sidecar-before-publish",
        serde_json::json!({"repository_id": repo_id, "operation_id": operation_id, "files": desired.len()}),
    );
    guard.ensure_active()?;
    publish_directory(&state.storage.root, repo_id, &desired)?;
    guard.ensure_active()?;
    // Revalidate the exact committed operation and route after publication.
    operation_context(state, repo_id, operation_id, generation, expected_route).await?;
    write_receipt(
        state,
        repo_id,
        operation_id,
        generation,
        &bundle.refs_sha256,
        sequence,
        route_epoch,
        fencing_token,
        &desired,
    )?;
    let _ = fs::remove_dir_all(&staged);
    let _ = fs::remove_file(progress_path(state, operation_id)?);
    Ok(true)
}

struct OperationState {
    id: Uuid,
    repository_id: Uuid,
    state: String,
    source_generation: i64,
    target_node_id: String,
}

async fn reconcile_operation(state: &AppState, node_id: &str, operation: &OperationState) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT p.storage_generation,r.primary_node_id \
             FROM repositories p LEFT JOIN repository_shard_routes r ON r.repository_id=p.id \
             WHERE p.id=$1",
            &[&operation.repository_id],
        )
        .await
        .map_err(Error::internal)?;
    let Some(row) = row else { return Ok(()) };
    let generation: i64 = row.get(0);
    let primary: Option<String> = row.get(1);
    if operation.state == "completed"
        && operation.target_node_id == node_id
        && primary.as_deref() == Some(node_id)
        && generation == operation.source_generation + 1
        && let Err(error) = finalize(state, operation.repository_id, operation.id, generation, None, false).await
    {
        eprintln!("rootyard: CI sidecar finalization for {} deferred: {}", operation.id, error.1);
    }
    Ok(())
}

/// Startup recovery: republish every committed cutover whose finalization was
/// interrupted, retain staged bundles for resumable/verified operations, and
/// remove only staging proven to belong to an aborted or foreign operation.
pub async fn reconcile_startup(state: &AppState) -> Result<(), Error> {
    let Ok(Some(node_id)) = crate::sharding::transport::node_id() else {
        return Ok(());
    };
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT id,repository_id,target_node_id,state,source_generation \
             FROM shard_replication_operations \
             WHERE target_node_id=$1 AND state IN ('copying','verified','completed') \
             ORDER BY updated_at,id",
            &[&node_id],
        )
        .await
        .map_err(Error::internal)?;
    let known: BTreeMap<Uuid, OperationState> = rows
        .into_iter()
        .map(|row| {
            let operation = OperationState {
                id: row.get(0),
                repository_id: row.get(1),
                target_node_id: row.get(2),
                state: row.get(3),
                source_generation: row.get(4),
            };
            (row.get::<_, Uuid>(0), operation)
        })
        .collect();
    for operation in known.values() {
        reconcile_operation(state, &node_id, operation).await?;
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
        if known.contains_key(&operation_id) {
            continue;
        }
        // Never delete an uninspected directory. Resolve this exact operation
        // before cleanup; only a proven aborted or foreign target stage goes.
        let exact = client
            .query_opt("SELECT target_node_id,state FROM shard_replication_operations WHERE id=$1", &[&operation_id])
            .await
            .map_err(Error::internal)?;
        let remove = match exact {
            // An uninspected orphan is retained; only exact aborted or foreign
            // operation staging is removed.
            None => false,
            Some(row) => {
                let target: String = row.get(0);
                let state_name: String = row.get(1);
                target != node_id || state_name == "aborted"
            }
        };
        if remove {
            let kind = entry.file_type().map_err(Error::internal)?;
            if kind.is_dir() && !kind.is_symlink() {
                let _ = fs::remove_dir_all(entry.path());
            } else {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    // Reconcile interrupted atomic directory publication. A fallback swap may
    // leave a retired directory; restore it when the live name is absent.
    let base = state.storage.root.join("ci-pins");
    if safe_directory(&base)? {
        for entry in fs::read_dir(&base).map_err(Error::internal)? {
            let entry = entry.map_err(Error::internal)?;
            let name = entry.file_name().into_string().map_err(|_| conflict("non UTF-8 CI sidecar filename"))?;
            let kind = entry.file_type().map_err(Error::internal)?;
            if !kind.is_dir() || kind.is_symlink() {
                continue;
            }
            if name.contains(".stage-") {
                let _ = fs::remove_dir_all(entry.path());
                continue;
            }
            if let Some(raw) =
                name.strip_prefix('.').and_then(|value| value.split_once(".retired-").map(|(repo, _)| repo))
            {
                let Ok(repo_id) = raw.parse::<Uuid>() else { continue };
                let live = base.join(repo_id.to_string());
                if safe_directory(&live)? {
                    let _ = fs::remove_dir_all(entry.path());
                } else {
                    fs::rename(entry.path(), &live).map_err(Error::internal)?;
                    sync_directory(&base)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(repo: Uuid, op: Uuid) -> SidecarBundle {
        SidecarBundle {
            version: SIDECAR_VERSION,
            repository_id: repo,
            operation_id: op,
            source_generation: 3,
            target_generation: 4,
            refs_sha256: "a".repeat(64),
            journal_sequence: 11,
            files: vec![SidecarFile {
                name: format!("{}.json", Uuid::new_v4()),
                sha256: "b".repeat(64),
                content: "{}".to_owned(),
            }],
            retained_refs: vec!["refs/rootyard-ci/snapshots/example".to_owned()],
        }
    }

    #[test]
    fn progress_record_round_trips_for_its_own_operation() {
        let repo = Uuid::new_v4();
        let op = Uuid::new_v4();
        let bundle = bundle(repo, op);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        assert_eq!(decode_progress(&bytes, op, repo).unwrap(), bundle);
    }

    #[test]
    fn progress_record_for_another_operation_or_repository_is_rejected() {
        let repo = Uuid::new_v4();
        let op = Uuid::new_v4();
        let bytes = serde_json::to_vec(&bundle(repo, op)).unwrap();
        assert!(decode_progress(&bytes, Uuid::new_v4(), repo).is_err());
        assert!(decode_progress(&bytes, op, Uuid::new_v4()).is_err());
    }

    #[test]
    fn progress_record_with_unknown_or_missing_fields_is_rejected() {
        let repo = Uuid::new_v4();
        let op = Uuid::new_v4();
        let mut value = serde_json::to_value(bundle(repo, op)).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(decode_progress(value.to_string().as_bytes(), op, repo).is_err());
        let mut value = serde_json::to_value(bundle(repo, op)).unwrap();
        value.as_object_mut().unwrap().remove("retained_refs");
        assert!(decode_progress(value.to_string().as_bytes(), op, repo).is_err());
        assert!(decode_progress(b"not json", op, repo).is_err());
    }
}
