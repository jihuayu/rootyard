//! CI sidecar capture: directory scan, manifest validation and the
//! measured bundle/intents that travel with a migration operation.
use super::{
    CI_PREFIX, MAX_SIDECAR_BYTES, MAX_SIDECAR_FILES, RETAINED_PREFIX, SIDECAR_VERSION, SidecarBundle, SidecarFile,
    canonical_job, digest, safe_directory, sidecar_directory, valid_digest,
};
use crate::{
    AppState, Error, journal,
    sharding::{models::conflict, replication::RefManifest},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self},
    path::Path as FsPath,
};
use uuid::Uuid;

pub(super) struct Scanned {
    pub(super) intents: BTreeMap<Uuid, (crate::ci_pins::Intent, Vec<u8>)>,
    pub(super) receipts: BTreeMap<Uuid, Vec<u8>>,
}

pub(super) fn read_sidecar_directory(
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

pub(super) fn manifest_ci_roots(manifest: &RefManifest) -> Result<BTreeMap<String, String>, Error> {
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

pub(super) fn bundle_intents(
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
pub(super) fn validate_bundle_stage(
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
