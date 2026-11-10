//! Offline paired backups. A volume flock and PostgreSQL table locks are barriers,
//! not a claim of online cross-store atomicity or zero data loss.
//!
//! Two current-format archive versions exist:
//!
//! * format 21 (`schema 147`): the legacy PG + volume (+ Pando closure)
//!   archive. It carries no Blob bytes and is described as such in its manifest;
//! * format 22 (`schema 147`, the same frozen catalog): the paired PG + v1
//!   OpenDAL Blob closure archive. Every exact `pg_refstore` pack/idx artifact
//!   referenced by the restored PostgreSQL snapshot is exported from the live
//!   Blob backend into the archive, re-read from the source before publication
//!   of the archive, and is the only source the restore imports from. The
//!   archive records the source physical backend identity; restore only accepts
//!   a target with the same identity, so a repository's refs, its pack ledger
//!   and the restored bytes stay bound to one backend coordinate.
//!
//! The version is chosen by the actual source: an archive is format 22 exactly
//! when the source has at least one `pg_refstore` serving repository. A source
//! with Blob-served repositories can therefore never fall back to a metadata
//! archive that silently claims to be independent.
use crate::config::Config;
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncReadExt, process::Command};
use tokio_postgres::{Client, GenericClient};
use uuid::Uuid;

mod authority;
mod blob_closure;
mod catalog;
mod lfs_inventory;
mod lifetime;
use catalog::{
    FORMAT, FORMAT_PAIRED, catalogs as schema_catalogs, digest as schema_contract_digest, versions as schema_versions,
};
const MAX_ENTRIES: usize = 2_000_000;
const MAX_MANIFEST: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    kind: String,
    mode: u32,
    bytes: u64,
    sha256: Option<String>,
    target: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Repository {
    id: Uuid,
    generation: i64,
    incident_revision: i64,
    state: String,
    recovery_reason: Option<String>,
    /// Storage backend (`gitfs`, `pando` or `pg_refstore`); decides whether a
    /// persistent bare repository must exist (native) or must not (served).
    #[serde(default)]
    backend: String,
    unknown_operations: i64,
    // Diagnostic refs are not synthesized push receipts or an event watermark.
    refs: Option<String>,
    head: Option<String>,
}
/// Exact OpenDAL Blob closure shipped inside a format22 archive.
///
/// It is the evidence that the restored PostgreSQL pack ledger and the restored
/// bytes describe the same closure; restore re-derives it from the restored
/// database after import and refuses any difference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BlobClosure {
    /// Non-secret logical backend identity digest (`BlobBackendIdentity`).
    backend_identity: String,
    provider: String,
    repositories: usize,
    artifacts: usize,
    bytes: u64,
    digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    backup_id: Uuid,
    volume_id: Uuid,
    schema_contract_sha256: String,
    boundary_unix_seconds: u64,
    rootyard_version: String,
    binary_sha256: String,
    postgres_version: String,
    pg_dump_version: String,
    git_version: String,
    schema_versions: Vec<i32>,
    consistency: String,
    journal_record_files: usize,
    repositories: Vec<Repository>,
    #[serde(default)]
    lfs_objects: Vec<lfs_inventory::Object>,
    /// Present exactly in format22. Format21 archives never contain Blob bytes
    /// and do not carry this member (they are not independent byte backups).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blob_closure: Option<BlobClosure>,
    /// Exact original locators of the archived artifacts. Restore rebuilds the
    /// same-coordinate objects and never re-points the immutable ledger.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    blob_artifacts: Vec<ledger::Artifact>,
    /// Duplicate of the durable RefStore rows the closure depends on. Restore
    /// compares the restored rows with this map and refuses any divergence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refstore: Option<ledger::RefStoreCarry>,
    files: BTreeMap<String, Entry>,
}

mod filesystem;
mod ledger;
mod postgres;
mod restore;
mod snapshot;
pub use filesystem::ensure_not_restoring;
use filesystem::*;
use lifetime::BackupMutex;
pub(crate) use lifetime::{ensure_database_available, prepare_serving_database};
use postgres::*;
pub use restore::{check, restore};
pub use snapshot::create;

/// Offline read-only export witness for the Blob byte layer.
///
/// Defined directly in `crate::backup` (not a child) so `blob_store::archive`
/// can name it, with private fields and no public constructor. Only the offline
/// backup creates one after holding the exclusive session barrier and proving
/// the volume/restore-guard state. It admits the export surface to stream and
/// verify exact locators only; there is no rebuild method behind it.
pub(crate) struct ArchiveRead {
    volume_id: Uuid,
    backup_id: Uuid,
}

impl ArchiveRead {
    /// `pub(in crate::backup)` seals construction to the backup subtree.
    pub(in crate::backup) fn seal(volume_id: Uuid, backup_id: Uuid) -> Result<Self> {
        ensure!(!volume_id.is_nil() && !backup_id.is_nil(), "archive read witness needs real identities");
        Ok(Self { volume_id, backup_id })
    }

    /// Blob-layer admission. It cannot verify itself, only carry the identities
    /// that the archive manifest must reproduce.
    pub(crate) fn admit(&self) -> (Uuid, Uuid) {
        (self.volume_id, self.backup_id)
    }
}

/// Opaque, bounded same-coordinate restore permit for exactly one original
/// Blob object.
///
/// Fields are private and the only constructor is `pub(in crate::backup)`, so
/// no other module (including `blob_store::archive`) can mint one. The Blob
/// layer only borrows it, and its `verify` method checks the permit against the
/// locator and physical backend it is about to touch before any IO.
pub(crate) struct OfflineRestorePermit {
    locator: crate::blob_store::BlobLocator,
    backend_identity: String,
}

impl OfflineRestorePermit {
    /// Issue a permit bound to one exact locator and the archive's backend.
    /// Non-canonical locators (the public constructor already rejects these)
    /// are refused, as is an empty backend identity.
    pub(in crate::backup) fn issue(locator: crate::blob_store::BlobLocator, backend_identity: &str) -> Result<Self> {
        ensure!(!locator.attempt_id().is_nil(), "restore permit needs a real attempt id");
        ensure!(locator.length() > 0, "restore permit needs a positive length");
        ensure!(
            backend_identity.len() == 64 && backend_identity.bytes().all(|b| b.is_ascii_hexdigit()),
            "restore permit needs a canonical backend identity"
        );
        Ok(Self { locator, backend_identity: backend_identity.to_owned() })
    }

    /// Blob-layer entry check, called before any provider IO. Accepts only when
    /// the locator and backend are exactly the permitted ones; there is no
    /// string, id or bool alternative that could widen it.
    pub(crate) fn verify(&self, locator: &crate::blob_store::BlobLocator, backend_identity: &str) -> bool {
        self.backend_identity == backend_identity && &self.locator == locator
    }
}
