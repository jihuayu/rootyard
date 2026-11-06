//! Offline paired backups. A volume flock and PostgreSQL table locks are barriers,
//! not a claim of online cross-store atomicity or zero data loss.
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
mod catalog;
mod lfs_inventory;
use catalog::{FORMAT, catalogs as schema_catalogs, digest as schema_contract_digest, versions as schema_versions};
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
    unknown_operations: i64,
    // Diagnostic refs are not synthesized push receipts or an event watermark.
    refs: Option<String>,
    head: Option<String>,
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
    files: BTreeMap<String, Entry>,
}

mod filesystem;
mod postgres;
mod restore;
mod snapshot;
pub use filesystem::ensure_not_restoring;
use filesystem::*;
use postgres::*;
pub use restore::{check, restore};
pub use snapshot::create;
