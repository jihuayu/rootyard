//! Data models, private store configuration, native Git execution, and shared
//! validation/atomic-filesystem/failpoint helpers.

use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
};
use uuid::Uuid;

pub(crate) const SCHEMA: u32 = 1;
pub(crate) const MAX_JSON: u64 = 16 * 1024 * 1024;
pub(crate) const SYNTHETIC_AUTHOR_NAME: &str = "Rootyard View";
pub(crate) const SYNTHETIC_AUTHOR_EMAIL: &str = "view@rootyard.invalid";
pub(crate) const SYNTHETIC_DATE: &str = "1700000000 +0000";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepoMeta {
    pub schema: u32,
    pub repo_id: String,
    pub name: String,
    pub head_oid: String,
    pub generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MountEntry {
    pub mount_path: String,
    pub repo_id: String,
    pub repo_name: String,
    pub base_oid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespaceRevision {
    pub schema: u32,
    pub revision_id: String,
    pub namespace: String,
    pub revision_number: u64,
    pub mounts: Vec<MountEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ViewMeta {
    pub schema: u32,
    pub view_id: String,
    pub view_name: String,
    pub strategy: String,
    pub revision_id: Option<String>,
    pub source_repo_id: Option<String>,
    pub subdir_path: Option<String>,
    pub view_base_oid: String,
    pub head_oid: String,
    pub view_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangesetTarget {
    pub repo_id: String,
    pub repo_name: String,
    pub mount_path: String,
    pub base_oid: String,
    pub expected_old_oid: String,
    pub candidate_oid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangesetRecord {
    pub schema: u32,
    pub changeset_id: String,
    pub view_id: String,
    pub task_ref: String,
    pub view_base_oid: String,
    pub task_commit_oid: String,
    pub state: String,
    pub targets: Vec<ChangesetTarget>,
    pub projected_view_oid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefLease {
    pub schema: u32,
    pub repo_id: String,
    pub ref_name: String,
    pub changeset_id: String,
}

pub(crate) const PROVENANCE_KEY_ID: &str = "rootyard-local-v1";
pub(crate) const PROVENANCE_SECRET: &[u8] = b"rootyard-view-lab-hmac-sha256-key-v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EpochCommitMap {
    pub schema: u32,
    pub view_id: String,
    pub view_epoch: u64,
    pub epochs: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceCommitRecord {
    pub projected_commit_oid: String,
    pub source_commit_oid: String,
    pub view_epoch: u64,
    pub projected_tree_oid: String,
    pub projected_parent_oids: Vec<String>,
    pub source_signed: bool,
    pub source_signature_type: String,
    pub original_signature_covers_projected_oid: bool,
    pub platform_signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ViewProvenanceManifest {
    pub schema: u32,
    pub view_id: String,
    pub strategy: String,
    pub key_id: String,
    pub view_epoch: u64,
    pub commits: Vec<ProvenanceCommitRecord>,
}

pub struct Store {
    pub(crate) root: PathBuf,
    _lock: File,
    pub(crate) git: OsString,
}

pub struct Staging(pub(crate) PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        let absolute = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()?.join(root)
        };
        no_symlink_components(&absolute)?;
        if !absolute.exists() {
            private_dir(&absolute)?;
        }
        require_directory(&absolute)?;
        let root = fs::canonicalize(absolute)?;
        ensure!(
            fs::metadata(&root)?.permissions().mode() & 0o077 == 0,
            "store must be private (mode 0700)"
        );
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join(".lock"))?;
        lock.try_lock_exclusive()
            .context("view store busy; retry after other lab operation")?;
        for name in [
            "repos",
            "namespaces",
            "views",
            "changesets",
            "leases",
            "staging",
        ] {
            let path = root.join(name);
            if !path.exists() {
                private_dir(&path)?;
            }
            require_directory(&path)?;
        }
        let git = std::env::var_os("ROOTYARD_VIEW_GIT").unwrap_or_else(|| "git".into());
        let store = Self {
            root,
            _lock: lock,
            git,
        };
        let version_text = store.git_text(&store.root, &["--version"])?;
        let version = version_text
            .split_whitespace()
            .nth(2)
            .context("invalid Git version")?;
        let parts: Vec<u32> = version
            .split('.')
            .take(2)
            .map(str::parse)
            .collect::<std::result::Result<_, _>>()?;
        ensure!(
            parts.len() == 2 && (parts[0], parts[1]) >= (2, 39),
            "Git 2.39 or newer is required"
        );
        Ok(store)
    }

    pub(crate) fn git_output_with_env(
        &self,
        repo: &Path,
        args: &[&str],
        extra_env: &[(&str, &str)],
        stdin_bytes: Option<&[u8]>,
    ) -> Result<Output> {
        let mut command = Command::new(&self.git);
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.excludesFile=/dev/null",
                "-c",
                "core.attributesFile=/dev/null",
                "-c",
                "gc.auto=0",
                "-c",
                "maintenance.auto=false",
            ])
            .arg("-C")
            .arg(repo)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_env {
            command.env(key, value);
        }
        if let Some(input) = stdin_bytes {
            command.stdin(Stdio::piped());
            let mut child = command.spawn().context("cannot spawn native Git")?;
            if let Some(mut handle) = child.stdin.take() {
                handle.write_all(input)?;
            }
            Ok(child.wait_with_output()?)
        } else {
            command.stdin(Stdio::null());
            Ok(command.output().context("cannot execute native Git")?)
        }
    }

    pub(crate) fn git(&self, repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
        let result = self.git_output_with_env(repo, args, &[], None)?;
        ensure!(
            result.status.success(),
            "native Git command {} failed",
            args.first().unwrap_or(&"git")
        );
        Ok(result.stdout)
    }

    pub(crate) fn git_with_input(
        &self,
        repo: &Path,
        args: &[&str],
        extra_env: &[(&str, &str)],
        stdin_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let result = self.git_output_with_env(repo, args, extra_env, Some(stdin_bytes))?;
        ensure!(
            result.status.success(),
            "native Git command {} failed",
            args.first().unwrap_or(&"git")
        );
        Ok(result.stdout)
    }

    pub(crate) fn git_text(&self, repo: &Path, args: &[&str]) -> Result<String> {
        Ok(String::from_utf8(self.git(repo, args)?)?.trim().to_owned())
    }

    pub(crate) fn stage(&self) -> Result<Staging> {
        let path = self.root.join("staging").join(new_id());
        private_dir(&path)?;
        Ok(Staging(path))
    }

    pub(crate) fn ensure_not_overlapping(&self, source: &Path) -> Result<()> {
        ensure!(
            !source.starts_with(&self.root) && !self.root.starts_with(source),
            "source and store must not overlap"
        );
        Ok(())
    }

    pub(crate) fn repo_git_dir(&self, repo_id: &str) -> PathBuf {
        self.root.join("repos").join(repo_id).join("repo.git")
    }

    pub(crate) fn ensure_no_active_lease(&self, repo_id: &str) -> Result<()> {
        let lease_name = format!("{repo_id}.json");
        let lease_path = self.root.join("leases").join(lease_name);
        ensure!(
            !lease_path.try_exists()?,
            "repository ref write lease is held by an active cross-repository changeset"
        );
        Ok(())
    }
}

pub(crate) fn next_utf8_field<'a>(
    fields: &mut impl Iterator<Item = &'a [u8]>,
    message: &'static str,
) -> Result<&'a str> {
    let raw = fields.next().context(message)?;
    Ok(std::str::from_utf8(raw)?)
}

pub(crate) fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

pub(crate) fn new_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn text_arg(value: &OsString) -> Result<String> {
    Ok(value.to_str().context("argument must be UTF-8")?.to_owned())
}

pub(crate) fn valid_id(id: &str) -> Result<()> {
    ensure!(
        Uuid::parse_str(id)?.to_string() == id,
        "invalid canonical id"
    );
    Ok(())
}

pub(crate) fn valid_oid(oid: &str) -> Result<()> {
    ensure!(
        oid.len() == 40
            && oid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && oid.bytes().any(|b| b != b'0'),
        "OID must be a non-zero 40-character lowercase SHA-1 hex string"
    );
    Ok(())
}

pub(crate) fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

pub(crate) fn require_directory(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_dir(),
        "expected a real directory, not a symlink"
    );
    Ok(())
}

pub(crate) fn no_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        ensure!(
            !matches!(component, Component::ParentDir),
            "parent traversal is unsupported"
        );
        current.push(component);
        if let Ok(meta) = fs::symlink_metadata(&current) {
            ensure!(
                !meta.file_type().is_symlink(),
                "symlink directory component unsupported"
            );
        }
    }
    Ok(())
}

pub(crate) fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= limit,
        "invalid or oversized file"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "file exceeded limit");
    Ok(bytes)
}

pub(crate) fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn write_atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().context("missing parent directory")?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name().unwrap().to_string_lossy(),
        new_id()
    ));
    let bytes = serde_json::to_vec_pretty(value)?;
    write_new(&tmp, &bytes, 0o600)?;
    fs::rename(&tmp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn sync_tree(root: &Path) -> Result<()> {
    for child in fs::read_dir(root)? {
        let child = child?;
        if child.file_type()?.is_dir() {
            sync_tree(&child.path())?;
        }
    }
    File::open(root)?.sync_all()?;
    Ok(())
}

pub(crate) fn publish(from: &Path, to: &Path) -> Result<()> {
    ensure!(!to.try_exists()?, "destination already exists");
    fs::rename(from, to)?;
    File::open(to.parent().unwrap())?
        .sync_all()
        .with_context(|| {
            format!(
                "publication result uncertain; inspect {} before retrying",
                to.display()
            )
        })?;
    Ok(())
}

pub(crate) fn failpoint(point: &str) {
    if std::env::var("ROOTYARD_VIEW_TEST_FAILPOINT")
        .ok()
        .as_deref()
        == Some(point)
    {
        std::process::exit(if point == "before_commit_point" {
            86
        } else {
            87
        });
    }
}
