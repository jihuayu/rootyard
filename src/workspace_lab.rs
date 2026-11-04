//! Native-directory, full-copy workspace experiment. All writers must be stopped
//! by the caller. The store lock cannot fence editors, Git or arbitrary processes.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
};
use uuid::Uuid;

const SCHEMA: u32 = 1;
const MAX_MANIFEST: u64 = 64 * 1024 * 1024;
const MAX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Workspace {
    schema: u32,
    workspace_id: String,
    agent_id: String,
    base_oid: String,
    namespace_revision: u32,
    parent_checkpoint_id: Option<String>,
    git_version: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    path_base64: String,
    kind: String,
    mode: u32,
    size: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    checkpoint_id: String,
    state: String,
    workspace: Workspace,
    excluded_ignored_entries: usize,
    entries: Vec<Entry>,
}

struct Store {
    root: PathBuf,
    _lock: File,
    git: OsString,
    git_version: String,
}

struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn run(args: Vec<OsString>) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "workspace lab requires Linux");
    let usage = "usage: rootyard-workspace-lab init STORE SOURCE AGENT BASE_OID --quiescent | checkpoint STORE WORKSPACE_ID --quiescent | restore STORE CHECKPOINT_ID AGENT | inspect STORE WORKSPACE_ID";
    let command = args.first().and_then(|x| x.to_str()).context(usage)?;
    let expected = match command {
        "init" => 6,
        "checkpoint" => 4,
        "restore" => 4,
        "inspect" => 3,
        _ => bail!(usage),
    };
    ensure!(args.len() == expected, "{usage}");
    if matches!(command, "init" | "checkpoint") {
        ensure!(
            args.last().unwrap() == "--quiescent",
            "stop ALL writers and explicitly pass --quiescent; this is a caller assumption, not a write barrier"
        );
    }
    // Reject overlap before creating even a store lock or staging directory.
    if command == "init" {
        let source = fs::canonicalize(&args[2]).context("source directory unavailable")?;
        let requested = Path::new(&args[1]);
        let absolute = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            std::env::current_dir()?.join(requested)
        };
        no_symlink_components(&absolute)?;
        let prospective = if absolute.exists() {
            fs::canonicalize(&absolute)?
        } else {
            fs::canonicalize(absolute.parent().context("store parent unavailable")?)?
                .join(absolute.file_name().context("invalid store path")?)
        };
        ensure!(
            !source.starts_with(&prospective) && !prospective.starts_with(&source),
            "source and store must not overlap"
        );
    }
    let store = Store::open(Path::new(&args[1]))?;
    let result = match command {
        "init" => {
            let source = fs::canonicalize(&args[2]).context("source directory unavailable")?;
            ensure!(
                !source.starts_with(&store.root) && !store.root.starts_with(&source),
                "source and store must not overlap"
            );
            let agent_id = text_arg(&args[3])?;
            valid_agent(&agent_id)?;
            let base_oid = text_arg(&args[4])?;
            valid_oid(&base_oid)?;
            store.validate_repo(&source, &base_oid)?;
            let head = store.git_text(&source, &["rev-parse", "--verify", "HEAD"])?;
            ensure!(
                head == base_oid,
                "initial HEAD must equal the fixed full base OID"
            );
            let workspace = Workspace {
                schema: SCHEMA,
                workspace_id: new_id(),
                agent_id,
                base_oid,
                namespace_revision: 1,
                parent_checkpoint_id: None,
                git_version: store.git_version.clone(),
            };
            store.materialize(&source, workspace, true, None)?
        }
        "checkpoint" => {
            let id = text_arg(&args[2])?;
            valid_id(&id)?;
            let workspace = store.read_workspace(&id)?;
            let source = store.root.join("workspaces").join(&id).join("repo");
            store.validate_repo(&source, &workspace.base_oid)?;
            let checkpoint_id = new_id();
            let staging = store.stage()?;
            let excluded = store.capture(&source, &staging.0.join("repo"))?;
            store.validate_repo(&staging.0.join("repo"), &workspace.base_oid)?;
            let entries = inventory(&staging.0.join("repo"))?;
            let manifest = Manifest {
                schema: SCHEMA,
                checkpoint_id: checkpoint_id.clone(),
                state: "local_complete".into(),
                workspace,
                excluded_ignored_entries: excluded,
                entries,
            };
            let bytes = serde_json::to_vec_pretty(&manifest)?;
            ensure!(
                bytes.len() as u64 <= MAX_MANIFEST,
                "manifest limit exceeded"
            );
            write_new(&staging.0.join("manifest.json"), &bytes, 0o600)?;
            write_new(
                &staging.0.join("manifest.sha256"),
                hex::encode(Sha256::digest(&bytes)).as_bytes(),
                0o600,
            )?;
            sync_tree(&staging.0)?;
            failpoint("before_publish");
            publish(
                &staging.0,
                &store.root.join("checkpoints").join(&checkpoint_id),
            )?;
            failpoint("after_publish");
            serde_json::json!({"checkpoint_id":checkpoint_id,"state":"local_complete","base_oid":manifest.workspace.base_oid,"excluded_ignored_entries":excluded,"entries":manifest.entries.len(),"durability":"local_filesystem_only","consistency":"caller_quiescent"})
        }
        "restore" => {
            let id = text_arg(&args[2])?;
            valid_id(&id)?;
            let agent_id = text_arg(&args[3])?;
            valid_agent(&agent_id)?;
            let checkpoint = store.root.join("checkpoints").join(&id);
            require_directory(&checkpoint)?;
            let bytes = read_regular(&checkpoint.join("manifest.json"), MAX_MANIFEST)?;
            let digest = read_regular(&checkpoint.join("manifest.sha256"), 64)?;
            ensure!(
                digest == hex::encode(Sha256::digest(&bytes)).as_bytes(),
                "checkpoint manifest checksum mismatch"
            );
            let manifest: Manifest =
                serde_json::from_slice(&bytes).context("invalid checkpoint manifest")?;
            ensure!(
                manifest.schema == SCHEMA
                    && manifest.checkpoint_id == id
                    && manifest.state == "local_complete",
                "unsupported or incomplete checkpoint"
            );
            store.validate_workspace(&manifest.workspace)?;
            validate_entries(&manifest.entries)?;
            let source = checkpoint.join("repo");
            ensure!(
                inventory(&source)? == manifest.entries,
                "checkpoint contents missing, unexpected or corrupt"
            );
            store.validate_repo(&source, &manifest.workspace.base_oid)?;
            let mut workspace = manifest.workspace;
            workspace.workspace_id = new_id();
            workspace.agent_id = agent_id;
            workspace.parent_checkpoint_id = Some(id);
            store.materialize(&source, workspace, false, Some(&manifest.entries))?
        }
        "inspect" => {
            let id = text_arg(&args[2])?;
            valid_id(&id)?;
            let workspace = store.read_workspace(&id)?;
            store.result(&workspace)
        }
        _ => unreachable!(),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

impl Store {
    fn open(root: &Path) -> Result<Self> {
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
            .context("workspace store busy; retry after other lab operation")?;
        for name in ["workspaces", "checkpoints", "staging"] {
            let path = root.join(name);
            if !path.exists() {
                private_dir(&path)?;
            }
            require_directory(&path)?;
        }
        let git = std::env::var_os("ROOTYARD_WORKSPACE_GIT").unwrap_or_else(|| "git".into());
        let mut store = Self {
            root,
            _lock: lock,
            git,
            git_version: String::new(),
        };
        store.git_version = store.git_text(&store.root, &["--version"])?;
        let version = store
            .git_version
            .split_whitespace()
            .nth(2)
            .context("invalid Git version")?;
        let parts: Vec<u32> = version
            .split('.')
            .take(2)
            .map(str::parse)
            .collect::<std::result::Result<_, _>>()?;
        ensure!(
            parts.len() == 2 && (parts[0], parts[1]) >= (2, 43),
            "Git 2.43 or newer is required"
        );
        Ok(store)
    }

    fn git_output(&self, repo: &Path, args: &[&str]) -> Result<Output> {
        let output = Command::new(&self.git)
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
            .stdin(Stdio::null())
            .output()
            .context("cannot execute native Git")?;
        Ok(output)
    }

    fn git(&self, repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
        let result = self.git_output(repo, args)?;
        ensure!(
            result.status.success(),
            "native Git validation failed for {} (stderr omitted)",
            args.first().unwrap_or(&"command")
        );
        Ok(result.stdout)
    }

    fn git_text(&self, repo: &Path, args: &[&str]) -> Result<String> {
        Ok(String::from_utf8(self.git(repo, args)?)?.trim().to_owned())
    }

    fn stage(&self) -> Result<Staging> {
        let path = self.root.join("staging").join(new_id());
        private_dir(&path)?;
        Ok(Staging(path))
    }

    fn result(&self, workspace: &Workspace) -> serde_json::Value {
        let mut result = serde_json::to_value(workspace).expect("serializable workspace");
        result["repo_path"] = self
            .root
            .join("workspaces")
            .join(&workspace.workspace_id)
            .join("repo")
            .to_string_lossy()
            .into_owned()
            .into();
        result
    }

    fn validate_workspace(&self, workspace: &Workspace) -> Result<()> {
        ensure!(
            workspace.schema == SCHEMA && workspace.namespace_revision == 1,
            "unsupported workspace schema"
        );
        valid_id(&workspace.workspace_id)?;
        valid_agent(&workspace.agent_id)?;
        valid_oid(&workspace.base_oid)?;
        if let Some(id) = &workspace.parent_checkpoint_id {
            valid_id(id)?;
        }
        ensure!(
            workspace.git_version == self.git_version,
            "Git version differs from captured version; migration is not supported"
        );
        Ok(())
    }

    fn read_workspace(&self, id: &str) -> Result<Workspace> {
        let directory = self.root.join("workspaces").join(id);
        require_directory(&directory)?;
        let workspace: Workspace = serde_json::from_slice(&read_regular(
            &directory.join("workspace.json"),
            MAX_MANIFEST,
        )?)?;
        self.validate_workspace(&workspace)?;
        ensure!(workspace.workspace_id == id, "workspace identity mismatch");
        Ok(workspace)
    }

    fn materialize(
        &self,
        source: &Path,
        workspace: Workspace,
        managed_only: bool,
        expected: Option<&[Entry]>,
    ) -> Result<serde_json::Value> {
        let staging = self.stage()?;
        let destination = staging.0.join("repo");
        if managed_only {
            self.capture(source, &destination)?;
        } else {
            copy_all(source, &destination)?;
        }
        if let Some(entries) = expected {
            ensure!(
                inventory(&destination)? == entries,
                "checkpoint changed while restoring"
            );
        }
        self.validate_repo(&destination, &workspace.base_oid)?;
        write_new(
            &staging.0.join("workspace.json"),
            &serde_json::to_vec_pretty(&workspace)?,
            0o600,
        )?;
        sync_tree(&staging.0)?;
        publish(
            &staging.0,
            &self.root.join("workspaces").join(&workspace.workspace_id),
        )?;
        Ok(self.result(&workspace))
    }

    fn validate_repo(&self, repo: &Path, base_oid: &str) -> Result<()> {
        require_directory(repo)?;
        require_directory(&repo.join(".git"))
            .context("only independent native .git directories are supported")?;
        for item in [
            "commondir",
            "gitdir",
            "objects/info/alternates",
            "objects/info/http-alternates",
            "shallow",
            "info/grafts",
        ] {
            ensure!(
                !repo.join(".git").join(item).try_exists()?,
                "external Git storage, shallow repositories and grafts are unsupported"
            );
        }
        let git_files = walk(&repo.join(".git"))?;
        for (path, metadata) in &git_files {
            ensure!(
                !metadata.file_type().is_symlink(),
                "symlinks inside .git are unsupported"
            );
            ensure!(
                metadata.is_file(),
                "special files inside .git are unsupported"
            );
            ensure!(
                !path.as_os_str().as_bytes().ends_with(b".lock"),
                "checkpoint busy: Git lock exists; do not delete it blindly"
            );
            ensure!(
                !path.starts_with("worktrees") && !path.starts_with("modules"),
                "linked worktrees and submodules are unsupported"
            );
            if path.starts_with("hooks") && !path.as_os_str().as_bytes().ends_with(b".sample") {
                bail!("custom Git hooks are unsupported");
            }
        }
        // Parse local config without include expansion before other Git commands.
        let config = self.git(
            repo,
            &["config", "--local", "--no-includes", "--null", "--list"],
        )?;
        for record in config.split(|b| *b == 0).filter(|x| !x.is_empty()) {
            let split = record
                .iter()
                .position(|b| *b == b'\n')
                .context("invalid Git config")?;
            let key = std::str::from_utf8(&record[..split])?;
            let value = std::str::from_utf8(&record[split + 1..])?;
            let allowed = match key {
                "core.repositoryformatversion" => value == "0",
                "core.filemode" | "core.logallrefupdates" => value == "true",
                "core.bare" | "core.ignorecase" | "core.precomposeunicode" => value == "false",
                "core.autocrlf" => ["false", "true", "input"].contains(&value),
                "core.eol" => ["native", "lf", "crlf"].contains(&value),
                "user.name" | "user.email" => !value.contains(['\r', '\n']),
                _ => false,
            };
            ensure!(
                allowed,
                "unsupported local Git config key: {key}; use a trusted standalone fixture with reviewed configuration"
            );
        }
        ensure!(
            self.git_text(repo, &["rev-parse", "--show-object-format"])? == "sha1",
            "only SHA-1 repositories are currently qualified"
        );
        ensure!(
            self.git_text(repo, &["rev-parse", "--is-bare-repository"])? == "false",
            "bare repository unsupported"
        );
        ensure!(
            self.git_text(repo, &["cat-file", "-t", base_oid])? == "commit",
            "base OID must identify a complete local commit"
        );
        ensure!(
            self.git_text(repo, &["rev-parse", "--verify", "HEAD^{commit}"])
                .is_ok(),
            "unborn HEAD unsupported by this slice"
        );
        let index = repo.join(".git/index");
        if index.try_exists()? {
            validate_index(&read_regular(&index, MAX_MANIFEST)?)?;
        }
        ensure!(
            self.git(
                repo,
                &["for-each-ref", "--format=%(refname)", "refs/replace/"]
            )?
            .is_empty(),
            "replacement refs are unsupported"
        );
        {
            let path = repo.join(".git/info/attributes");
            if path.try_exists()? {
                let bytes = read_regular(&path, MAX_MANIFEST)?;
                ensure!(
                    !bytes.windows(6).any(|x| x == b"filter"),
                    "Git clean/smudge and LFS attributes are unsupported"
                );
            }
        }
        self.managed(repo)?;
        // Check referenced objects, index entries and reflogs with Git itself.
        self.git(repo, &["fsck", "--full", "--strict"])?;
        Ok(())
    }

    fn managed(&self, repo: &Path) -> Result<BTreeSet<PathBuf>> {
        let mut managed = BTreeSet::new();
        for output in [
            self.git(repo, &["ls-tree", "-rz", "--full-tree", "HEAD"])?,
            self.git(repo, &["ls-files", "--stage", "-z"])?,
        ] {
            for record in output.split(|b| *b == 0).filter(|x| !x.is_empty()) {
                ensure!(
                    !record.starts_with(b"160000 "),
                    "submodules/gitlinks are unsupported"
                );
                let split = record
                    .iter()
                    .position(|b| *b == b'\t')
                    .context("invalid Git path record")?;
                managed.insert(relative_path(&record[split + 1..])?);
            }
        }
        for record in self
            .git(repo, &["ls-files", "--others", "--exclude-standard", "-z"])?
            .split(|b| *b == 0)
            .filter(|x| !x.is_empty())
        {
            managed.insert(relative_path(record)?);
        }
        Ok(managed)
    }

    fn capture(&self, source: &Path, destination: &Path) -> Result<usize> {
        let managed = self.managed(source)?;
        let mut selected = BTreeSet::new();
        let mut ignored = 0;
        for (path, metadata) in walk(source)? {
            if path.starts_with(".git") || managed.contains(&path) {
                ensure!(
                    metadata.is_file() || metadata.file_type().is_symlink(),
                    "managed special file cannot be checkpointed"
                );
                if path.file_name() == Some(OsStr::new(".gitattributes")) {
                    let bytes = read_regular(&source.join(&path), MAX_MANIFEST)?;
                    ensure!(
                        !bytes.windows(6).any(|x| x == b"filter"),
                        "Git clean/smudge and LFS attributes are unsupported"
                    );
                }
                selected.insert(path);
            } else {
                ignored += 1;
            }
        }
        copy_selected(source, destination, &selected)?;
        Ok(ignored)
    }
}

fn validate_index(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 32 && &bytes[..4] == b"DIRC",
        "invalid native Git index"
    );
    let version = u32::from_be_bytes(bytes[4..8].try_into()?);
    ensure!(
        matches!(version, 2 | 3),
        "only index v2/v3 supported; unknown extensions are not silently discarded"
    );
    let count = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
    ensure!(count <= MAX_ENTRIES, "index entry limit exceeded");
    let end = bytes.len() - 20;
    let mut cursor: usize = 12;
    for _ in 0..count {
        let start = cursor;
        ensure!(
            cursor.checked_add(62).is_some_and(|n| n <= end),
            "truncated index entry"
        );
        let flags = u16::from_be_bytes(bytes[cursor + 60..cursor + 62].try_into()?);
        cursor += 62;
        if flags & 0x4000 != 0 {
            ensure!(
                version == 3 && cursor + 2 <= end,
                "invalid extended index flags"
            );
            let extended = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into()?);
            ensure!(
                extended & !0x2000 == 0,
                "skip-worktree or unknown index flags unsupported"
            );
            cursor += 2;
        }
        let nul = bytes[cursor..end]
            .iter()
            .position(|b| *b == 0)
            .context("unterminated index path")?;
        relative_path(&bytes[cursor..cursor + nul])?;
        cursor += nul + 1;
        cursor = start + (cursor - start).div_ceil(8) * 8;
        ensure!(cursor <= end, "truncated index padding");
    }
    while cursor < end {
        ensure!(cursor + 8 <= end, "invalid index extension");
        let name = &bytes[cursor..cursor + 4];
        ensure!(
            name == b"TREE" || name == b"REUC",
            "unsupported index extension (split/sparse/fsmonitor/untracked cache or unknown)"
        );
        let size = u32::from_be_bytes(bytes[cursor + 4..cursor + 8].try_into()?) as usize;
        cursor = cursor
            .checked_add(8 + size)
            .context("index extension overflow")?;
        ensure!(cursor <= end, "truncated index extension");
    }
    Ok(())
}

fn new_id() -> String {
    Uuid::new_v4().to_string()
}
fn text_arg(value: &OsStr) -> Result<String> {
    Ok(value.to_str().context("argument must be UTF-8")?.to_owned())
}
fn valid_id(id: &str) -> Result<()> {
    ensure!(
        Uuid::parse_str(id)?.to_string() == id,
        "invalid canonical id"
    );
    Ok(())
}
fn valid_agent(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 63
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid agent identity"
    );
    Ok(())
}
fn valid_oid(oid: &str) -> Result<()> {
    ensure!(
        oid.len() == 40
            && oid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "base OID must be a full lowercase SHA-1 commit OID"
    );
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn require_directory(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_dir(),
        "expected a real directory, not a symlink"
    );
    Ok(())
}
fn no_symlink_components(path: &Path) -> Result<()> {
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
fn relative_path(bytes: &[u8]) -> Result<PathBuf> {
    ensure!(
        !bytes.is_empty() && !bytes.contains(&0) && !bytes.ends_with(b"/"),
        "invalid path"
    );
    ensure!(
        !bytes
            .split(|b| *b == b'/')
            .any(|x| x.is_empty() || x == b"." || x == b".."),
        "unsafe path component"
    );
    let path = PathBuf::from(OsString::from_vec(bytes.to_vec()));
    ensure!(
        path.components().all(|c| matches!(c, Component::Normal(_))),
        "unsafe relative path"
    );
    Ok(path)
}
fn validate_symlink(root: &Path, path: &Path, target: &Path) -> Result<()> {
    ensure!(
        !target.as_os_str().is_empty() && !target.is_absolute(),
        "absolute or empty symlink target unsupported"
    );
    let mut resolved: Vec<OsString> = path
        .parent()
        .unwrap()
        .components()
        .map(|c| c.as_os_str().to_owned())
        .collect();
    let mut pending: VecDeque<OsString> = target
        .components()
        .map(|c| c.as_os_str().to_owned())
        .collect();
    let mut links = 0;
    while let Some(component) = pending.pop_front() {
        if component == "." {
            continue;
        }
        if component == ".." {
            ensure!(resolved.pop().is_some(), "symlink escapes repository");
            continue;
        }
        resolved.push(component);
        ensure!(
            resolved.first().is_none_or(|x| x != ".git"),
            "symlink into Git metadata unsupported"
        );
        let location: PathBuf = resolved.iter().collect();
        match fs::symlink_metadata(root.join(location)) {
            Ok(meta) if meta.file_type().is_symlink() => {
                links += 1;
                ensure!(links <= 40, "symlink loop or excessive chain");
                let location: PathBuf = resolved.iter().collect();
                let link = fs::read_link(root.join(location))?;
                ensure!(!link.is_absolute(), "symlink chain escapes repository");
                resolved.pop();
                let components: Vec<_> = link
                    .components()
                    .map(|c| c.as_os_str().to_owned())
                    .collect();
                for part in components.into_iter().rev() {
                    pending.push_front(part);
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn walk(root: &Path) -> Result<BTreeMap<PathBuf, fs::Metadata>> {
    require_directory(root)?;
    fn visit(
        root: &Path,
        relative: &Path,
        output: &mut BTreeMap<PathBuf, fs::Metadata>,
    ) -> Result<()> {
        for child in fs::read_dir(root.join(relative))? {
            let child = child?;
            let path = relative.join(child.file_name());
            relative_path(path.as_os_str().as_bytes())?;
            let meta = fs::symlink_metadata(child.path())?;
            if meta.is_dir() {
                ensure!(
                    path.file_name() != Some(OsStr::new(".git")) || path == Path::new(".git"),
                    "nested Git repositories unsupported"
                );
                visit(root, &path, output)?;
            } else {
                ensure!(output.len() < MAX_ENTRIES, "file count limit exceeded");
                output.insert(path, meta);
            }
        }
        Ok(())
    }
    let mut output = BTreeMap::new();
    visit(root, Path::new(""), &mut output)?;
    Ok(output)
}

fn copy_all(source: &Path, destination: &Path) -> Result<()> {
    copy_selected(source, destination, &walk(source)?.into_keys().collect())
}

fn copy_selected(source: &Path, destination: &Path, selected: &BTreeSet<PathBuf>) -> Result<()> {
    private_dir(destination)?;
    let mut total = 0_u64;
    for relative in selected {
        let from = source.join(relative);
        let to = destination.join(relative);
        let metadata = fs::symlink_metadata(&from)?;
        ensure!(
            metadata.permissions().mode() & 0o7000 == 0,
            "special permission bits unsupported"
        );
        let mut directory = destination.to_path_buf();
        for component in relative.parent().unwrap().components() {
            directory.push(component);
            if !directory.exists() {
                private_dir(&directory)?;
            }
            require_directory(&directory)?;
        }
        if metadata.file_type().is_symlink() {
            ensure!(
                !relative.starts_with(".git"),
                "symlink Git metadata unsupported"
            );
            let target = fs::read_link(&from)?;
            validate_symlink(source, relative, &target)?;
            symlink(target, &to)?;
        } else {
            ensure!(metadata.is_file(), "special file cannot be copied");
            total = total
                .checked_add(metadata.len())
                .context("copy size overflow")?;
            ensure!(total <= MAX_BYTES, "workspace copy limit is 1 GiB");
            let mut input = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&from)?;
            ensure!(
                input.metadata()?.is_file(),
                "copy input is not a regular file"
            );
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&to)?;
            // Explicit read/write loop: no hardlink, clone ioctl or copy_file_range.
            let mut buffer = [0_u8; 64 * 1024];
            let mut copied = 0_u64;
            loop {
                let count = input.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                copied += count as u64;
                ensure!(
                    copied <= metadata.len(),
                    "source grew during capture; quiescence required"
                );
                output.write_all(&buffer[..count])?;
            }
            ensure!(
                copied == metadata.len(),
                "source changed during capture; quiescence required"
            );
            output.set_permissions(fs::Permissions::from_mode(
                metadata.permissions().mode() & 0o777,
            ))?;
            output.sync_all()?;
        }
    }
    // Empty .git directories are legal and need not be retained, but the root must exist.
    for name in [".git", ".git/objects", ".git/refs"] {
        if !destination.join(name).exists() {
            private_dir(&destination.join(name))?;
        }
    }
    Ok(())
}

fn inventory(root: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut total = 0_u64;
    for (path, meta) in walk(root)? {
        let (kind, bytes, mode) = if meta.file_type().is_symlink() {
            ensure!(
                !path.starts_with(".git"),
                "symlink Git metadata unsupported"
            );
            let target = fs::read_link(root.join(&path))?;
            validate_symlink(root, &path, &target)?;
            ("symlink", target.into_os_string().into_vec(), 0o777)
        } else {
            ensure!(meta.is_file(), "special checkpoint file");
            total = total.checked_add(meta.len()).context("size overflow")?;
            ensure!(total <= MAX_BYTES, "checkpoint size limit exceeded");
            (
                "file",
                read_regular(&root.join(&path), MAX_BYTES)?,
                meta.permissions().mode() & 0o777,
            )
        };
        entries.push(Entry {
            path_base64: STANDARD.encode(path.as_os_str().as_bytes()),
            kind: kind.into(),
            mode,
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    Ok(entries)
}
fn validate_entries(entries: &[Entry]) -> Result<()> {
    ensure!(
        entries.len() <= MAX_ENTRIES,
        "manifest entry limit exceeded"
    );
    let mut paths = BTreeSet::new();
    for entry in entries {
        let path = relative_path(&STANDARD.decode(&entry.path_base64)?)?;
        ensure!(paths.insert(path), "duplicate checkpoint path");
        ensure!(
            matches!(entry.kind.as_str(), "file" | "symlink")
                && entry.mode <= 0o777
                && entry.sha256.len() == 64
                && entry.size <= MAX_BYTES,
            "invalid checkpoint entry"
        );
    }
    Ok(())
}
fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
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
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn sync_tree(root: &Path) -> Result<()> {
    for child in fs::read_dir(root)? {
        let child = child?;
        if child.file_type()?.is_dir() {
            sync_tree(&child.path())?;
        }
    }
    File::open(root)?.sync_all()?;
    Ok(())
}
fn publish(from: &Path, to: &Path) -> Result<()> {
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
fn failpoint(point: &str) {
    if std::env::var("ROOTYARD_WORKSPACE_TEST_FAILPOINT")
        .ok()
        .as_deref()
        == Some(point)
    {
        std::process::exit(if point == "before_publish" { 86 } else { 87 });
    }
}
