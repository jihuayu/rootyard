//! Opt-in local Namespace, Git View and two-phase cross-repository ChangeSet prototype.
//! Native bare Git repositories in the private store remain authoritative per repository.
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStringExt,
        fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
};
use uuid::Uuid;

const SCHEMA: u32 = 1;
const MAX_JSON: u64 = 16 * 1024 * 1024;
const SYNTHETIC_AUTHOR_NAME: &str = "Rootyard View";
const SYNTHETIC_AUTHOR_EMAIL: &str = "view@rootyard.invalid";
const SYNTHETIC_DATE: &str = "1700000000 +0000";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RepoMeta {
    schema: u32,
    repo_id: String,
    name: String,
    head_oid: String,
    generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MountEntry {
    mount_path: String,
    repo_id: String,
    repo_name: String,
    base_oid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NamespaceRevision {
    schema: u32,
    revision_id: String,
    namespace: String,
    revision_number: u64,
    mounts: Vec<MountEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ViewMeta {
    schema: u32,
    view_id: String,
    view_name: String,
    strategy: String,
    revision_id: Option<String>,
    source_repo_id: Option<String>,
    subdir_path: Option<String>,
    view_base_oid: String,
    head_oid: String,
    view_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChangesetTarget {
    repo_id: String,
    repo_name: String,
    mount_path: String,
    base_oid: String,
    expected_old_oid: String,
    candidate_oid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChangesetRecord {
    schema: u32,
    changeset_id: String,
    view_id: String,
    task_ref: String,
    view_base_oid: String,
    task_commit_oid: String,
    state: String,
    targets: Vec<ChangesetTarget>,
    projected_view_oid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RefLease {
    schema: u32,
    repo_id: String,
    ref_name: String,
    changeset_id: String,
}

struct Store {
    root: PathBuf,
    _lock: File,
    git: OsString,
}

struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn run(args: Vec<OsString>) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "view lab requires Linux");
    let usage = "usage: rootyard-view-lab register-repo | advance-repo | create-namespace | project-subdir | create-task-view | integrate-changeset | recover-changeset";
    let command = args.first().and_then(|x| x.to_str()).context(usage)?;
    ensure!(args.len() >= 3, "{usage}");
    let store = Store::open(Path::new(&args[1]))?;
    let result = match command {
        "register-repo" => {
            ensure!(
                args.len() == 5 && args[4] == "--quiescent",
                "register-repo requires STORE REPO_NAME SOURCE_PATH --quiescent"
            );
            let name = text_arg(&args[2])?;
            let source = fs::canonicalize(&args[3]).context("source unavailable")?;
            store.register_repo(&name, &source)?
        }
        "advance-repo" => {
            ensure!(
                args.len() == 5 && args[4] == "--quiescent",
                "advance-repo requires STORE REPO_NAME SOURCE_PATH --quiescent"
            );
            let name = text_arg(&args[2])?;
            let source = fs::canonicalize(&args[3]).context("source unavailable")?;
            store.advance_repo(&name, &source)?
        }
        "create-namespace" => {
            ensure!(
                args.len() >= 4,
                "create-namespace requires STORE NAMESPACE_NAME and at least one mount"
            );
            let namespace = text_arg(&args[2])?;
            let specs: Vec<String> = args[3..].iter().map(text_arg).collect::<Result<_>>()?;
            store.create_namespace(&namespace, &specs)?
        }
        "project-subdir" => {
            ensure!(
                args.len() == 5,
                "project-subdir requires STORE VIEW_NAME REPO_NAME SUBDIR_PATH"
            );
            let view_name = text_arg(&args[2])?;
            let repo_name = text_arg(&args[3])?;
            let subdir = text_arg(&args[4])?;
            store.project_subdir(&view_name, &repo_name, &subdir)?
        }
        "create-task-view" => {
            ensure!(
                args.len() == 4,
                "create-task-view requires STORE VIEW_NAME REVISION_ID"
            );
            let view_name = text_arg(&args[2])?;
            let revision_id = text_arg(&args[3])?;
            store.create_task_view(&view_name, &revision_id)?
        }
        "integrate-changeset" => {
            ensure!(
                args.len() == 4,
                "integrate-changeset requires STORE VIEW_ID TASK_REF"
            );
            let view_id = text_arg(&args[2])?;
            let task_ref = text_arg(&args[3])?;
            store.integrate_changeset(&view_id, &task_ref)?
        }
        "recover-changeset" => {
            ensure!(
                args.len() == 3,
                "recover-changeset requires STORE CHANGESET_ID"
            );
            let changeset_id = text_arg(&args[2])?;
            store.recover_changeset(&changeset_id)?
        }
        _ => bail!(usage),
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
            parts.len() == 2 && (parts[0], parts[1]) >= (2, 43),
            "Git 2.43 or newer is required"
        );
        Ok(store)
    }

    fn git_output_with_env(
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

    fn git(&self, repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
        let result = self.git_output_with_env(repo, args, &[], None)?;
        ensure!(
            result.status.success(),
            "native Git command {} failed",
            args.first().unwrap_or(&"git")
        );
        Ok(result.stdout)
    }

    fn git_with_input(
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

    fn git_text(&self, repo: &Path, args: &[&str]) -> Result<String> {
        Ok(String::from_utf8(self.git(repo, args)?)?.trim().to_owned())
    }

    fn stage(&self) -> Result<Staging> {
        let path = self.root.join("staging").join(new_id());
        private_dir(&path)?;
        Ok(Staging(path))
    }

    fn ensure_not_overlapping(&self, source: &Path) -> Result<()> {
        ensure!(
            !source.starts_with(&self.root) && !self.root.starts_with(source),
            "source and store must not overlap"
        );
        Ok(())
    }

    fn list_repos(&self) -> Result<Vec<RepoMeta>> {
        let mut repos = Vec::new();
        for entry in fs::read_dir(self.root.join("repos"))? {
            let entry = entry?;
            let meta_path = entry.path().join("meta.json");
            let bytes = read_regular(&meta_path, MAX_JSON)?;
            let meta: RepoMeta = serde_json::from_slice(&bytes)?;
            ensure!(meta.schema == SCHEMA, "unsupported repository schema");
            valid_id(&meta.repo_id)?;
            ensure!(valid_name(&meta.name), "invalid repository name");
            valid_oid(&meta.head_oid)?;
            repos.push(meta);
        }
        repos.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(repos)
    }

    fn find_repo_by_name(&self, name: &str) -> Result<RepoMeta> {
        ensure!(valid_name(name), "invalid repository name");
        self.list_repos()?
            .into_iter()
            .find(|r| r.name == name)
            .with_context(|| format!("repository {name} not found"))
    }

    fn read_repo(&self, repo_id: &str) -> Result<RepoMeta> {
        valid_id(repo_id)?;
        let bytes = read_regular(
            &self.root.join("repos").join(repo_id).join("meta.json"),
            MAX_JSON,
        )?;
        let meta: RepoMeta = serde_json::from_slice(&bytes)?;
        ensure!(
            meta.schema == SCHEMA && meta.repo_id == repo_id,
            "invalid repository metadata"
        );
        Ok(meta)
    }

    fn repo_git_dir(&self, repo_id: &str) -> PathBuf {
        self.root.join("repos").join(repo_id).join("repo.git")
    }

    fn ensure_no_active_lease(&self, repo_id: &str) -> Result<()> {
        let lease_name = format!("{repo_id}.json");
        let lease_path = self.root.join("leases").join(lease_name);
        ensure!(
            !lease_path.try_exists()?,
            "repository ref write lease is held by an active cross-repository changeset"
        );
        Ok(())
    }

    fn register_repo(&self, name: &str, source: &Path) -> Result<serde_json::Value> {
        ensure!(valid_name(name), "invalid repository name");
        self.ensure_not_overlapping(source)?;
        ensure!(
            self.list_repos()?.iter().all(|r| r.name != name),
            "repository name already registered"
        );
        ensure!(
            self.git_text(source, &["rev-parse", "--show-object-format"])? == "sha1",
            "only SHA-1 repositories are supported"
        );
        let head_oid = self.git_text(source, &["rev-parse", "--verify", "HEAD^{commit}"])?;
        valid_oid(&head_oid)?;

        let repo_id = new_id();
        let staging = self.stage()?;
        let bare = staging.0.join("repo.git");
        private_dir(&bare)?;
        self.git(&bare, &["init", "--bare", "--initial-branch=main"])?;
        let source_str = source.to_str().context("source path must be UTF-8")?;
        let refspec = format!("{head_oid}:refs/heads/main");
        self.git(&bare, &["fetch", "--no-tags", source_str, &refspec])?;
        self.git(&bare, &["fsck", "--full", "--strict"])?;

        let meta = RepoMeta {
            schema: SCHEMA,
            repo_id: repo_id.clone(),
            name: name.to_owned(),
            head_oid: head_oid.clone(),
            generation: 1,
        };
        write_new(
            &staging.0.join("meta.json"),
            &serde_json::to_vec_pretty(&meta)?,
            0o600,
        )?;
        sync_tree(&staging.0)?;
        let destination = self.root.join("repos").join(&repo_id);
        publish(&staging.0, &destination)?;
        Ok(serde_json::json!({
            "repo_id": repo_id,
            "name": name,
            "head_oid": head_oid,
            "generation": 1,
            "repo_path": destination.join("repo.git").to_string_lossy(),
        }))
    }

    fn advance_repo(&self, name: &str, source: &Path) -> Result<serde_json::Value> {
        self.ensure_not_overlapping(source)?;
        let mut meta = self.find_repo_by_name(name)?;
        self.ensure_no_active_lease(&meta.repo_id)?;
        let bare = self.repo_git_dir(&meta.repo_id);
        let current_oid = self.git_text(&bare, &["rev-parse", "--verify", "refs/heads/main"])?;
        ensure!(
            current_oid == meta.head_oid,
            "repository HEAD diverged from metadata"
        );
        let new_oid = self.git_text(source, &["rev-parse", "--verify", "HEAD^{commit}"])?;
        valid_oid(&new_oid)?;
        ensure!(
            new_oid != current_oid,
            "repository HEAD is already at target OID"
        );

        let source_str = source.to_str().context("source path must be UTF-8")?;
        let staging_ref = format!("refs/rootyard/advance/{}", new_id());
        let refspec = format!("{new_oid}:{staging_ref}");
        self.git(&bare, &["fetch", "--no-tags", source_str, &refspec])?;
        let is_ancestor = self
            .git_output_with_env(
                &bare,
                &["merge-base", "--is-ancestor", &current_oid, &new_oid],
                &[],
                None,
            )?
            .status
            .success();
        if !is_ancestor {
            let _ = self.git(&bare, &["update-ref", "-d", &staging_ref]);
            bail!("non-fast-forward advance rejected");
        }
        self.git(&bare, &["fsck", "--full", "--strict"])?;
        self.git(
            &bare,
            &["update-ref", "refs/heads/main", &new_oid, &current_oid],
        )?;
        let _ = self.git(&bare, &["update-ref", "-d", &staging_ref]);

        let old_oid = meta.head_oid;
        meta.head_oid = new_oid.clone();
        meta.generation += 1;
        write_atomic_json(
            &self
                .root
                .join("repos")
                .join(&meta.repo_id)
                .join("meta.json"),
            &meta,
        )?;
        Ok(serde_json::json!({
            "repo_id": meta.repo_id,
            "name": meta.name,
            "old_head_oid": old_oid,
            "head_oid": new_oid,
            "generation": meta.generation,
        }))
    }

    fn create_namespace(&self, namespace: &str, specs: &[String]) -> Result<serde_json::Value> {
        ensure!(valid_name(namespace), "invalid namespace name");
        ensure!(
            !specs.is_empty(),
            "at least one mount specification is required"
        );

        let mut parsed_mounts = Vec::new();
        let mut seen_repos = BTreeSet::new();
        let spec_err = "mount specification must have form MOUNT_PATH=REPO_NAME@BASE_OID";
        for spec in specs {
            let (mount_raw, rhs) = spec.split_once('=').context(spec_err)?;
            let (repo_name, base_oid) = rhs.split_once('@').context(spec_err)?;
            let mount_path = normalize_mount_path(mount_raw)?;
            valid_oid(base_oid)?;
            let repo = self.find_repo_by_name(repo_name)?;
            ensure!(
                seen_repos.insert(repo.repo_id.clone()),
                "duplicate repository in namespace mounts"
            );
            let bare = self.repo_git_dir(&repo.repo_id);
            ensure!(
                self.git_text(&bare, &["cat-file", "-t", base_oid])? == "commit",
                "base OID {base_oid} does not identify a commit in {repo_name}"
            );
            parsed_mounts.push(MountEntry {
                mount_path,
                repo_id: repo.repo_id,
                repo_name: repo.name,
                base_oid: base_oid.to_owned(),
            });
        }
        parsed_mounts.sort_by(|a, b| a.mount_path.cmp(&b.mount_path));
        validate_non_overlapping_mounts(&parsed_mounts)?;

        let mut max_revision = 0_u64;
        for entry in fs::read_dir(self.root.join("namespaces"))? {
            let entry = entry?;
            let manifest_path = entry.path().join("manifest.json");
            let bytes = read_regular(&manifest_path, MAX_JSON)?;
            let rev: NamespaceRevision = serde_json::from_slice(&bytes)?;
            if rev.namespace == namespace && rev.revision_number > max_revision {
                max_revision = rev.revision_number;
            }
        }
        let revision_id = new_id();
        let revision_number = max_revision + 1;

        for mount in &parsed_mounts {
            let bare = self.repo_git_dir(&mount.repo_id);
            let pin_ref = format!("refs/rootyard/namespace-pins/{revision_id}");
            self.git(&bare, &["update-ref", &pin_ref, &mount.base_oid])?;
        }

        let revision = NamespaceRevision {
            schema: SCHEMA,
            revision_id: revision_id.clone(),
            namespace: namespace.to_owned(),
            revision_number,
            mounts: parsed_mounts,
        };
        let bytes = serde_json::to_vec_pretty(&revision)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        let staging = self.stage()?;
        write_new(&staging.0.join("manifest.json"), &bytes, 0o600)?;
        write_new(&staging.0.join("manifest.sha256"), digest.as_bytes(), 0o600)?;
        sync_tree(&staging.0)?;
        let dest = self.root.join("namespaces").join(&revision_id);
        publish(&staging.0, &dest)?;
        Ok(serde_json::json!({
            "revision_id": revision_id,
            "namespace": namespace,
            "revision_number": revision_number,
            "manifest_sha256": digest,
            "mounts": revision.mounts,
        }))
    }

    fn read_namespace_revision(&self, revision_id: &str) -> Result<NamespaceRevision> {
        valid_id(revision_id)?;
        let dir = self.root.join("namespaces").join(revision_id);
        require_directory(&dir)?;
        let bytes = read_regular(&dir.join("manifest.json"), MAX_JSON)?;
        let digest = read_regular(&dir.join("manifest.sha256"), 64)?;
        ensure!(
            digest == hex::encode(Sha256::digest(&bytes)).as_bytes(),
            "namespace revision checksum mismatch"
        );
        let rev: NamespaceRevision = serde_json::from_slice(&bytes)?;
        ensure!(
            rev.schema == SCHEMA && rev.revision_id == revision_id,
            "invalid namespace revision manifest"
        );
        validate_non_overlapping_mounts(&rev.mounts)?;
        Ok(rev)
    }

    fn project_subdir(
        &self,
        view_name: &str,
        repo_name: &str,
        subdir_raw: &str,
    ) -> Result<serde_json::Value> {
        ensure!(valid_name(view_name), "invalid view name");
        let subdir = normalize_mount_path(subdir_raw)?;
        let repo = self.find_repo_by_name(repo_name)?;
        let source_bare = self.repo_git_dir(&repo.repo_id);
        let source_head =
            self.git_text(&source_bare, &["rev-parse", "--verify", "refs/heads/main"])?;

        let commits_text = self.git_text(
            &source_bare,
            &["rev-list", "--topo-order", "--reverse", "refs/heads/main"],
        )?;
        let source_commits: Vec<&str> = commits_text
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        ensure!(
            !source_commits.is_empty(),
            "source repository has no commits"
        );

        let staging = self.stage()?;
        let view_bare = staging.0.join("repo.git");
        private_dir(&view_bare)?;
        self.git(&view_bare, &["init", "--bare", "--initial-branch=main"])?;
        let source_str = source_bare.to_str().context("path must be UTF-8")?;
        let refspec = format!("{source_head}:refs/rootyard/tmp-source");
        self.git(&view_bare, &["fetch", "--no-tags", source_str, &refspec])?;

        let mut commit_map: BTreeMap<String, String> = BTreeMap::new();
        let mut commit_tree_map: BTreeMap<String, String> = BTreeMap::new();

        for src_oid in source_commits {
            let parents_line =
                self.git_text(&view_bare, &["rev-list", "--parents", "-n", "1", src_oid])?;
            let mut mapped_parents = Vec::new();
            for parent_src in parents_line.split_whitespace().skip(1) {
                if let Some(mapped) = commit_map.get(parent_src)
                    && !mapped_parents.contains(mapped)
                {
                    mapped_parents.push(mapped.clone());
                }
            }

            let spec = format!("{src_oid}:{subdir}");
            let subtree_out =
                self.git_output_with_env(&view_bare, &["rev-parse", "--verify", &spec], &[], None)?;
            let subtree_oid = if subtree_out.status.success() {
                let raw_text = String::from_utf8(subtree_out.stdout)?;
                let candidate = raw_text.trim().to_owned();
                if self.git_text(&view_bare, &["cat-file", "-t", &candidate])? == "tree" {
                    Some(candidate)
                } else {
                    None
                }
            } else {
                None
            };

            let Some(subtree_oid) = subtree_oid else {
                if let Some(first_parent) = mapped_parents.first() {
                    commit_map.insert(src_oid.to_owned(), first_parent.clone());
                }
                continue;
            };

            if !mapped_parents.is_empty()
                && mapped_parents
                    .iter()
                    .all(|p| commit_tree_map.get(p) == Some(&subtree_oid))
            {
                commit_map.insert(src_oid.to_owned(), mapped_parents[0].clone());
                continue;
            }

            let raw_meta = self.git(
                &view_bare,
                &[
                    "log",
                    "-1",
                    "--date=raw",
                    "--format=%an%x00%ae%x00%ad%x00%cn%x00%ce%x00%cd%x00%B",
                    src_oid,
                ],
            )?;
            let mut fields = raw_meta.splitn(7, |b| *b == 0);
            let author_name = next_utf8_field(&mut fields, "missing author name")?;
            let author_email = next_utf8_field(&mut fields, "missing author email")?;
            let author_date = next_utf8_field(&mut fields, "missing author date")?;
            let committer_name = next_utf8_field(&mut fields, "missing committer name")?;
            let committer_email = next_utf8_field(&mut fields, "missing committer email")?;
            let committer_date = next_utf8_field(&mut fields, "missing committer date")?;
            let raw_body = fields.next().context("missing commit body")?;
            let body = raw_body.strip_suffix(b"\n").unwrap_or(raw_body);

            let mut c_args = vec!["commit-tree", &subtree_oid];
            for parent in &mapped_parents {
                c_args.push("-p");
                c_args.push(parent);
            }
            let env = [
                ("GIT_AUTHOR_NAME", author_name),
                ("GIT_AUTHOR_EMAIL", author_email),
                ("GIT_AUTHOR_DATE", author_date),
                ("GIT_COMMITTER_NAME", committer_name),
                ("GIT_COMMITTER_EMAIL", committer_email),
                ("GIT_COMMITTER_DATE", committer_date),
            ];
            let proj_out = self.git_with_input(&view_bare, &c_args, &env, body)?;
            let proj_oid = String::from_utf8(proj_out)?.trim().to_owned();
            commit_tree_map.insert(proj_oid.clone(), subtree_oid);
            commit_map.insert(src_oid.to_owned(), proj_oid);
        }

        let projected_head = commit_map
            .get(&source_head)
            .context("subdirectory never appeared in source history")?
            .clone();
        self.git(
            &view_bare,
            &["update-ref", "refs/heads/main", &projected_head],
        )?;
        self.git(
            &view_bare,
            &["update-ref", "-d", "refs/rootyard/tmp-source"],
        )?;
        self.git(&view_bare, &["repack", "-adq"])?;
        self.git(&view_bare, &["prune", "--expire=now"])?;
        self.git(&view_bare, &["fsck", "--full", "--strict"])?;

        let view_id = new_id();
        let meta = ViewMeta {
            schema: SCHEMA,
            view_id: view_id.clone(),
            view_name: view_name.to_owned(),
            strategy: "subdirectory_projection".into(),
            revision_id: None,
            source_repo_id: Some(repo.repo_id),
            subdir_path: Some(subdir.clone()),
            view_base_oid: projected_head.clone(),
            head_oid: projected_head.clone(),
            view_epoch: 1,
        };
        write_new(
            &staging.0.join("view.json"),
            &serde_json::to_vec_pretty(&meta)?,
            0o600,
        )?;
        write_new(
            &staging.0.join("commit_map.json"),
            &serde_json::to_vec_pretty(&commit_map)?,
            0o600,
        )?;
        sync_tree(&staging.0)?;
        let destination = self.root.join("views").join(&view_id);
        publish(&staging.0, &destination)?;

        Ok(serde_json::json!({
            "view_id": view_id,
            "view_name": view_name,
            "strategy": "subdirectory_projection",
            "source_repo": repo_name,
            "subdir_path": subdir,
            "source_head_oid": source_head,
            "projected_head_oid": projected_head,
            "projected_commits": commit_tree_map.len(),
            "commit_map": commit_map,
            "repo_path": destination.join("repo.git").to_string_lossy(),
        }))
    }

    fn create_task_view(&self, view_name: &str, revision_id: &str) -> Result<serde_json::Value> {
        ensure!(valid_name(view_name), "invalid view name");
        let revision = self.read_namespace_revision(revision_id)?;
        let staging = self.stage()?;
        let view_bare = staging.0.join("repo.git");
        private_dir(&view_bare)?;
        self.git(&view_bare, &["init", "--bare", "--initial-branch=main"])?;

        let mut mount_trees = Vec::new();
        for mount in &revision.mounts {
            let repo_bare = self.repo_git_dir(&mount.repo_id);
            let repo_str = repo_bare.to_str().context("path must be UTF-8")?;
            let mount_ref = format!("refs/rootyard/mounts/{}", mount.repo_id);
            let refspec = format!("{}:{mount_ref}", mount.base_oid);
            self.git(&view_bare, &["fetch", "--no-tags", repo_str, &refspec])?;
            let tree_spec = format!("{}^{{tree}}", mount.base_oid);
            let tree_oid = self.git_text(&view_bare, &["rev-parse", "--verify", &tree_spec])?;
            mount_trees.push((mount.mount_path.clone(), tree_oid));
        }

        let root_tree_oid = self.build_composite_tree(&view_bare, &mount_trees)?;
        let msg = format!(
            "Rootyard task snapshot view for namespace {} revision {}\n",
            revision.namespace, revision.revision_id
        );
        let env = [
            ("GIT_AUTHOR_NAME", SYNTHETIC_AUTHOR_NAME),
            ("GIT_AUTHOR_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
            ("GIT_AUTHOR_DATE", SYNTHETIC_DATE),
            ("GIT_COMMITTER_NAME", SYNTHETIC_AUTHOR_NAME),
            ("GIT_COMMITTER_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
            ("GIT_COMMITTER_DATE", SYNTHETIC_DATE),
        ];
        let base_out = self.git_with_input(
            &view_bare,
            &["commit-tree", &root_tree_oid],
            &env,
            msg.as_bytes(),
        )?;
        let view_base_oid = String::from_utf8(base_out)?.trim().to_owned();
        self.git(
            &view_bare,
            &["update-ref", "refs/heads/main", &view_base_oid],
        )?;
        self.git(
            &view_bare,
            &["update-ref", "refs/rootyard/view-base", &view_base_oid],
        )?;
        self.git(&view_bare, &["fsck", "--full", "--strict"])?;

        let view_id = new_id();
        let meta = ViewMeta {
            schema: SCHEMA,
            view_id: view_id.clone(),
            view_name: view_name.to_owned(),
            strategy: "task_snapshot".into(),
            revision_id: Some(revision.revision_id),
            source_repo_id: None,
            subdir_path: None,
            view_base_oid: view_base_oid.clone(),
            head_oid: view_base_oid.clone(),
            view_epoch: 1,
        };
        write_new(
            &staging.0.join("view.json"),
            &serde_json::to_vec_pretty(&meta)?,
            0o600,
        )?;
        sync_tree(&staging.0)?;
        let destination = self.root.join("views").join(&view_id);
        publish(&staging.0, &destination)?;

        Ok(serde_json::json!({
            "view_id": view_id,
            "view_name": view_name,
            "strategy": "task_snapshot",
            "revision_id": revision_id,
            "view_base_oid": view_base_oid,
            "head_oid": view_base_oid,
            "repo_path": destination.join("repo.git").to_string_lossy(),
        }))
    }

    fn build_composite_tree(&self, bare: &Path, mounts: &[(String, String)]) -> Result<String> {
        let mut split_mounts: Vec<(Vec<&str>, &str)> = Vec::new();
        for (path, tree_oid) in mounts {
            let comps: Vec<&str> = path.split('/').collect();
            split_mounts.push((comps, tree_oid.as_str()));
        }
        self.build_tree_level(bare, &split_mounts)
    }

    fn build_tree_level(&self, bare: &Path, items: &[(Vec<&str>, &str)]) -> Result<String> {
        let mut direct: BTreeMap<&str, &str> = BTreeMap::new();
        let mut nested: BTreeMap<&str, Vec<(Vec<&str>, &str)>> = BTreeMap::new();
        for (comps, tree_oid) in items {
            ensure!(!comps.is_empty(), "empty mount path component");
            let head = comps[0];
            if comps.len() == 1 {
                ensure!(
                    !nested.contains_key(head) && direct.insert(head, *tree_oid).is_none(),
                    "overlapping mount tree entry"
                );
            } else {
                ensure!(!direct.contains_key(head), "overlapping mount tree entry");
                nested
                    .entry(head)
                    .or_default()
                    .push((comps[1..].to_vec(), *tree_oid));
            }
        }
        let mut entries: BTreeMap<&str, String> = BTreeMap::new();
        for (name, oid) in direct {
            entries.insert(name, oid.to_owned());
        }
        for (name, children) in nested {
            let child_oid = self.build_tree_level(bare, &children)?;
            entries.insert(name, child_oid);
        }
        let mut input = Vec::new();
        for (name, oid) in entries {
            let record = format!("040000 tree {oid}\t{name}\0");
            input.extend_from_slice(record.as_bytes());
        }
        let out = self.git_with_input(bare, &["mktree", "-z"], &[], &input)?;
        Ok(String::from_utf8(out)?.trim().to_owned())
    }

    fn read_view(&self, view_id: &str) -> Result<ViewMeta> {
        valid_id(view_id)?;
        let bytes = read_regular(
            &self.root.join("views").join(view_id).join("view.json"),
            MAX_JSON,
        )?;
        let meta: ViewMeta = serde_json::from_slice(&bytes)?;
        ensure!(
            meta.schema == SCHEMA && meta.view_id == view_id,
            "invalid view metadata"
        );
        Ok(meta)
    }

    fn view_git_dir(&self, view_id: &str) -> PathBuf {
        self.root.join("views").join(view_id).join("repo.git")
    }

    fn integrate_changeset(&self, view_id: &str, task_ref: &str) -> Result<serde_json::Value> {
        let task_name = task_ref
            .strip_prefix("refs/heads/task/")
            .context("writable view pushes must use refs/heads/task/<name>")?;
        ensure!(valid_name(task_name), "invalid task branch name");

        let view = self.read_view(view_id)?;
        ensure!(
            view.strategy == "task_snapshot",
            "only task_snapshot views accept changeset integration"
        );
        let revision_id = view
            .revision_id
            .as_deref()
            .context("task view missing revision_id")?;
        let revision = self.read_namespace_revision(revision_id)?;
        let view_bare = self.view_git_dir(view_id);

        let view_base_oid = self.git_text(
            &view_bare,
            &["rev-parse", "--verify", "refs/rootyard/view-base"],
        )?;
        ensure!(
            view_base_oid == view.view_base_oid,
            "view base ref diverged from metadata"
        );
        let task_commit_oid = self.git_text(
            &view_bare,
            &["rev-parse", "--verify", &format!("{task_ref}^{{commit}}")],
        )?;
        ensure!(
            task_commit_oid != view_base_oid,
            "task branch has no changes relative to view base"
        );
        let is_ancestor = self
            .git_output_with_env(
                &view_bare,
                &[
                    "merge-base",
                    "--is-ancestor",
                    &view_base_oid,
                    &task_commit_oid,
                ],
                &[],
                None,
            )?
            .status
            .success();
        ensure!(
            is_ancestor,
            "task branch commit must descend from the current view base"
        );

        let mount_prefixes: Vec<&str> = revision
            .mounts
            .iter()
            .map(|m| m.mount_path.as_str())
            .collect();
        let ls_out = self.git(
            &view_bare,
            &["ls-tree", "-r", "-z", "--name-only", &task_commit_oid],
        )?;
        let diff_out = self.git(
            &view_bare,
            &[
                "diff-tree",
                "-r",
                "-z",
                "--name-only",
                &view_base_oid,
                &task_commit_oid,
            ],
        )?;
        for output in [ls_out, diff_out] {
            for raw in output.split(|b| *b == 0).filter(|x| !x.is_empty()) {
                let path = std::str::from_utf8(raw).context("non-UTF-8 path")?;
                normalize_mount_path(path)?;
                ensure!(
                    mount_prefixes
                        .iter()
                        .any(|prefix| path_within_mount(path, prefix)),
                    "path {path} is outside all mounted repositories"
                );
            }
        }

        let changeset_id = new_id();
        let changeset_dir = self.root.join("changesets").join(&changeset_id);
        private_dir(&changeset_dir)?;

        let mut modified_mounts = Vec::new();
        for mount in &revision.mounts {
            let base_tree_spec = format!("{}:{}", view_base_oid, mount.mount_path);
            let base_subtree =
                self.git_text(&view_bare, &["rev-parse", "--verify", &base_tree_spec])?;
            let task_tree_spec = format!("{}:{}", task_commit_oid, mount.mount_path);
            let task_subtree_out = self.git_output_with_env(
                &view_bare,
                &["rev-parse", "--verify", &task_tree_spec],
                &[],
                None,
            )?;
            ensure!(
                task_subtree_out.status.success(),
                "mounted directory {} cannot be deleted entirely from view",
                mount.mount_path
            );
            let raw_task_tree = String::from_utf8(task_subtree_out.stdout)?;
            let task_subtree = raw_task_tree.trim().to_owned();
            ensure!(
                self.git_text(&view_bare, &["cat-file", "-t", &task_subtree])? == "tree",
                "mounted path {} must remain a directory tree",
                mount.mount_path
            );
            if task_subtree != base_subtree {
                modified_mounts.push((mount.clone(), base_subtree, task_subtree));
            }
        }
        ensure!(
            !modified_mounts.is_empty(),
            "task commit modifies no mounted repository trees"
        );
        modified_mounts.sort_by(|a, b| a.0.repo_id.cmp(&b.0.repo_id));

        let view_str = view_bare.to_str().context("path must be UTF-8")?;
        let mut staged_targets = Vec::new();

        for (mount, _base_subtree, task_subtree) in &modified_mounts {
            self.ensure_no_active_lease(&mount.repo_id)?;
            let repo_bare = self.repo_git_dir(&mount.repo_id);
            let current_main =
                self.git_text(&repo_bare, &["rev-parse", "--verify", "refs/heads/main"])?;
            let input_ref = format!("refs/rootyard/changesets/{changeset_id}/input");
            let refspec = format!("{task_commit_oid}:{input_ref}");
            self.git(&repo_bare, &["fetch", "--no-tags", view_str, &refspec])?;

            let current_base_commit = self.git_text(
                &view_bare,
                &[
                    "rev-parse",
                    "--verify",
                    &format!("refs/rootyard/mounts/{}", mount.repo_id),
                ],
            )?;

            let merged_tree = if current_main == current_base_commit {
                task_subtree.clone()
            } else {
                let env = [
                    ("GIT_AUTHOR_NAME", SYNTHETIC_AUTHOR_NAME),
                    ("GIT_AUTHOR_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
                    ("GIT_AUTHOR_DATE", SYNTHETIC_DATE),
                    ("GIT_COMMITTER_NAME", SYNTHETIC_AUTHOR_NAME),
                    ("GIT_COMMITTER_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
                    ("GIT_COMMITTER_DATE", SYNTHETIC_DATE),
                ];
                let delta_out = self.git_with_input(
                    &repo_bare,
                    &["commit-tree", task_subtree, "-p", &current_base_commit],
                    &env,
                    b"temporary reverse-mapped delta\n",
                )?;
                let delta_commit = String::from_utf8(delta_out)?.trim().to_owned();
                let merge_out = self.git_output_with_env(
                    &repo_bare,
                    &["merge-tree", "--write-tree", &current_main, &delta_commit],
                    &[],
                    None,
                )?;
                if !merge_out.status.success() {
                    let _ = self.git(&repo_bare, &["update-ref", "-d", &input_ref]);
                    self.cleanup_candidates(&staged_targets, &changeset_id);
                    let aborted = ChangesetRecord {
                        schema: SCHEMA,
                        changeset_id: changeset_id.clone(),
                        view_id: view_id.to_owned(),
                        task_ref: task_ref.to_owned(),
                        view_base_oid,
                        task_commit_oid,
                        state: "aborted_conflict".into(),
                        targets: staged_targets,
                        projected_view_oid: None,
                    };
                    let cs_file = changeset_dir.join("changeset.json");
                    write_atomic_json(&cs_file, &aborted)?;
                    bail!(
                        "three-way merge conflict in {}; aborted in Phase 1 with zero main updates",
                        mount.repo_name
                    );
                }
                String::from_utf8(merge_out.stdout)?
                    .lines()
                    .next()
                    .context("empty merge-tree output")?
                    .trim()
                    .to_owned()
            };

            let msg = format!(
                "Integrate view {} task {}\n\nRootyard-Changeset-Id: {}\nRootyard-View-Task-Commit: {}\n",
                view.view_name, task_name, changeset_id, task_commit_oid
            );
            let env = [
                ("GIT_AUTHOR_NAME", SYNTHETIC_AUTHOR_NAME),
                ("GIT_AUTHOR_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
                ("GIT_AUTHOR_DATE", SYNTHETIC_DATE),
                ("GIT_COMMITTER_NAME", SYNTHETIC_AUTHOR_NAME),
                ("GIT_COMMITTER_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
                ("GIT_COMMITTER_DATE", SYNTHETIC_DATE),
            ];
            let cand_out = self.git_with_input(
                &repo_bare,
                &["commit-tree", &merged_tree, "-p", &current_main],
                &env,
                msg.as_bytes(),
            )?;
            let candidate_oid = String::from_utf8(cand_out)?.trim().to_owned();
            let candidate_ref = format!("refs/rootyard/changesets/{changeset_id}/candidate");
            self.git(&repo_bare, &["update-ref", &candidate_ref, &candidate_oid])?;
            let _ = self.git(&repo_bare, &["update-ref", "-d", &input_ref]);
            self.git(&repo_bare, &["fsck", "--full", "--strict"])?;

            staged_targets.push(ChangesetTarget {
                repo_id: mount.repo_id.clone(),
                repo_name: mount.repo_name.clone(),
                mount_path: mount.mount_path.clone(),
                base_oid: current_base_commit,
                expected_old_oid: current_main,
                candidate_oid,
            });
        }

        // Phase 2: Acquire ordered per-repo ref write leases and record STAGED state.
        for target in &staged_targets {
            let lease = RefLease {
                schema: SCHEMA,
                repo_id: target.repo_id.clone(),
                ref_name: "refs/heads/main".into(),
                changeset_id: changeset_id.clone(),
            };
            let lease_path = self
                .root
                .join("leases")
                .join(format!("{}.json", target.repo_id));
            write_new(&lease_path, &serde_json::to_vec_pretty(&lease)?, 0o600)?;
        }
        File::open(self.root.join("leases"))?.sync_all()?;

        let mut record = ChangesetRecord {
            schema: SCHEMA,
            changeset_id: changeset_id.clone(),
            view_id: view_id.to_owned(),
            task_ref: task_ref.to_owned(),
            view_base_oid,
            task_commit_oid,
            state: "staged".into(),
            targets: staged_targets,
            projected_view_oid: None,
        };
        let cs_file = changeset_dir.join("changeset.json");
        write_atomic_json(&cs_file, &record)?;

        failpoint("before_commit_point");

        // Pre-commit verification under held leases before the irreversible Commit Point.
        for target in &record.targets {
            let repo_bare = self.repo_git_dir(&target.repo_id);
            let actual_main =
                self.git_text(&repo_bare, &["rev-parse", "--verify", "refs/heads/main"])?;
            let candidate_ref = format!("refs/rootyard/changesets/{changeset_id}/candidate");
            let actual_cand =
                self.git_text(&repo_bare, &["rev-parse", "--verify", &candidate_ref])?;
            if actual_main != target.expected_old_oid || actual_cand != target.candidate_oid {
                self.release_leases(&record.targets, &changeset_id)?;
                self.cleanup_candidates(&record.targets, &changeset_id);
                record.state = "aborted_cas_mismatch".into();
                write_atomic_json(&cs_file, &record)?;
                bail!(
                    "pre-commit CAS mismatch on {}; aborted before commit point",
                    target.repo_name
                );
            }
        }

        // Irreversible Commit Point: all leases held, all candidates verified.
        record.state = "committing".into();
        write_atomic_json(&cs_file, &record)?;

        // Phase 3: Roll-forward pointer flips and view re-projection.
        self.complete_committing_changeset(&mut record, true)
    }

    fn recover_changeset(&self, changeset_id: &str) -> Result<serde_json::Value> {
        valid_id(changeset_id)?;
        let path = self
            .root
            .join("changesets")
            .join(changeset_id)
            .join("changeset.json");
        let bytes = read_regular(&path, MAX_JSON)?;
        let mut record: ChangesetRecord = serde_json::from_slice(&bytes)?;
        ensure!(
            record.schema == SCHEMA && record.changeset_id == changeset_id,
            "invalid changeset record"
        );
        match record.state.as_str() {
            "staged" => {
                // Crashed before the Commit Point: clean up candidate refs and leases.
                self.release_leases(&record.targets, changeset_id)?;
                self.cleanup_candidates(&record.targets, changeset_id);
                record.state = "aborted_pre_commit".into();
                write_atomic_json(&path, &record)?;
                Ok(serde_json::to_value(&record)?)
            }
            "committing" => self.complete_committing_changeset(&mut record, false),
            "integrated" | "aborted_conflict" | "aborted_cas_mismatch" | "aborted_pre_commit" => {
                Ok(serde_json::to_value(&record)?)
            }
            other => bail!("unsupported changeset state {other}"),
        }
    }

    fn complete_committing_changeset(
        &self,
        record: &mut ChangesetRecord,
        allow_mid_failpoint: bool,
    ) -> Result<serde_json::Value> {
        for (index, target) in record.targets.iter().enumerate() {
            let repo_bare = self.repo_git_dir(&target.repo_id);
            let current_main =
                self.git_text(&repo_bare, &["rev-parse", "--verify", "refs/heads/main"])?;
            if current_main != target.candidate_oid {
                ensure!(
                    current_main == target.expected_old_oid,
                    "unexpected repository main OID during committing roll-forward"
                );
                self.git(
                    &repo_bare,
                    &[
                        "update-ref",
                        "refs/heads/main",
                        &target.candidate_oid,
                        &target.expected_old_oid,
                    ],
                )?;
            }
            let mut meta = self.read_repo(&target.repo_id)?;
            if meta.head_oid != target.candidate_oid {
                meta.head_oid = target.candidate_oid.clone();
                meta.generation += 1;
                write_atomic_json(
                    &self
                        .root
                        .join("repos")
                        .join(&meta.repo_id)
                        .join("meta.json"),
                    &meta,
                )?;
            }
            if index == 0 && allow_mid_failpoint {
                failpoint("mid_commit_after_first_repo");
            }
        }

        // Re-project the composite view's canonical refs/heads/main to match the new source tips.
        let mut view = self.read_view(&record.view_id)?;
        let revision_id = view
            .revision_id
            .as_deref()
            .context("task view missing revision_id")?;
        let revision = self.read_namespace_revision(revision_id)?;
        let view_bare = self.view_git_dir(&record.view_id);

        let mut mount_trees = Vec::new();
        for mount in &revision.mounts {
            let repo_bare = self.repo_git_dir(&mount.repo_id);
            let repo_main =
                self.git_text(&repo_bare, &["rev-parse", "--verify", "refs/heads/main"])?;
            let repo_str = repo_bare.to_str().context("path must be UTF-8")?;
            let mount_ref = format!("refs/rootyard/mounts/{}", mount.repo_id);
            let refspec = format!("{repo_main}:{mount_ref}");
            self.git(&view_bare, &["fetch", "--no-tags", repo_str, &refspec])?;
            let tree_spec = format!("{repo_main}^{{tree}}");
            let tree_oid = self.git_text(&view_bare, &["rev-parse", "--verify", &tree_spec])?;
            mount_trees.push((mount.mount_path.clone(), tree_oid));
        }

        let new_root_tree = self.build_composite_tree(&view_bare, &mount_trees)?;
        let msg = format!(
            "Projected view main after {}\n\nRootyard-Changeset-Id: {}\nRootyard-Replaces-Task-Commit: {}\n",
            record.changeset_id, record.changeset_id, record.task_commit_oid
        );
        let env = [
            ("GIT_AUTHOR_NAME", SYNTHETIC_AUTHOR_NAME),
            ("GIT_AUTHOR_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
            ("GIT_AUTHOR_DATE", SYNTHETIC_DATE),
            ("GIT_COMMITTER_NAME", SYNTHETIC_AUTHOR_NAME),
            ("GIT_COMMITTER_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
            ("GIT_COMMITTER_DATE", SYNTHETIC_DATE),
        ];
        let proj_out = self.git_with_input(
            &view_bare,
            &["commit-tree", &new_root_tree, "-p", &record.view_base_oid],
            &env,
            msg.as_bytes(),
        )?;
        let projected_oid = String::from_utf8(proj_out)?.trim().to_owned();
        self.git(
            &view_bare,
            &["update-ref", "refs/heads/main", &projected_oid],
        )?;
        self.git(
            &view_bare,
            &["update-ref", "refs/rootyard/view-base", &projected_oid],
        )?;
        let integrated_ref = format!("refs/rootyard/integrated/{}", record.changeset_id);
        self.git(&view_bare, &["update-ref", &integrated_ref, &projected_oid])?;
        self.git(&view_bare, &["fsck", "--full", "--strict"])?;

        view.view_base_oid = projected_oid.clone();
        view.head_oid = projected_oid.clone();
        view.view_epoch += 1;
        write_atomic_json(
            &self
                .root
                .join("views")
                .join(&view.view_id)
                .join("view.json"),
            &view,
        )?;

        record.state = "integrated".into();
        record.projected_view_oid = Some(projected_oid);
        let changeset_path = self
            .root
            .join("changesets")
            .join(&record.changeset_id)
            .join("changeset.json");
        write_atomic_json(&changeset_path, record)?;

        self.release_leases(&record.targets, &record.changeset_id)?;
        Ok(serde_json::to_value(&*record)?)
    }

    fn release_leases(&self, targets: &[ChangesetTarget], changeset_id: &str) -> Result<()> {
        for target in targets {
            let lease_path = self
                .root
                .join("leases")
                .join(format!("{}.json", target.repo_id));
            if lease_path.try_exists()? {
                let bytes = read_regular(&lease_path, MAX_JSON)?;
                let lease: RefLease = serde_json::from_slice(&bytes)?;
                if lease.changeset_id == changeset_id {
                    fs::remove_file(&lease_path)?;
                }
            }
        }
        File::open(self.root.join("leases"))?.sync_all()?;
        Ok(())
    }

    fn cleanup_candidates(&self, targets: &[ChangesetTarget], changeset_id: &str) {
        let candidate_ref = format!("refs/rootyard/changesets/{changeset_id}/candidate");
        for target in targets {
            let repo_bare = self.repo_git_dir(&target.repo_id);
            let _ = self.git(&repo_bare, &["update-ref", "-d", &candidate_ref]);
        }
    }
}

fn next_utf8_field<'a>(
    fields: &mut impl Iterator<Item = &'a [u8]>,
    message: &'static str,
) -> Result<&'a str> {
    let raw = fields.next().context(message)?;
    Ok(std::str::from_utf8(raw)?)
}

fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

fn text_arg(value: &OsString) -> Result<String> {
    Ok(value.to_str().context("argument must be UTF-8")?.to_owned())
}

fn valid_id(id: &str) -> Result<()> {
    ensure!(
        Uuid::parse_str(id)?.to_string() == id,
        "invalid canonical id"
    );
    Ok(())
}

fn valid_oid(oid: &str) -> Result<()> {
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

fn normalize_mount_path(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    ensure!(
        !bytes.is_empty()
            && !bytes.contains(&0)
            && !bytes.starts_with(b"/")
            && !bytes.ends_with(b"/"),
        "mount path must be a non-empty relative path without leading or trailing slash"
    );
    for part in raw.split('/') {
        ensure!(
            !part.is_empty() && part != "." && part != ".." && part != ".git",
            "unsafe mount path component"
        );
    }
    let path = PathBuf::from(OsString::from_vec(bytes.to_vec()));
    ensure!(
        path.components().all(|c| matches!(c, Component::Normal(_))),
        "unsafe relative mount path"
    );
    Ok(raw.to_owned())
}

fn path_within_mount(path: &str, mount_prefix: &str) -> bool {
    path == mount_prefix
        || (path.starts_with(mount_prefix)
            && path.as_bytes().get(mount_prefix.len()) == Some(&b'/'))
}

fn validate_non_overlapping_mounts(mounts: &[MountEntry]) -> Result<()> {
    ensure!(!mounts.is_empty(), "mounts cannot be empty");
    for (i, left) in mounts.iter().enumerate() {
        normalize_mount_path(&left.mount_path)?;
        for right in &mounts[i + 1..] {
            ensure!(
                !path_within_mount(&left.mount_path, &right.mount_path)
                    && !path_within_mount(&right.mount_path, &left.mount_path),
                "overlapping namespace mounts {} and {}",
                left.mount_path,
                right.mount_path
            );
        }
    }
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
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_paths_reject_overlap_and_traversal() {
        for good in ["libs/proto", "services/search", "a/b/c"] {
            assert!(normalize_mount_path(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "/libs/proto",
            "libs/proto/",
            "libs//proto",
            "libs/../proto",
            "libs/./proto",
            ".git",
            "libs/.git/config",
        ] {
            assert!(normalize_mount_path(bad).is_err(), "{bad}");
        }

        let m1 = MountEntry {
            mount_path: "libs/proto".into(),
            repo_id: new_id(),
            repo_name: "proto".into(),
            base_oid: "a".repeat(40),
        };
        let m2 = MountEntry {
            mount_path: "libs/proto/v2".into(),
            repo_id: new_id(),
            repo_name: "proto2".into(),
            base_oid: "b".repeat(40),
        };
        let m3 = MountEntry {
            mount_path: "libs/proto-extra".into(),
            repo_id: new_id(),
            repo_name: "proto3".into(),
            base_oid: "c".repeat(40),
        };
        let overlapping = [m1.clone(), m2];
        let disjoint = [m1, m3];
        assert!(validate_non_overlapping_mounts(&overlapping).is_err());
        assert!(validate_non_overlapping_mounts(&disjoint).is_ok());
    }
}
