//! Repository registration, namespace revision manifests, and mount path validation.

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    os::unix::ffi::OsStringExt,
    path::{Component, Path, PathBuf},
};

use super::models::*;

impl Store {
    pub fn list_repos(&self) -> Result<Vec<RepoMeta>> {
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

    pub fn find_repo_by_name(&self, name: &str) -> Result<RepoMeta> {
        ensure!(valid_name(name), "invalid repository name");
        self.list_repos()?
            .into_iter()
            .find(|r| r.name == name)
            .with_context(|| format!("repository {name} not found"))
    }

    pub fn read_repo(&self, repo_id: &str) -> Result<RepoMeta> {
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

    pub fn register_repo(&self, name: &str, source: &Path) -> Result<serde_json::Value> {
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

    pub fn advance_repo(&self, name: &str, source: &Path) -> Result<serde_json::Value> {
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

    pub fn create_namespace(&self, namespace: &str, specs: &[String]) -> Result<serde_json::Value> {
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

    pub fn read_namespace_revision(&self, revision_id: &str) -> Result<NamespaceRevision> {
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
}

pub fn normalize_mount_path(raw: &str) -> Result<String> {
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

pub fn path_within_mount(path: &str, mount_prefix: &str) -> bool {
    path == mount_prefix
        || (path.starts_with(mount_prefix)
            && path.as_bytes().get(mount_prefix.len()) == Some(&b'/'))
}

pub fn validate_non_overlapping_mounts(mounts: &[MountEntry]) -> Result<()> {
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
