//! Deterministic subdirectory projection and composite task view construction.

use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use super::models::*;
use super::namespace::normalize_mount_path;

impl Store {
    pub fn project_subdir(
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

    pub fn create_task_view(
        &self,
        view_name: &str,
        revision_id: &str,
    ) -> Result<serde_json::Value> {
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

    pub(crate) fn build_composite_tree(
        &self,
        bare: &Path,
        mounts: &[(String, String)],
    ) -> Result<String> {
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

    pub fn read_view(&self, view_id: &str) -> Result<ViewMeta> {
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

    pub(crate) fn view_git_dir(&self, view_id: &str) -> PathBuf {
        self.root.join("views").join(view_id).join("repo.git")
    }
}
