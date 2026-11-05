//! Deterministic subdirectory projection, long-term history strategies, and composite task views.

use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use super::models::*;
use super::namespace::{make_provenance_record, normalize_mount_path};

impl Store {
    pub fn project_subdir(
        &self,
        view_name: &str,
        repo_name: &str,
        subdir_raw: &str,
    ) -> Result<serde_json::Value> {
        let strat = "subdirectory_projection";
        self.project_repo_history(view_name, repo_name, Some(subdir_raw), strat, None, false)
    }

    pub fn project_history_cli(&self, args: &[OsString]) -> Result<serde_json::Value> {
        let usage = "project-history requires STORE VIEW_NAME TARGET_SPEC [--strategy ...] [--subdir ...] [--epoch ...]";
        ensure!(args.len() >= 2, "{usage}");
        let view_name = text_arg(&args[0])?;
        let mut target = text_arg(&args[1])?;
        let mut strategy = "deterministic_history".to_owned();
        let (mut subdir, mut epoch) = (None, None);
        let mut i = 2;
        while i + 1 < args.len() {
            let val = text_arg(&args[i + 1])?;
            match text_arg(&args[i])?.as_str() {
                "--strategy" => strategy = val,
                "--subdir" => subdir = Some(val),
                "--epoch" => epoch = Some(val.parse().context("invalid --epoch")?),
                other => bail!("unknown project-history flag {other}"),
            }
            i += 2;
        }
        ensure!(i == args.len(), "dangling project-history flag");
        let valid_strat = matches!(strategy.as_str(), "deterministic_history" | "task_snapshot");
        ensure!(valid_strat, "unsupported projection strategy {strategy}");
        if valid_id(&target).is_ok() && self.root.join("namespaces").join(&target).exists() {
            ensure!(
                subdir.is_none(),
                "--subdir cannot be combined with a namespace target"
            );
            if strategy == "task_snapshot" {
                return self.create_task_view(&view_name, &target);
            }
            let rev = self.read_namespace_revision(&target)?;
            target = rev
                .mounts
                .first()
                .context("empty namespace mounts")?
                .repo_name
                .clone();
        }
        self.project_repo_history(
            &view_name,
            &target,
            subdir.as_deref(),
            &strategy,
            epoch,
            true,
        )
    }

    fn find_view_by_name(&self, view_name: &str) -> Result<Option<ViewMeta>> {
        for entry in fs::read_dir(self.root.join("views"))? {
            let meta = self.read_view(&entry?.file_name().to_string_lossy())?;
            if meta.view_name == view_name {
                return Ok(Some(meta));
            }
        }
        Ok(None)
    }

    fn project_repo_history(
        &self,
        view_name: &str,
        repo_name: &str,
        subdir_raw: Option<&str>,
        strategy: &str,
        requested_epoch: Option<u64>,
        attach_trailer: bool,
    ) -> Result<serde_json::Value> {
        ensure!(valid_name(view_name), "invalid view name");
        let subdir = subdir_raw.map(normalize_mount_path).transpose()?;
        let repo = self.find_repo_by_name(repo_name)?;
        let src_bare = self.repo_git_dir(&repo.repo_id);
        let src_head = self.git_text(&src_bare, &["rev-parse", "--verify", "refs/heads/main"])?;

        let existing = self.find_view_by_name(view_name)?;
        ensure!(
            attach_trailer || existing.is_none(),
            "view name already exists"
        );

        let (view_id, view_epoch, mut commit_map, mut epochs, mut prov_commits, staging) =
            if let Some(prev) = &existing {
                let same_cfg = prev.strategy == strategy
                    && prev.source_repo_id.as_deref() == Some(repo.repo_id.as_str())
                    && prev.subdir_path == subdir;
                ensure!(
                    same_cfg,
                    "existing view configuration mismatch for epoch projection"
                );
                let next_ep = requested_epoch.unwrap_or(prev.view_epoch + 1);
                ensure!(
                    next_ep > prev.view_epoch,
                    "view_epoch must exceed {}",
                    prev.view_epoch
                );
                let vdir = self.root.join("views").join(&prev.view_id);
                let load = |f: &str| read_regular(&vdir.join(f), MAX_JSON);
                let cmap: BTreeMap<String, String> = if strategy == "task_snapshot" {
                    BTreeMap::new()
                } else {
                    serde_json::from_slice(&load("commit_map.json")?)?
                };
                let emap: EpochCommitMap = serde_json::from_slice(&load("epoch_commit_map.json")?)?;
                let pman: ViewProvenanceManifest =
                    serde_json::from_slice(&load("provenance.json")?)?;
                let kept = if strategy == "task_snapshot" {
                    Vec::new()
                } else {
                    pman.commits
                };
                (prev.view_id.clone(), next_ep, cmap, emap.epochs, kept, None)
            } else {
                let ep = requested_epoch.unwrap_or(1);
                ensure!(ep >= 1, "view_epoch must be at least 1");
                let stg = self.stage()?;
                let vbare = stg.0.join("repo.git");
                private_dir(&vbare)?;
                self.git(&vbare, &["init", "--bare", "--initial-branch=main"])?;
                let (cmap, emap) = (BTreeMap::new(), BTreeMap::new());
                (new_id(), ep, cmap, emap, Vec::new(), Some(stg))
            };

        let view_dir = staging
            .as_ref()
            .map_or_else(|| self.root.join("views").join(&view_id), |s| s.0.clone());
        let view_bare = view_dir.join("repo.git");
        let src_str = src_bare.to_str().context("path must be UTF-8")?;
        let tmp_ref = format!("{src_head}:refs/rootyard/tmp-source");
        self.git(&view_bare, &["fetch", "--no-tags", src_str, &tmp_ref])?;

        let source_commits: Vec<String> = if strategy == "task_snapshot" {
            vec![src_head.clone()]
        } else {
            let rev_args = ["rev-list", "--topo-order", "--reverse", "refs/heads/main"];
            self.git_text(&src_bare, &rev_args)?
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        };
        ensure!(
            !source_commits.is_empty(),
            "source repository has no commits"
        );

        let mut commit_tree_map: BTreeMap<String, String> = prov_commits
            .iter()
            .map(|r| (r.projected_commit_oid.clone(), r.projected_tree_oid.clone()))
            .collect();
        let (mut newly_projected, mut reused_commits) = (0usize, 0usize);

        for src_oid in &source_commits {
            if strategy != "task_snapshot" && commit_map.contains_key(src_oid) {
                reused_commits += 1;
                continue;
            }
            let mut mapped_parents = Vec::new();
            if strategy != "task_snapshot" {
                let p_line =
                    self.git_text(&view_bare, &["rev-list", "--parents", "-n", "1", src_oid])?;
                for parent_src in p_line.split_whitespace().skip(1) {
                    if let Some(m) = commit_map.get(parent_src)
                        && !mapped_parents.contains(m)
                    {
                        mapped_parents.push(m.clone());
                    }
                }
            }

            let spec = subdir.as_ref().map_or_else(
                || format!("{src_oid}^{{tree}}"),
                |s| format!("{src_oid}:{s}"),
            );
            let t_out =
                self.git_output_with_env(&view_bare, &["rev-parse", "--verify", &spec], &[], None)?;
            let subtree_oid = if t_out.status.success() {
                let cand = String::from_utf8(t_out.stdout)?.trim().to_owned();
                (self.git_text(&view_bare, &["cat-file", "-t", &cand])? == "tree").then_some(cand)
            } else {
                None
            };
            let Some(subtree_oid) = subtree_oid else {
                if let Some(first_parent) = mapped_parents.first() {
                    commit_map.insert(src_oid.clone(), first_parent.clone());
                }
                continue;
            };

            if strategy != "task_snapshot"
                && !mapped_parents.is_empty()
                && mapped_parents
                    .iter()
                    .all(|p| commit_tree_map.get(p) == Some(&subtree_oid))
            {
                commit_map.insert(src_oid.clone(), mapped_parents[0].clone());
                continue;
            }

            let sig_info = self.inspect_source_signature(&view_bare, src_oid)?;
            let ctx = (view_id.as_str(), strategy, view_epoch);
            let oids = ("", src_oid.as_str(), subtree_oid.as_str());
            let mut rec = make_provenance_record(ctx, oids, mapped_parents.clone(), sig_info);
            let fmt = "--format=%an%x00%ae%x00%ad%x00%cn%x00%ce%x00%cd%x00%B";
            let raw_meta = self.git(&view_bare, &["log", "-1", "--date=raw", fmt, src_oid])?;
            let mut fields = raw_meta.splitn(7, |b| *b == 0);
            let an = next_utf8_field(&mut fields, "missing author name")?;
            let ae = next_utf8_field(&mut fields, "missing author email")?;
            let ad = next_utf8_field(&mut fields, "missing author date")?;
            let cn = next_utf8_field(&mut fields, "missing committer name")?;
            let ce = next_utf8_field(&mut fields, "missing committer email")?;
            let cd = next_utf8_field(&mut fields, "missing committer date")?;
            let raw_body = fields.next().context("missing commit body")?;
            let mut body = raw_body.strip_suffix(b"\n").unwrap_or(raw_body).to_vec();
            if attach_trailer {
                let tr = format!("\nRootyard-View-Signature: {}\n", rec.platform_signature);
                body.extend_from_slice(tr.as_bytes());
            }

            let mut c_args = vec!["commit-tree", &subtree_oid];
            for parent in &mapped_parents {
                c_args.extend(["-p", parent.as_str()]);
            }
            let env = [
                ("GIT_AUTHOR_NAME", an),
                ("GIT_AUTHOR_EMAIL", ae),
                ("GIT_AUTHOR_DATE", ad),
                ("GIT_COMMITTER_NAME", cn),
                ("GIT_COMMITTER_EMAIL", ce),
                ("GIT_COMMITTER_DATE", cd),
            ];
            let proj_out = self.git_with_input(&view_bare, &c_args, &env, &body)?;
            let proj_oid = String::from_utf8(proj_out)?.trim().to_owned();
            commit_tree_map.insert(proj_oid.clone(), subtree_oid);
            commit_map.insert(src_oid.clone(), proj_oid.clone());
            rec.projected_commit_oid = proj_oid;
            prov_commits.push(rec);
            newly_projected += 1;
        }

        let projected_head = commit_map
            .get(&src_head)
            .context("subdirectory never appeared in source history")?
            .clone();
        self.git(
            &view_bare,
            &["update-ref", "refs/heads/main", &projected_head],
        )?;
        if strategy == "task_snapshot" {
            self.git(
                &view_bare,
                &["update-ref", "refs/rootyard/view-base", &projected_head],
            )?;
        }
        self.git(
            &view_bare,
            &["update-ref", "-d", "refs/rootyard/tmp-source"],
        )?;
        self.git(&view_bare, &["repack", "-adq"])?;
        self.git(&view_bare, &["prune", "--expire=now"])?;
        self.git(&view_bare, &["fsck", "--full", "--strict"])?;

        let meta = ViewMeta {
            schema: SCHEMA,
            view_id: view_id.clone(),
            view_name: view_name.to_owned(),
            strategy: strategy.into(),
            revision_id: None,
            source_repo_id: Some(repo.repo_id),
            subdir_path: subdir.clone(),
            view_base_oid: projected_head.clone(),
            head_oid: projected_head.clone(),
            view_epoch,
        };
        epochs.insert(view_epoch.to_string(), commit_map.clone());
        let source_signed = prov_commits.iter().filter(|r| r.source_signed).count();
        let total_projected = prov_commits.len();
        write_atomic_json(&view_dir.join("view.json"), &meta)?;
        write_atomic_json(&view_dir.join("commit_map.json"), &commit_map)?;
        self.write_view_provenance(&view_dir, &meta, prov_commits, epochs)?;
        let destination = self.root.join("views").join(&view_id);
        if let Some(stg) = staging {
            sync_tree(&stg.0)?;
            publish(&stg.0, &destination)?;
        }

        Ok(serde_json::json!({
            "view_id": view_id,
            "view_name": view_name,
            "strategy": strategy,
            "view_epoch": view_epoch,
            "source_repo": repo_name,
            "subdir_path": subdir,
            "source_head_oid": src_head,
            "projected_head_oid": projected_head,
            "head_oid": projected_head,
            "projected_commits": total_projected,
            "newly_projected_commits": newly_projected,
            "reused_epoch_commits": reused_commits,
            "rewritten_history_commits": if strategy == "task_snapshot" { 0 } else { total_projected },
            "source_signed_commits": source_signed,
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
        let (mut any_signed, mut sig_kind) = (false, "none".to_owned());
        for mount in &revision.mounts {
            let repo_bare = self.repo_git_dir(&mount.repo_id);
            let repo_str = repo_bare.to_str().context("path must be UTF-8")?;
            let refspec = format!("{}:refs/rootyard/mounts/{}", mount.base_oid, mount.repo_id);
            self.git(&view_bare, &["fetch", "--no-tags", repo_str, &refspec])?;
            let (s, k) = self.inspect_source_signature(&view_bare, &mount.base_oid)?;
            if s {
                (any_signed, sig_kind) = (true, k);
            }
            let tree_spec = format!("{}^{{tree}}", mount.base_oid);
            let tree_oid = self.git_text(&view_bare, &["rev-parse", "--verify", &tree_spec])?;
            mount_trees.push((mount.mount_path.clone(), tree_oid));
        }

        let root_tree = self.build_composite_tree(&view_bare, &mount_trees)?;
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
        let c_args = ["commit-tree", &root_tree];
        let base_out = self.git_with_input(&view_bare, &c_args, &env, msg.as_bytes())?;
        let base_oid = String::from_utf8(base_out)?.trim().to_owned();
        self.git(&view_bare, &["update-ref", "refs/heads/main", &base_oid])?;
        self.git(
            &view_bare,
            &["update-ref", "refs/rootyard/view-base", &base_oid],
        )?;
        self.git(&view_bare, &["fsck", "--full", "--strict"])?;

        let view_id = new_id();
        let meta = ViewMeta {
            schema: SCHEMA,
            view_id: view_id.clone(),
            view_name: view_name.to_owned(),
            strategy: "task_snapshot".into(),
            revision_id: Some(revision.revision_id.clone()),
            source_repo_id: None,
            subdir_path: None,
            view_base_oid: base_oid.clone(),
            head_oid: base_oid.clone(),
            view_epoch: 1,
        };
        let src_oid = revision
            .mounts
            .first()
            .map_or_else(|| base_oid.clone(), |m| m.base_oid.clone());
        let ctx = (view_id.as_str(), "task_snapshot", 1);
        let oids = (base_oid.as_str(), src_oid.as_str(), root_tree.as_str());
        let rec = make_provenance_record(ctx, oids, Vec::new(), (any_signed, sig_kind));
        let cmap = BTreeMap::from([(src_oid, base_oid.clone())]);
        let epochs = BTreeMap::from([("1".into(), cmap.clone())]);
        write_atomic_json(&staging.0.join("view.json"), &meta)?;
        write_atomic_json(&staging.0.join("commit_map.json"), &cmap)?;
        self.write_view_provenance(&staging.0, &meta, vec![rec], epochs)?;
        sync_tree(&staging.0)?;
        let destination = self.root.join("views").join(&view_id);
        publish(&staging.0, &destination)?;

        Ok(serde_json::json!({
            "view_id": view_id,
            "view_name": view_name,
            "strategy": "task_snapshot",
            "view_epoch": 1,
            "revision_id": revision_id,
            "view_base_oid": base_oid,
            "projected_head_oid": base_oid,
            "head_oid": base_oid,
            "projected_commits": 1,
            "rewritten_history_commits": 0,
            "source_signed_commits": usize::from(any_signed),
            "commit_map": cmap,
            "repo_path": destination.join("repo.git").to_string_lossy(),
        }))
    }

    pub(crate) fn build_composite_tree(
        &self,
        bare: &Path,
        mounts: &[(String, String)],
    ) -> Result<String> {
        let split: Vec<(Vec<&str>, &str)> = mounts
            .iter()
            .map(|(p, t)| (p.split('/').collect(), t.as_str()))
            .collect();
        self.build_tree_level(bare, &split)
    }

    fn build_tree_level(&self, bare: &Path, items: &[(Vec<&str>, &str)]) -> Result<String> {
        let mut direct: BTreeMap<&str, &str> = BTreeMap::new();
        let mut nested: BTreeMap<&str, Vec<(Vec<&str>, &str)>> = BTreeMap::new();
        for (comps, tree_oid) in items {
            ensure!(!comps.is_empty(), "empty mount path component");
            let head = comps[0];
            if comps.len() == 1 {
                let fresh = !nested.contains_key(head) && direct.insert(head, *tree_oid).is_none();
                ensure!(fresh, "overlapping mount tree entry");
            } else {
                ensure!(!direct.contains_key(head), "overlapping mount tree entry");
                nested
                    .entry(head)
                    .or_default()
                    .push((comps[1..].to_vec(), *tree_oid));
            }
        }
        let mut entries: BTreeMap<&str, String> =
            direct.into_iter().map(|(k, v)| (k, v.to_owned())).collect();
        for (name, children) in nested {
            entries.insert(name, self.build_tree_level(bare, &children)?);
        }
        let mut input = Vec::new();
        for (name, oid) in entries {
            input.extend_from_slice(format!("040000 tree {oid}\t{name}\0").as_bytes());
        }
        let out = self.git_with_input(bare, &["mktree", "-z"], &[], &input)?;
        Ok(String::from_utf8(out)?.trim().to_owned())
    }

    pub fn read_view(&self, view_id: &str) -> Result<ViewMeta> {
        valid_id(view_id)?;
        let path = self.root.join("views").join(view_id).join("view.json");
        let meta: ViewMeta = serde_json::from_slice(&read_regular(&path, MAX_JSON)?)?;
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
