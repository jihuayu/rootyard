//! Two-phase cross-repository ChangeSet integration, crash recovery, and ref lease cleanup.

use anyhow::{Context, Result, bail, ensure};
use std::fs::{self, File};

use super::models::*;
use super::namespace::{normalize_mount_path, path_within_mount};

impl Store {
    pub fn integrate_changeset(&self, view_id: &str, task_ref: &str) -> Result<serde_json::Value> {
        let task_name = task_ref
            .strip_prefix("refs/heads/task/")
            .context("writable view pushes must use refs/heads/task/<name>")?;
        ensure!(valid_name(task_name), "invalid task branch name");

        let view = self.read_view(view_id)?;
        ensure!(view.strategy == "task_snapshot", "only task_snapshot views accept changeset integration");
        let revision_id = view.revision_id.as_deref().context("task view missing revision_id")?;
        let revision = self.read_namespace_revision(revision_id)?;
        let view_bare = self.view_git_dir(view_id);

        let view_base_oid = self.git_text(&view_bare, &["rev-parse", "--verify", "refs/rootyard/view-base"])?;
        ensure!(view_base_oid == view.view_base_oid, "view base ref diverged from metadata");
        let task_commit_oid =
            self.git_text(&view_bare, &["rev-parse", "--verify", &format!("{task_ref}^{{commit}}")])?;
        ensure!(task_commit_oid != view_base_oid, "task branch has no changes relative to view base");
        let is_ancestor = self
            .git_output_with_env(
                &view_bare,
                &["merge-base", "--is-ancestor", &view_base_oid, &task_commit_oid],
                &[],
                None,
            )?
            .status
            .success();
        ensure!(is_ancestor, "task branch commit must descend from the current view base");

        let mount_prefixes: Vec<&str> = revision.mounts.iter().map(|m| m.mount_path.as_str()).collect();
        let ls_out = self.git(&view_bare, &["ls-tree", "-r", "-z", "--name-only", &task_commit_oid])?;
        let diff_out =
            self.git(&view_bare, &["diff-tree", "-r", "-z", "--name-only", &view_base_oid, &task_commit_oid])?;
        for output in [ls_out, diff_out] {
            for raw in output.split(|b| *b == 0).filter(|x| !x.is_empty()) {
                let path = std::str::from_utf8(raw).context("non-UTF-8 path")?;
                normalize_mount_path(path)?;
                ensure!(
                    mount_prefixes.iter().any(|prefix| path_within_mount(path, prefix)),
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
            let base_subtree = self.git_text(&view_bare, &["rev-parse", "--verify", &base_tree_spec])?;
            let task_tree_spec = format!("{}:{}", task_commit_oid, mount.mount_path);
            let task_subtree_out =
                self.git_output_with_env(&view_bare, &["rev-parse", "--verify", &task_tree_spec], &[], None)?;
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
        ensure!(!modified_mounts.is_empty(), "task commit modifies no mounted repository trees");
        modified_mounts.sort_by(|a, b| a.0.repo_id.cmp(&b.0.repo_id));

        let view_str = view_bare.to_str().context("path must be UTF-8")?;
        let mut staged_targets = Vec::new();

        for (mount, _base_subtree, task_subtree) in &modified_mounts {
            self.ensure_no_active_lease(&mount.repo_id)?;
            let repo_bare = self.repo_git_dir(&mount.repo_id);
            let current_main = self.git_text(&repo_bare, &["rev-parse", "--verify", "refs/heads/main"])?;
            let input_ref = format!("refs/rootyard/changesets/{changeset_id}/input");
            let refspec = format!("{task_commit_oid}:{input_ref}");
            self.git(&repo_bare, &["fetch", "--no-tags", view_str, &refspec])?;

            let current_base_commit = self
                .git_text(&view_bare, &["rev-parse", "--verify", &format!("refs/rootyard/mounts/{}", mount.repo_id)])?;

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
                    bail!("three-way merge conflict in {}; aborted in Phase 1 with zero main updates", mount.repo_name);
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
            let lease_path = self.root.join("leases").join(format!("{}.json", target.repo_id));
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
            let actual_main = self.git_text(&repo_bare, &["rev-parse", "--verify", "refs/heads/main"])?;
            let candidate_ref = format!("refs/rootyard/changesets/{changeset_id}/candidate");
            let actual_cand = self.git_text(&repo_bare, &["rev-parse", "--verify", &candidate_ref])?;
            if actual_main != target.expected_old_oid || actual_cand != target.candidate_oid {
                self.release_leases(&record.targets, &changeset_id)?;
                self.cleanup_candidates(&record.targets, &changeset_id);
                record.state = "aborted_cas_mismatch".into();
                write_atomic_json(&cs_file, &record)?;
                bail!("pre-commit CAS mismatch on {}; aborted before commit point", target.repo_name);
            }
        }

        // Irreversible Commit Point: all leases held, all candidates verified.
        record.state = "committing".into();
        write_atomic_json(&cs_file, &record)?;

        // Phase 3: Roll-forward pointer flips and view re-projection.
        self.complete_committing_changeset(&mut record, true)
    }

    pub fn recover_changeset(&self, changeset_id: &str) -> Result<serde_json::Value> {
        valid_id(changeset_id)?;
        let path = self.root.join("changesets").join(changeset_id).join("changeset.json");
        let bytes = read_regular(&path, MAX_JSON)?;
        let mut record: ChangesetRecord = serde_json::from_slice(&bytes)?;
        ensure!(record.schema == SCHEMA && record.changeset_id == changeset_id, "invalid changeset record");
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

    pub(crate) fn complete_committing_changeset(
        &self,
        record: &mut ChangesetRecord,
        allow_mid_failpoint: bool,
    ) -> Result<serde_json::Value> {
        for (index, target) in record.targets.iter().enumerate() {
            let repo_bare = self.repo_git_dir(&target.repo_id);
            let current_main = self.git_text(&repo_bare, &["rev-parse", "--verify", "refs/heads/main"])?;
            if current_main != target.candidate_oid {
                ensure!(
                    current_main == target.expected_old_oid,
                    "unexpected repository main OID during committing roll-forward"
                );
                self.git(
                    &repo_bare,
                    &["update-ref", "refs/heads/main", &target.candidate_oid, &target.expected_old_oid],
                )?;
            }
            let mut meta = self.read_repo(&target.repo_id)?;
            if meta.head_oid != target.candidate_oid {
                meta.head_oid = target.candidate_oid.clone();
                meta.generation += 1;
                let meta_path = self.root.join("repos").join(&meta.repo_id).join("meta.json");
                write_atomic_json(&meta_path, &meta)?;
            }
            if index == 0 && allow_mid_failpoint {
                failpoint("mid_commit_after_first_repo");
            }
        }

        // Re-project the composite view's canonical refs/heads/main to match the new source tips.
        let mut view = self.read_view(&record.view_id)?;
        let revision_id = view.revision_id.as_deref().context("task view missing revision_id")?;
        let revision = self.read_namespace_revision(revision_id)?;
        let view_bare = self.view_git_dir(&record.view_id);

        let mut mount_trees = Vec::new();
        for mount in &revision.mounts {
            let repo_bare = self.repo_git_dir(&mount.repo_id);
            let repo_main = self.git_text(&repo_bare, &["rev-parse", "--verify", "refs/heads/main"])?;
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
        self.git(&view_bare, &["update-ref", "refs/heads/main", &projected_oid])?;
        self.git(&view_bare, &["update-ref", "refs/rootyard/view-base", &projected_oid])?;
        let integrated_ref = format!("refs/rootyard/integrated/{}", record.changeset_id);
        self.git(&view_bare, &["update-ref", &integrated_ref, &projected_oid])?;
        self.git(&view_bare, &["fsck", "--full", "--strict"])?;

        view.view_base_oid = projected_oid.clone();
        view.head_oid = projected_oid.clone();
        view.view_epoch += 1;
        let view_meta_path = self.root.join("views").join(&view.view_id).join("view.json");
        write_atomic_json(&view_meta_path, &view)?;
        self.append_integrated_view_provenance(&view, &record.task_commit_oid, &new_root_tree, &record.view_base_oid)?;

        record.state = "integrated".into();
        record.projected_view_oid = Some(projected_oid);
        let changeset_path = self.root.join("changesets").join(&record.changeset_id).join("changeset.json");
        write_atomic_json(&changeset_path, record)?;

        self.release_leases(&record.targets, &record.changeset_id)?;
        Ok(serde_json::to_value(&*record)?)
    }

    pub(crate) fn release_leases(&self, targets: &[ChangesetTarget], changeset_id: &str) -> Result<()> {
        for target in targets {
            let lease_path = self.root.join("leases").join(format!("{}.json", target.repo_id));
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

    pub(crate) fn cleanup_candidates(&self, targets: &[ChangesetTarget], changeset_id: &str) {
        let candidate_ref = format!("refs/rootyard/changesets/{changeset_id}/candidate");
        for target in targets {
            let repo_bare = self.repo_git_dir(&target.repo_id);
            let _ = self.git(&repo_bare, &["update-ref", "-d", &candidate_ref]);
        }
    }
}
