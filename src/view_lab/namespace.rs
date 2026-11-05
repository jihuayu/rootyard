//! Repository registration, namespace revision manifests, mount validation, and provenance verification.

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    os::unix::ffi::OsStringExt,
    path::{Component, Path, PathBuf},
};

use super::models::*;

pub fn compute_provenance_signature(
    vid: &str,
    strat: &str,
    ep: u64,
    src: &str,
    tree: &str,
    parents: &[String],
) -> String {
    let mut key = [0u8; 64];
    key[..PROVENANCE_SECRET.len()].copy_from_slice(PROVENANCE_SECRET);
    let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();
    let p_str = parents.join(",");
    let msg = format!("rootyard-view-sig-v1\0{vid}\0{strat}\0{ep}\0{src}\0{tree}\0{p_str}");
    let inner = Sha256::new()
        .chain_update(&ipad)
        .chain_update(msg)
        .finalize();
    let mac = Sha256::new()
        .chain_update(&opad)
        .chain_update(inner)
        .finalize();
    format!("hmac-sha256:{PROVENANCE_KEY_ID}:{}", hex::encode(mac))
}

pub(crate) fn make_provenance_record(
    ctx: (&str, &str, u64),
    oids: (&str, &str, &str),
    parents: Vec<String>,
    sig_info: (bool, String),
) -> ProvenanceCommitRecord {
    let sig = compute_provenance_signature(ctx.0, ctx.1, ctx.2, oids.1, oids.2, &parents);
    ProvenanceCommitRecord {
        projected_commit_oid: oids.0.to_owned(),
        source_commit_oid: oids.1.to_owned(),
        view_epoch: ctx.2,
        projected_tree_oid: oids.2.to_owned(),
        projected_parent_oids: parents,
        source_signed: sig_info.0,
        source_signature_type: sig_info.1,
        original_signature_covers_projected_oid: false,
        platform_signature: sig,
    }
}

impl Store {
    pub fn list_repos(&self) -> Result<Vec<RepoMeta>> {
        let mut repos = Vec::new();
        for entry in fs::read_dir(self.root.join("repos"))? {
            let bytes = read_regular(&entry?.path().join("meta.json"), MAX_JSON)?;
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
        let path = self.root.join("repos").join(repo_id).join("meta.json");
        let meta: RepoMeta = serde_json::from_slice(&read_regular(&path, MAX_JSON)?)?;
        let ok = meta.schema == SCHEMA && meta.repo_id == repo_id;
        ensure!(ok, "invalid repository metadata");
        Ok(meta)
    }

    pub fn register_repo(&self, name: &str, source: &Path) -> Result<serde_json::Value> {
        ensure!(valid_name(name), "invalid repository name");
        self.ensure_not_overlapping(source)?;
        let taken = self.list_repos()?.iter().any(|r| r.name == name);
        ensure!(!taken, "repository name already registered");
        let fmt = self.git_text(source, &["rev-parse", "--show-object-format"])?;
        ensure!(fmt == "sha1", "only SHA-1 repositories are supported");
        let head_oid = self.git_text(source, &["rev-parse", "--verify", "HEAD^{commit}"])?;
        valid_oid(&head_oid)?;

        let repo_id = new_id();
        let staging = self.stage()?;
        let bare = staging.0.join("repo.git");
        private_dir(&bare)?;
        self.git(&bare, &["init", "--bare", "--initial-branch=main"])?;
        let src_str = source.to_str().context("source path must be UTF-8")?;
        let spec = format!("{head_oid}:refs/heads/main");
        self.git(&bare, &["fetch", "--no-tags", src_str, &spec])?;
        self.git(&bare, &["fsck", "--full", "--strict"])?;

        let meta = RepoMeta {
            schema: SCHEMA,
            repo_id: repo_id.clone(),
            name: name.to_owned(),
            head_oid: head_oid.clone(),
            generation: 1,
        };
        let meta_bytes = serde_json::to_vec_pretty(&meta)?;
        write_new(&staging.0.join("meta.json"), &meta_bytes, 0o600)?;
        sync_tree(&staging.0)?;
        let dest = self.root.join("repos").join(&repo_id);
        publish(&staging.0, &dest)?;
        Ok(serde_json::json!({
            "repo_id": repo_id,
            "name": name,
            "head_oid": head_oid,
            "generation": 1,
            "repo_path": dest.join("repo.git").to_string_lossy(),
        }))
    }

    pub fn advance_repo(&self, name: &str, source: &Path) -> Result<serde_json::Value> {
        self.ensure_not_overlapping(source)?;
        let mut meta = self.find_repo_by_name(name)?;
        self.ensure_no_active_lease(&meta.repo_id)?;
        let bare = self.repo_git_dir(&meta.repo_id);
        let cur_oid = self.git_text(&bare, &["rev-parse", "--verify", "refs/heads/main"])?;
        ensure!(cur_oid == meta.head_oid, "repository HEAD diverged");
        let new_oid = self.git_text(source, &["rev-parse", "--verify", "HEAD^{commit}"])?;
        valid_oid(&new_oid)?;
        ensure!(
            new_oid != cur_oid,
            "repository HEAD is already at target OID"
        );

        let src_str = source.to_str().context("source path must be UTF-8")?;
        let stg_ref = format!("refs/rootyard/advance/{}", new_id());
        let spec = format!("{new_oid}:{stg_ref}");
        self.git(&bare, &["fetch", "--no-tags", src_str, &spec])?;
        let anc = ["merge-base", "--is-ancestor", &cur_oid, &new_oid];
        let is_anc = self
            .git_output_with_env(&bare, &anc, &[], None)?
            .status
            .success();
        if !is_anc {
            let _ = self.git(&bare, &["update-ref", "-d", &stg_ref]);
            bail!("non-fast-forward advance rejected");
        }
        self.git(&bare, &["fsck", "--full", "--strict"])?;
        let ref_args = ["update-ref", "refs/heads/main", &new_oid, &cur_oid];
        self.git(&bare, &ref_args)?;
        let _ = self.git(&bare, &["update-ref", "-d", &stg_ref]);

        let old_oid = meta.head_oid;
        meta.head_oid = new_oid.clone();
        meta.generation += 1;
        let rdir = self.root.join("repos").join(&meta.repo_id);
        write_atomic_json(&rdir.join("meta.json"), &meta)?;
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
            let fresh = seen_repos.insert(repo.repo_id.clone());
            ensure!(fresh, "duplicate repository in namespace mounts");
            let bare = self.repo_git_dir(&repo.repo_id);
            let obj_t = self.git_text(&bare, &["cat-file", "-t", base_oid])?;
            ensure!(obj_t == "commit", "base OID {base_oid} is not a commit");
            parsed_mounts.push(MountEntry {
                mount_path,
                repo_id: repo.repo_id,
                repo_name: repo.name,
                base_oid: base_oid.to_owned(),
            });
        }
        parsed_mounts.sort_by(|a, b| a.mount_path.cmp(&b.mount_path));
        validate_non_overlapping_mounts(&parsed_mounts)?;

        let mut max_rev = 0_u64;
        for entry in fs::read_dir(self.root.join("namespaces"))? {
            let bytes = read_regular(&entry?.path().join("manifest.json"), MAX_JSON)?;
            let rev: NamespaceRevision = serde_json::from_slice(&bytes)?;
            if rev.namespace == namespace && rev.revision_number > max_rev {
                max_rev = rev.revision_number;
            }
        }
        let revision_id = new_id();
        let revision_number = max_rev + 1;

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
        publish(&staging.0, &self.root.join("namespaces").join(&revision_id))?;
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
        let expected = hex::encode(Sha256::digest(&bytes));
        ensure!(
            digest == expected.as_bytes(),
            "namespace revision checksum mismatch"
        );
        let rev: NamespaceRevision = serde_json::from_slice(&bytes)?;
        let valid = rev.schema == SCHEMA && rev.revision_id == revision_id;
        ensure!(valid, "invalid namespace revision manifest");
        validate_non_overlapping_mounts(&rev.mounts)?;
        Ok(rev)
    }

    pub(crate) fn inspect_source_signature(&self, bare: &Path, c: &str) -> Result<(bool, String)> {
        let raw = self.git(bare, &["cat-file", "commit", c])?;
        let text = String::from_utf8_lossy(&raw);
        let hdrs = text.split("\n\n").next().unwrap_or("");
        let signed = hdrs
            .lines()
            .any(|l| l.starts_with("gpgsig ") || l.starts_with("gpgsig-sha256 "));
        if !signed {
            return Ok((false, "none".into()));
        }
        let kind = if hdrs.contains("-----BEGIN SSH SIGNATURE-----") {
            "ssh"
        } else {
            "gpg"
        };
        Ok((true, kind.into()))
    }

    pub(crate) fn write_view_provenance(
        &self,
        dir: &Path,
        meta: &ViewMeta,
        commits: Vec<ProvenanceCommitRecord>,
        epochs: BTreeMap<String, BTreeMap<String, String>>,
    ) -> Result<()> {
        let manifest = ViewProvenanceManifest {
            schema: SCHEMA,
            view_id: meta.view_id.clone(),
            strategy: meta.strategy.clone(),
            key_id: PROVENANCE_KEY_ID.into(),
            view_epoch: meta.view_epoch,
            commits,
        };
        let epoch_map = EpochCommitMap {
            schema: SCHEMA,
            view_id: meta.view_id.clone(),
            view_epoch: meta.view_epoch,
            epochs,
        };
        write_atomic_json(&dir.join("provenance.json"), &manifest)?;
        write_atomic_json(&dir.join("epoch_commit_map.json"), &epoch_map)
    }

    pub(crate) fn append_integrated_view_provenance(
        &self,
        meta: &ViewMeta,
        src: &str,
        tree: &str,
        parent: &str,
    ) -> Result<()> {
        let dir = self.root.join("views").join(&meta.view_id);
        let p_bytes = read_regular(&dir.join("provenance.json"), MAX_JSON)?;
        let mut man: ViewProvenanceManifest = serde_json::from_slice(&p_bytes)?;
        let e_bytes = read_regular(&dir.join("epoch_commit_map.json"), MAX_JSON)?;
        let mut emap: EpochCommitMap = serde_json::from_slice(&e_bytes)?;
        if !man
            .commits
            .iter()
            .any(|c| c.projected_commit_oid == meta.head_oid)
        {
            let ctx = (
                meta.view_id.as_str(),
                meta.strategy.as_str(),
                meta.view_epoch,
            );
            let oids = (meta.head_oid.as_str(), src, tree);
            let rec =
                make_provenance_record(ctx, oids, vec![parent.to_owned()], (false, "none".into()));
            man.commits.push(rec);
        }
        let ep_entry = BTreeMap::from([(src.to_owned(), meta.head_oid.clone())]);
        emap.epochs.insert(meta.view_epoch.to_string(), ep_entry);
        self.write_view_provenance(&dir, meta, man.commits, emap.epochs)
    }

    pub fn verify_view(&self, view_id: &str) -> Result<serde_json::Value> {
        let meta = self.read_view(view_id)?;
        let view_dir = self.root.join("views").join(view_id);
        let bare = self.view_git_dir(view_id);
        self.git(&bare, &["fsck", "--full", "--strict"])?;
        let p_bytes = read_regular(&view_dir.join("provenance.json"), MAX_JSON)?;
        let man: ViewProvenanceManifest = serde_json::from_slice(&p_bytes)?;
        let ok_man = man.schema == SCHEMA && man.view_id == view_id;
        ensure!(ok_man, "invalid provenance manifest");
        let main_oid = self.git_text(&bare, &["rev-parse", "--verify", "refs/heads/main"])?;
        let rev_args = ["rev-list", "--topo-order", "--reverse", "refs/heads/main"];
        let rev_out = self.git_text(&bare, &rev_args)?;
        let reachable: Vec<&str> = rev_out
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let by_oid: BTreeMap<&str, &ProvenanceCommitRecord> = man
            .commits
            .iter()
            .map(|r| (r.projected_commit_oid.as_str(), r))
            .collect();
        let (mut tampered, mut verified) = (Vec::new(), 0usize);
        if main_oid != meta.head_oid
            || man.view_epoch != meta.view_epoch
            || man.strategy != meta.strategy
            || man.key_id != PROVENANCE_KEY_ID
        {
            tampered.push(main_oid.clone());
        }
        for &oid in &reachable {
            let t_spec = format!("{oid}^{{tree}}");
            let tree = self.git_text(&bare, &["rev-parse", "--verify", &t_spec])?;
            let p_line = self.git_text(&bare, &["rev-list", "--parents", "-n", "1", oid])?;
            let parents: Vec<String> = p_line
                .split_whitespace()
                .skip(1)
                .map(str::to_owned)
                .collect();
            let raw_bytes = self.git(&bare, &["cat-file", "commit", oid])?;
            let raw = String::from_utf8_lossy(&raw_bytes);
            let tr_sig = raw
                .lines()
                .find_map(|l| l.strip_prefix("Rootyard-View-Signature: "));
            let ok = by_oid.get(oid).is_some_and(|rec| {
                let (vid, st, src) = (&meta.view_id, &meta.strategy, &rec.source_commit_oid);
                let exp =
                    compute_provenance_signature(vid, st, rec.view_epoch, src, &tree, &parents);
                (1..=meta.view_epoch).contains(&rec.view_epoch)
                    && rec.projected_tree_oid == tree
                    && rec.projected_parent_oids == parents
                    && !rec.original_signature_covers_projected_oid
                    && rec.platform_signature == exp
                    && tr_sig.is_none_or(|t| t == exp)
            });
            if ok {
                verified += 1;
            } else if !tampered.contains(&oid.to_owned()) {
                tampered.push(oid.to_owned());
            }
        }
        for rec in &man.commits {
            let p_oid = &rec.projected_commit_oid;
            if !reachable.contains(&p_oid.as_str()) && !tampered.contains(p_oid) {
                tampered.push(p_oid.clone());
            }
        }
        let report = serde_json::json!({
            "view_id": view_id,
            "strategy": meta.strategy,
            "view_epoch": meta.view_epoch,
            "signature_verified": tampered.is_empty(),
            "source_signed_commits": man.commits.iter().filter(|r| r.source_signed).count(),
            "verified_projected_commits": verified,
            "tampered_commits": tampered,
        });
        if !tampered.is_empty() {
            println!("{}", serde_json::to_string(&report)?);
            bail!("view provenance verification failed for {view_id}: tampered {tampered:?}");
        }
        Ok(report)
    }
}

pub fn normalize_mount_path(raw: &str) -> Result<String> {
    let b = raw.as_bytes();
    let ok = !b.is_empty() && !b.contains(&0) && !b.starts_with(b"/") && !b.ends_with(b"/");
    ensure!(
        ok,
        "mount path must be a non-empty relative path without leading or trailing slash"
    );
    for part in raw.split('/') {
        let valid = !part.is_empty() && part != "." && part != ".." && part != ".git";
        ensure!(valid, "unsafe mount path component");
    }
    let path = PathBuf::from(OsString::from_vec(b.to_vec()));
    let normal = path.components().all(|c| matches!(c, Component::Normal(_)));
    ensure!(normal, "unsafe mount path");
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
            let (lp, rp) = (&left.mount_path, &right.mount_path);
            let overlap = path_within_mount(lp, rp) || path_within_mount(rp, lp);
            ensure!(!overlap, "overlapping namespace mounts {lp} and {rp}");
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
            "", "/a", "a/", "a//b", "a/../b", "a/./b", ".git", "a/.git/b",
        ] {
            assert!(normalize_mount_path(bad).is_err(), "{bad}");
        }
        let mk = |p: &str, n: &str, c: &str| MountEntry {
            mount_path: p.into(),
            repo_id: new_id(),
            repo_name: n.into(),
            base_oid: c.repeat(40),
        };
        let a = mk("libs/proto", "p1", "a");
        let b = mk("libs/proto/v2", "p2", "b");
        let c = mk("libs/proto-ext", "p3", "c");
        assert!(validate_non_overlapping_mounts(&[a.clone(), b]).is_err());
        assert!(validate_non_overlapping_mounts(&[a, c]).is_ok());
    }
}
