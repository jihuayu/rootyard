//! Exact-object native Git view for bounded primary-origin CI fallback.
use super::Plan;
use crate::{AppState, Error, ci_pins, db, git_http, journal, mirror::sync::private_directory};
use anyhow::ensure;
use axum::http::StatusCode;
use std::{
    collections::BTreeSet,
    fs::File,
    path::{Path, PathBuf},
    process::Stdio,
};
use uuid::Uuid;

fn unavailable() -> Error {
    Error(StatusCode::CONFLICT, "CI origin source is not retained")
}
struct StagingDirectory(PathBuf);
impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if self.0.exists() { let _=std::fs::remove_dir_all(&self.0); }
    }
}
fn config(format: &str) -> String {
    let version = if format == "sha256" { 1 } else { 0 };
    let extension = if format == "sha256" {
        "[extensions]\n\tobjectFormat = sha256\n"
    } else {
        ""
    };
    format!(
        "[core]\n\trepositoryformatversion = {version}\n\tbare = true\n\thooksPath = /dev/null\n\
        {extension}[http]\n\treceivepack = false\n\tgetanyfile = false\n\
        [uploadpack]\n\tallowFilter = false\n\tallowAnySHA1InWant = false\n\
        \tallowTipSHA1InWant = false\n\tallowReachableSHA1InWant = false\n\
        [gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n"
    )
}
async fn git(
    state: &AppState,
    path: &Path,
    args: &[&str],
    limit: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut cmd = state.storage.git(&state.config);
    cmd.arg("--no-replace-objects")
        .arg("--git-dir")
        .arg(path)
        .args(args);
    git_http::collect_git_output(cmd, limit, state.config.git_timeout).await
}
fn refs(plan: &Plan) -> anyhow::Result<Vec<(String, String)>> {
    let mut values = vec![("refs/heads/main".into(), plan.target_oid.clone())];
    let mut seen = BTreeSet::new();
    for tag in &plan.dependencies.tags {
        ensure!(
            !tag.name.is_empty()
                && tag.name.len() <= 128
                && tag
                    .name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c))
                && !tag.name.contains("..")
                && !tag.name.starts_with('-')
                && !tag.name.contains("@{")
                && seen.insert(tag.name.clone())
                && ci_pins::valid_oid(&tag.object_oid),
            "invalid CI tag"
        );
        values.push((format!("refs/tags/{}", tag.name), tag.object_oid.clone()));
    }
    Ok(values)
}
async fn objects(state: &AppState, path: &Path, args: &[&str]) -> anyhow::Result<BTreeSet<String>> {
    let raw = git(state, path, args, 64 * 1024 * 1024).await?;
    let mut out = BTreeSet::new();
    for line in std::str::from_utf8(&raw)?.lines() {
        ensure!(
            ci_pins::valid_oid(line),
            "invalid CI view object enumeration"
        );
        out.insert(line.into());
    }
    ensure!(!out.is_empty(), "empty CI view");
    Ok(out)
}
async fn expected(state: &AppState, path: &Path, plan: &Plan) -> anyhow::Result<BTreeSet<String>> {
    let mut result = if plan.dependencies.history == "target" {
        objects(
            state,
            path,
            &[
                "rev-list",
                "--objects",
                "--no-object-names",
                "--max-count=1",
                &plan.target_oid,
                "--",
            ],
        )
        .await?
    } else {
        objects(
            state,
            path,
            &[
                "rev-list",
                "--objects",
                "--no-object-names",
                &plan.target_oid,
                "--",
            ],
        )
        .await?
    };
    for tag in &plan.dependencies.tags {
        result.extend(
            objects(
                state,
                path,
                &[
                    "rev-list",
                    "--objects",
                    "--no-object-names",
                    &tag.object_oid,
                    "--",
                ],
            )
            .await?,
        );
    }
    Ok(result)
}
async fn actual(state: &AppState, path: &Path) -> anyhow::Result<BTreeSet<String>> {
    objects(
        state,
        path,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
    )
    .await
}
async fn validate(state: &AppState, path: &Path, plan: &Plan, source: &Path) -> anyhow::Result<()> {
    journal::safe_path(path)?;
    ensure!(
        path.is_dir() && path.canonicalize()? == path,
        "invalid CI origin view directory"
    );
    for forbidden in [
        "info/grafts",
        "objects/info/alternates",
        "objects/info/http-alternates",
        "refs/replace",
    ] {
        ensure!(
            !journal::exists(&path.join(forbidden))?,
            "unsupported CI origin view topology"
        );
    }
    ensure!(
        journal::read(&path.join("config"))? == config(&plan.object_format).as_bytes(),
        "CI origin view config changed"
    );
    ensure!(
        journal::read(&path.join("HEAD"))? == b"ref: refs/heads/main\n",
        "CI origin view HEAD changed"
    );
    if plan.dependencies.history == "target" {
        ensure!(
            journal::read(&path.join("shallow"))? == format!("{}\n", plan.target_oid).as_bytes(),
            "CI origin shallow boundary changed"
        );
    } else {
        ensure!(
            !journal::exists(&path.join("shallow"))?,
            "unexpected CI origin shallow boundary"
        );
    }
    for (name, oid) in refs(plan)? {
        ensure!(
            git(state, path, &["rev-parse", "--verify", &name], 128).await?
                == format!("{oid}\n").as_bytes(),
            "CI origin view ref differs"
        );
    }
    let actual_refs = git(
        state,
        path,
        &["for-each-ref", "--format=%(refname) %(objectname)"],
        8192,
    )
    .await?;
    let mut allowed = refs(plan)?
        .into_iter()
        .map(|(name, oid)| format!("{name} {oid}"))
        .collect::<Vec<_>>();
    allowed.sort();
    let mut found = std::str::from_utf8(&actual_refs)?
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    found.sort();
    ensure!(found == allowed, "CI origin view has undeclared refs");
    let mut entries = BTreeSet::new();
    let mut directories = vec![path.to_path_buf()];
    while let Some(dir) = directories.pop() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let item = entry.path();
            ensure!(entries.len() < 256, "CI origin view too many entries");
            let meta = std::fs::symlink_metadata(&item)?;
            ensure!(!meta.file_type().is_symlink(), "CI origin view symlink");
            ensure!(
                meta.is_dir() || meta.is_file(),
                "CI origin view special file"
            );
            let rel = item.strip_prefix(path)?.to_string_lossy().into_owned();
            entries.insert(rel);
            if meta.is_dir() {
                directories.push(item);
            }
        }
    }
    let mut allowed_entries = BTreeSet::from([
        "HEAD".to_owned(),
        "config".to_owned(),
        "objects".to_owned(),
        "objects/pack".to_owned(),
        "objects/info".to_owned(),
        "refs".to_owned(),
        "refs/heads".to_owned(),
        "refs/heads/main".to_owned(),
        "refs/tags".to_owned(),
    ]);
    if plan.dependencies.history == "target" {
        allowed_entries.insert("shallow".into());
    }
    for (name, _) in refs(plan)? {
        let mut parent = Path::new(&name).parent();
        while let Some(dir) = parent {
            allowed_entries.insert(dir.to_string_lossy().into_owned());
            parent = dir.parent();
        }
        allowed_entries.insert(name);
    }
    for rel in entries {
        if rel.starts_with("objects/pack/pack-")
            && (rel.ends_with(".pack") || rel.ends_with(".idx"))
        {
            continue;
        }
        ensure!(
            allowed_entries.contains(&rel),
            "CI origin view has undeclared file"
        );
    }
    ensure!(
        git(state, path, &["rev-parse", "--show-object-format"], 128).await?
            == format!("{}\n", plan.object_format).as_bytes(),
        "CI origin object format changed"
    );
    ensure!(
        git(state, path, &["cat-file", "-t", &plan.target_oid], 128).await? == b"commit\n",
        "CI origin target is not a commit"
    );
    git(
        state,
        path,
        &[
            "fsck",
            "--full",
            "--strict",
            "--no-reflogs",
            "--no-dangling",
        ],
        64 * 1024,
    )
    .await?;
    ensure!(
        expected(state, source, plan).await? == actual(state, path).await?,
        "CI origin view contains missing or extra objects"
    );
    Ok(())
}

/// Called only after a job token has passed live, exact-target authority.
/// The view contains solely the declared commit ancestry and tag closures.
pub(crate) async fn origin_job_path(
    state: &AppState,
    repo: &db::Repository,
    plan: &Plan,
    lease: &crate::storage::read_leases::Lease,
) -> Result<PathBuf, Error> {
    // The lease owner lives in Git HTTP for the entire response. Guard every
    // native source read, including receipt verification and pack construction;
    // a stalled PostgreSQL heartbeat cancels the Git future before GC proceeds.
    lease.guard(origin_job_path_inner(state,repo,plan)).await?
}

async fn origin_job_path_inner(
    state: &AppState,
    repo: &db::Repository,
    plan: &Plan,
) -> Result<PathBuf, Error> {
    if state.mirror_primary.is_some()
        || repo.id != plan.repository_id
        || repo.storage_generation != plan.storage_generation
        || !matches!(plan.dependencies.history.as_str(), "full" | "target")
        || plan.target_oid.len() != if plan.object_format == "sha1" { 40 } else { 64 }
    {
        return Err(Error::unauthorized());
    }
    let root = state.storage.root.join("ci-origin-views");
    let directory = root.join(repo.id.to_string());
    let destination = directory.join(format!("{}-{}.git", repo.storage_generation, plan.job_id));
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    super::dependencies::verify_on_origin(state, plan).await?;
    let source = state
        .storage
        .verify_path(repo.id)
        .map_err(Error::internal)?;
    let intent = ci_pins::Intent {
        version: 1,
        job_id: plan.job_id,
        owner_id: plan.owner_id,
        repository_id: repo.id,
        storage_generation: repo.storage_generation,
        object_format: plan.object_format.clone(),
        target_oid: plan.target_oid.clone(),
        retention_ref: format!("refs/rootyard-ci/jobs/{}", plan.job_id),
    };
    let receipt = ci_pins::verify_receipt(state, &intent)
        .await
        .map_err(|_| unavailable())?;
    if receipt != plan.source_receipt_sha256 {
        return Err(unavailable());
    }
    if destination.exists() {
        validate(state, &destination, plan, &source)
            .await
            .map_err(Error::internal)?;
        return Ok(destination);
    }
    private_directory(&root).map_err(Error::internal)?;
    private_directory(&directory).map_err(Error::internal)?;
    let stage = directory.join(format!(".{}.staging", Uuid::new_v4()));
    let _cleanup=StagingDirectory(stage.clone());
    let view = stage.join("view.git");
    let result = async {
        private_directory(&stage)?;
        private_directory(&view)?;
        for part in [
            "objects",
            "objects/pack",
            "objects/info",
            "refs",
            "refs/heads",
            "refs/tags",
        ] {
            private_directory(&view.join(part))?;
        }
        std::fs::write(view.join("config"), config(&plan.object_format))?;
        std::fs::write(view.join("HEAD"), b"ref: refs/heads/main\n")?;
        for (name, oid) in refs(plan)? {
            let path = view.join(&name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, format!("{oid}\n"))?;
        }
        if plan.dependencies.history == "target" {
            std::fs::write(view.join("shallow"), format!("{}\n", plan.target_oid))?;
        }
        let wanted = expected(state, &source, plan).await?;
        let mut revisions = String::new();
        for oid in &wanted {
            revisions.push_str(oid);
            revisions.push('\n');
        }
        let input = stage.join("revisions");
        std::fs::write(&input, revisions)?;
        let mut cmd = state.storage.git(&state.config);
        cmd.arg("--no-replace-objects")
            .arg("--git-dir")
            .arg(&source)
            .args([
                "-c",
                "pack.writeReverseIndex=false",
                "pack-objects",
                "--no-reuse-delta",
                "--no-reuse-object",
            ])
            .arg(view.join("objects/pack/pack"));
        let output = git_http::collect_git_output_input(
            cmd,
            128,
            state.config.git_timeout,
            Stdio::from(File::open(input)?),
        )
        .await?;
        ensure!(
            ci_pins::valid_oid(std::str::from_utf8(&output)?.trim()),
            "CI origin pack identity invalid"
        );
        validate(state, &view, plan, &source).await?;
        ensure!(
            crate::storage::disk_bytes(&stage, state.config.max_repo_bytes)?
                < state.config.max_repo_bytes,
            "CI origin view exceeds quota"
        );
        let view_for_sync = view.clone();
        tokio::task::spawn_blocking(move || crate::storage::sync_tree(&view_for_sync)).await??;
        std::fs::rename(&view, &destination)?;
        File::open(&directory)?.sync_all()?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    result.map_err(Error::internal)?;
    Ok(destination)
}
