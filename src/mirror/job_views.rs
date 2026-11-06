//! Immutable exact-plan Git job views on CI read mirrors.
use crate::{
    AppState, Error,
    ci_checkouts::Plan,
    db, git_http,
    mirror::{
        eviction, limiter,
        sync::{bare_config, mirror_git, private_directory, read_regular, verify_directory},
        views::pinned_path,
    },
};
use anyhow::{Context, Result};
use std::{
    fs::File,
    path::{Path as FsPath, PathBuf},
};
use uuid::Uuid;

pub(crate) async fn job_path(
    state: &AppState,
    repo: &db::Repository,
    plan: &Plan,
) -> Result<PathBuf, Error> {
    let oid = &plan.target_oid;
    if plan.repository_id != repo.id
        || plan.storage_generation != repo.storage_generation
        || !matches!(plan.dependencies.history.as_str(), "full" | "target")
    {
        return Err(Error::unauthorized());
    }
    let root = state.storage.root.join("repos").join(repo.id.to_string());
    let views = root.join("job-views");
    let destination = if plan.dependencies.history == "full" && plan.dependencies.tags.is_empty() {
        views.join(format!("{}-{oid}.git", repo.storage_generation))
    } else {
        views.join(format!(
            "{}-{oid}-{}.git",
            repo.storage_generation, plan.job_id
        ))
    };
    if destination.try_exists().map_err(Error::internal)? {
        validate_job_view(state, &destination, plan)
            .await
            .map_err(Error::internal)?;
        eviction::touch_path(&destination.join("HEAD"));
        return Ok(destination);
    }
    // Establish the existing immutable snapshot selection before taking the
    // shared repository preparation lock (pinned_path takes that same lock).
    let source = pinned_path(state, repo, oid).await?;
    let _closure_permit = limiter::for_state(state).try_acquire_closure(state)?;
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    if destination.try_exists().map_err(Error::internal)? {
        validate_job_view(state, &destination, plan)
            .await
            .map_err(Error::internal)?;
        eviction::touch_path(&destination.join("HEAD"));
        return Ok(destination);
    }
    // A retained target pin can predate a declared tag. Prefer the current
    // immutable snapshot when it contains the entire plan, then fall back to
    // the retained pin for plans that need only the older target closure.
    let current = read_regular(&root.join("current.json"), 4096)
        .ok()
        .and_then(|raw| serde_json::from_slice::<crate::mirror::Snapshot>(&raw).ok())
        .filter(|snapshot| {
            snapshot.repository_id == repo.id
                && snapshot.storage_generation == repo.storage_generation
        })
        .map(|snapshot| {
            root.join(snapshot.snapshot.to_string())
                .join("repository.git")
        });
    let source = if let Some(candidate) = current {
        if verify_directory(&candidate).is_ok()
            && planned_objects(state, &candidate, plan).await.is_ok()
        {
            candidate
        } else {
            source
        }
    } else {
        source
    };
    let bare = if source
        .file_name()
        .is_some_and(|name| name == "repository.git")
    {
        source.clone()
    } else {
        source
            .parent()
            .and_then(FsPath::parent)
            .ok_or_else(Error::bad_request)?
            .join("repository.git")
    };
    let stage = views.join(format!(".{}.staging", Uuid::new_v4()));
    let result = async {
        verify_directory(&root)?;
        private_directory(&views)?;
        // Never allow a source graft/shallow/promisor/alternate to silently
        // shorten history or fetch an undeclared external dependency.
        for forbidden in [
            "shallow",
            "info/grafts",
            "objects/info/alternates",
            "objects/info/http-alternates",
        ] {
            anyhow::ensure!(
                !crate::journal::exists(&bare.join(forbidden))?,
                "unsupported source topology"
            );
        }
        anyhow::ensure!(
            read_regular(&bare.join("config"), 4096)? == bare_config().as_bytes(),
            "snapshot configuration changed"
        );
        for entry in std::fs::read_dir(bare.join("objects/pack"))? {
            anyhow::ensure!(
                !entry?.file_name().to_string_lossy().ends_with(".promisor"),
                "promisor source unsupported"
            );
        }
        let expected = planned_objects(state, &source, plan).await?;
        private_directory(&stage)?;
        let view = stage.join("view.git");
        private_directory(&view)?;
        for dir in [
            "objects",
            "objects/pack",
            "objects/info",
            "refs",
            "refs/heads",
            "refs/tags",
        ] {
            private_directory(&view.join(dir))?;
        }
        std::fs::write(view.join("HEAD"), b"ref: refs/heads/main\n")?;
        std::fs::write(view.join("refs/heads/main"), format!("{oid}\n"))?;
        for (name, tag_oid) in tag_refs(plan)? {
            let path = view.join(&name);
            std::fs::create_dir_all(path.parent().context("tag parent")?)?;
            std::fs::write(path, format!("{tag_oid}\n"))?;
        }
        if plan.dependencies.history == "target" {
            std::fs::write(view.join("shallow"), format!("{oid}\n"))?;
        }
        std::fs::write(view.join("config"), bare_config())?;
        let input = stage.join("revisions");
        let mut lines = String::new();
        for object in &expected {
            lines.push_str(object);
            lines.push('\n');
        }
        std::fs::write(&input, lines)?;
        let mut cmd = mirror_git(state);
        cmd.arg("--git-dir")
            .arg(&source)
            .args(["-c", "pack.writeReverseIndex=false"])
            .args(["pack-objects", "--no-reuse-delta", "--no-reuse-object"])
            .arg(view.join("objects/pack/pack"));
        git_http::collect_git_output_input(
            cmd,
            128,
            state.config.git_timeout,
            File::open(input)?.into(),
        )
        .await?;
        validate_job_view(state, &view, plan).await?;
        anyhow::ensure!(
            all_objects(state, &view).await? == expected,
            "materialized target object set differs"
        );
        anyhow::ensure!(
            crate::storage::disk_bytes(&stage, state.config.max_repo_bytes)?
                < state.config.max_repo_bytes,
            "job view exceeds quota"
        );
        let to_sync = view.clone();
        tokio::task::spawn_blocking(move || crate::storage::sync_tree(&to_sync)).await??;
        std::fs::rename(&view, &destination)?;
        File::open(&views)?.sync_all()?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    // Only this unpublished staging directory, never retained objects.
    if stage.exists() {
        let _ = std::fs::remove_dir_all(stage);
    }
    result.map_err(Error::internal)?;
    eviction::enforce_watermark_locked(state, repo).await;
    Ok(destination)
}

fn tag_refs(plan: &Plan) -> Result<Vec<(String, String)>> {
    let mut result = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for tag in &plan.dependencies.tags {
        anyhow::ensure!(
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
                && crate::ci_pins::valid_oid(&tag.object_oid),
            "unsafe CI tag"
        );
        result.push((format!("refs/tags/{}", tag.name), tag.object_oid.clone()));
    }
    Ok(result)
}

async fn planned_objects(
    state: &AppState,
    path: &FsPath,
    plan: &Plan,
) -> Result<std::collections::BTreeSet<String>> {
    let mut result = if plan.dependencies.history == "target" {
        object_set(
            object_command(
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
            .await?,
        )?
    } else {
        closure_objects(state, path, &plan.target_oid).await?
    };
    for tag in &plan.dependencies.tags {
        result.extend(closure_objects(state, path, &tag.object_oid).await?);
    }
    Ok(result)
}

async fn object_command(state: &AppState, path: &FsPath, args: &[&str]) -> Result<Vec<u8>> {
    let mut cmd = mirror_git(state);
    cmd.arg("--git-dir").arg(path).args(args);
    git_http::collect_git_output(cmd, 64 * 1024 * 1024, state.config.git_timeout).await
}

fn object_set(bytes: Vec<u8>) -> Result<std::collections::BTreeSet<String>> {
    let mut result = std::collections::BTreeSet::new();
    for oid in std::str::from_utf8(&bytes)?.lines() {
        anyhow::ensure!(crate::ci_pins::valid_oid(oid), "invalid object enumeration");
        result.insert(oid.to_owned());
    }
    anyhow::ensure!(!result.is_empty(), "empty object closure");
    Ok(result)
}

async fn closure_objects(
    state: &AppState,
    path: &FsPath,
    oid: &str,
) -> Result<std::collections::BTreeSet<String>> {
    object_set(
        object_command(
            state,
            path,
            &["rev-list", "--objects", "--no-object-names", oid, "--"],
        )
        .await?,
    )
}

async fn all_objects(
    state: &AppState,
    path: &FsPath,
) -> Result<std::collections::BTreeSet<String>> {
    object_set(
        object_command(
            state,
            path,
            &[
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname)",
            ],
        )
        .await?,
    )
}

async fn validate_job_view(state: &AppState, path: &FsPath, plan: &Plan) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let oid = &plan.target_oid;
    // Closed filesystem grammar: no symlinks, extra refs, loose objects, grafts,
    // shallow/promisor metadata, alternates, hooks, URL routes or config extras.
    verify_directory(path)?;
    let mut directories = std::collections::BTreeSet::from([
        "objects".to_owned(),
        "objects/pack".to_owned(),
        "objects/info".to_owned(),
        "refs".to_owned(),
        "refs/heads".to_owned(),
        "refs/tags".to_owned(),
    ]);
    let mut files = std::collections::BTreeSet::from([
        "HEAD".to_owned(),
        "config".to_owned(),
        "refs/heads/main".to_owned(),
    ]);
    if plan.dependencies.history == "target" {
        files.insert("shallow".into());
    }
    for (name, _) in tag_refs(plan)? {
        let mut parent = FsPath::new(&name).parent();
        while let Some(dir) = parent {
            directories.insert(dir.to_string_lossy().into_owned());
            parent = dir.parent();
        }
        files.insert(name);
    }
    let mut stack = vec![path.to_path_buf()];
    let mut packs = std::collections::BTreeSet::new();
    let mut indexes = std::collections::BTreeSet::new();
    let mut count = 0;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir)? {
            count += 1;
            anyhow::ensure!(count <= 256, "unexpected job view entries");
            let entry = entry?;
            let p = entry.path();
            let meta = std::fs::symlink_metadata(&p)?;
            let relative = p
                .strip_prefix(path)?
                .to_str()
                .context("invalid job view path")?;
            if meta.is_dir() {
                anyhow::ensure!(
                    directories.contains(relative),
                    "unexpected job view directory"
                );
                verify_directory(&p)?;
                stack.push(p);
            } else {
                anyhow::ensure!(
                    meta.is_file() && meta.nlink() == 1,
                    "non-private job view file"
                );
                if files.contains(relative) {
                    continue;
                }
                let suffix = relative
                    .strip_prefix("objects/pack/pack-")
                    .context("unexpected job view file")?;
                let (hash, extension) = suffix.split_once('.').context("invalid job view pack")?;
                anyhow::ensure!(crate::ci_pins::valid_oid(hash), "invalid job pack identity");
                match extension {
                    "pack" => {
                        packs.insert(hash.to_owned());
                    }
                    "idx" => {
                        indexes.insert(hash.to_owned());
                    }
                    _ => anyhow::bail!("unexpected job pack metadata"),
                }
            }
        }
    }
    anyhow::ensure!(
        packs.len() == 1 && packs == indexes,
        "job pack pair differs"
    );
    for dir in directories {
        verify_directory(&path.join(dir))?;
    }
    anyhow::ensure!(
        read_regular(&path.join("config"), 4096)? == bare_config().as_bytes()
            && read_regular(&path.join("HEAD"), 64)? == b"ref: refs/heads/main\n"
            && read_regular(&path.join("refs/heads/main"), 64)? == format!("{oid}\n").as_bytes(),
        "job identity changed"
    );
    if plan.dependencies.history == "target" {
        anyhow::ensure!(
            read_regular(&path.join("shallow"), 64)? == format!("{oid}\n").as_bytes(),
            "job shallow boundary changed"
        );
    }
    let mut wanted = vec![format!("refs/heads/main {oid}")];
    for (name, tag_oid) in tag_refs(plan)? {
        anyhow::ensure!(
            read_regular(&path.join(&name), 128)? == format!("{tag_oid}\n").as_bytes(),
            "job tag ref changed"
        );
        wanted.push(format!("{name} {tag_oid}"));
    }
    wanted.sort();
    let mut found = std::str::from_utf8(
        &object_command(
            state,
            path,
            &["for-each-ref", "--format=%(refname) %(objectname)"],
        )
        .await?,
    )?
    .lines()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    found.sort();
    anyhow::ensure!(found == wanted, "job view has undeclared refs");
    anyhow::ensure!(
        object_command(state, path, &["rev-parse", "--show-object-format"]).await?
            == format!("{}\n", plan.object_format).as_bytes(),
        "job object format changed"
    );
    anyhow::ensure!(
        object_command(state, path, &["cat-file", "-t", oid]).await? == b"commit\n",
        "job target must be a commit"
    );
    object_command(state, path, &["fsck", "--full", "--strict", "--no-reflogs"]).await?;
    anyhow::ensure!(
        planned_objects(state, path, plan).await? == all_objects(state, path).await?,
        "job view contains unrelated objects"
    );
    Ok(())
}
