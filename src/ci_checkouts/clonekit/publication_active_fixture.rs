//! `cfg(test)`-only real-Git fixture for distinct valid Active CloneKit candidates.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Result, ensure};
use tempfile::TempDir;
use uuid::Uuid;

use crate::ci_checkouts::clonekit::{
    BuildCloneKitRequest, BuiltCloneKitArtifacts, CloneKitObjectFormat, build_clonekit_from_git,
};

pub(super) fn git_binary() -> PathBuf {
    PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".into()))
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let mut command = Command::new(git_binary());
    command.env("GIT_TERMINAL_PROMPT", "0").current_dir(dir);
    let output = command.args(args).output()?;
    ensure!(output.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&output.stderr));
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn init_repo(parent: &Path, name: &str) -> Result<PathBuf> {
    let dir = parent.join(name);
    fs::create_dir_all(&dir)?;
    for args in [
        &["init", "--quiet", "--object-format=sha1"][..],
        &["symbolic-ref", "HEAD", "refs/heads/main"],
        &["config", "user.name", "clonekit-fixture"],
        &["config", "user.email", "clonekit-fixture@test.invalid"],
    ] {
        git(&dir, args)?;
    }
    Ok(dir)
}

fn commit_file(repo: &Path, file: &str, content: &[u8], message: &str) -> Result<()> {
    let path = repo.join(file);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, content)?;
    git(repo, &["add", file])?;
    git(repo, &["commit", "--quiet", "-m", message])?;
    Ok(())
}

/// Build one complete valid Active candidate through the public Git build path.
pub(super) fn build_active_candidate(
    td: &TempDir,
    ids: (Uuid, Uuid, Uuid),
    kit_generation: u64,
    label: &str,
    payload: &[u8],
) -> Result<BuiltCloneKitArtifacts> {
    let source_repo = init_repo(td.path(), &format!("source-{label}"))?;
    commit_file(&source_repo, &format!("{label}.bin"), payload, &format!("{label} candidate commit"))?;
    let staging_root = td.path().join(format!("staging-{label}"));
    fs::create_dir_all(&staging_root)?;
    fs::set_permissions(&staging_root, std::fs::Permissions::from_mode(0o700))?;
    let built = build_clonekit_from_git(
        &BuildCloneKitRequest {
            tenant_id: ids.0,
            repository_id: ids.1,
            owner_id: ids.0,
            history_id: ids.2,
            storage_generation: 1,
            object_format: CloneKitObjectFormat::Sha1,
            kit_generation,
            branch_ref: "refs/heads/main".into(),
            created_unix: 1_750_000_000,
            expires_unix: 1_750_003_600,
            git_binary: git_binary(),
            source_repo_dir: source_repo,
            staging_root,
            retention_pin_id: Some(Uuid::new_v4()),
            inject_failure: None,
        },
        None,
    )?;
    Ok(built)
}
