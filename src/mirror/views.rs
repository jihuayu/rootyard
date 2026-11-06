//! Immutable snapshot pins and isolated reachable-closure job views on CI read mirrors.
use crate::{
    AppState, Error, db, git_http,
    mirror::{
        Snapshot, eviction,
        sync::{
            atomic_file, bare_config, mirror_git, private_directory, read_regular, verify_directory,
        },
    },
};
use anyhow::{Context, Result, bail};
use axum::http::StatusCode;
use std::{
    fs::File,
    path::{Path as FsPath, PathBuf},
};
use uuid::Uuid;

/// Pin by immutable snapshot and exact commit. Old snapshots and pins are kept;
/// no GC may remove objects referenced by these views or by active Git children.
pub(crate) async fn pinned_path(
    state: &AppState,
    repo: &db::Repository,
    oid: &str,
) -> Result<PathBuf, Error> {
    let root = state.storage.root.join("repos").join(repo.id.to_string());
    let unavailable = || {
        Error(
            StatusCode::CONFLICT,
            "mirror has no complete snapshot for this generation; sync and retry",
        )
    };
    let pin_name = format!("pin-{}-{oid}.json", repo.storage_generation);
    let pin_file = root.join(&pin_name);
    let load = || -> Result<(Snapshot, bool), Error> {
        let (path, pinned) = match pin_file.try_exists() {
            Ok(true) => (pin_file.clone(), true),
            Ok(false) => (root.join("current.json"), false),
            Err(error) => return Err(Error::internal(error)),
        };
        verify_directory(&root).map_err(|_| unavailable())?;
        let bytes = read_regular(&path, 4096).map_err(|_| unavailable())?;
        let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(Error::internal)?;
        if snapshot.repository_id != repo.id
            || snapshot.storage_generation != repo.storage_generation
        {
            return Err(unavailable());
        }
        Ok((snapshot, pinned))
    };
    let (snapshot, pinned) = load()?;
    let path_for = |snapshot: &Snapshot| {
        root.join(snapshot.snapshot.to_string())
            .join("pins")
            .join(format!("{oid}.git"))
    };
    if pinned {
        let pin = path_for(&snapshot);
        validate_pin(&pin, oid, &root.join(snapshot.snapshot.to_string()))
            .map_err(Error::internal)?;
        eviction::touch_path(&pin_file);
        return Ok(pin);
    }
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    // A concurrent request may have established this pin while we waited. Pins
    // survive later snapshots that drop the original ref, but never generations.
    let (snapshot, pinned) = load()?;
    if !pinned {
        let mut count = 0;
        let mut entries = 0;
        for entry in std::fs::read_dir(&root).map_err(Error::internal)? {
            entries += 1;
            if entries > 100_000 {
                return Err(Error::internal("mirror directory exceeds bound"));
            }
            let entry = entry.map_err(Error::internal)?;
            if entry.file_name().to_string_lossy().starts_with("pin-") {
                count += 1;
            }
        }
        if count >= crate::ci_pins::MAX_PINS {
            return Err(Error(
                StatusCode::TOO_MANY_REQUESTS,
                "mirror pin admission limit reached",
            ));
        }
    }
    let snapshot_root = root.join(snapshot.snapshot.to_string());
    let bare = snapshot_root.join("repository.git");
    for path in [
        &snapshot_root,
        &bare,
        &bare.join("objects"),
        &snapshot_root.join("pins"),
    ] {
        verify_directory(path).map_err(Error::internal)?;
    }
    let pin = path_for(&snapshot);
    if pin.try_exists().map_err(Error::internal)? {
        validate_pin(&pin, oid, &snapshot_root).map_err(Error::internal)?;
        if !pinned {
            atomic_file(
                &root,
                &pin_name,
                &serde_json::to_vec(&snapshot).map_err(Error::internal)?,
            )
            .map_err(Error::internal)?;
        }
        eviction::touch_path(&pin_file);
        return Ok(pin);
    }
    let mut command = mirror_git(state);
    command
        .arg("--git-dir")
        .arg(&bare)
        .args(["cat-file", "-t", oid]);
    let result = git_http::collect_git_output(command, 128, state.config.git_timeout).await;
    if !matches!(result, Ok(ref bytes) if bytes == b"commit\n") {
        return Err(Error(
            StatusCode::CONFLICT,
            "exact commit unavailable on mirror; sync and retry or use primary explicitly",
        ));
    }
    let temporary = snapshot_root
        .join("pins")
        .join(format!(".{}.staging", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        private_directory(&temporary)?;
        for name in ["objects", "objects/info", "refs", "refs/heads"] {
            private_directory(&temporary.join(name))?;
        }
        std::fs::write(temporary.join("HEAD"), b"ref: refs/heads/main\n")?;
        std::fs::write(temporary.join("refs/heads/main"), format!("{oid}\n"))?;
        std::fs::write(temporary.join("config"), bare_config())?;
        let objects = bare.join("objects").canonicalize()?;
        let text = objects
            .to_str()
            .context("mirror data directory must be UTF-8")?;
        if text.contains(['\n', '\r']) {
            bail!("invalid mirror data path");
        }
        std::fs::write(
            temporary.join("objects/info/alternates"),
            format!("{text}\n"),
        )?;
        crate::storage::sync_tree(&temporary)?;
        std::fs::rename(&temporary, &pin)?;
        File::open(snapshot_root.join("pins"))?.sync_all()?;
        atomic_file(&root, &pin_name, &serde_json::to_vec(&snapshot)?)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&temporary);
    }
    result.map_err(Error::internal)?;
    Ok(pin)
}

pub(crate) fn validate_pin(pin: &FsPath, oid: &str, snapshot: &FsPath) -> Result<()> {
    for path in [
        snapshot.to_path_buf(),
        snapshot.join("repository.git"),
        snapshot.join("repository.git/objects"),
        snapshot.join("pins"),
        pin.to_path_buf(),
        pin.join("objects"),
        pin.join("objects/info"),
        pin.join("refs"),
        pin.join("refs/heads"),
    ] {
        verify_directory(&path)?;
    }
    if read_regular(&pin.join("HEAD"), 64)? != b"ref: refs/heads/main\n"
        || read_regular(&pin.join("refs/heads/main"), 64)? != format!("{oid}\n").as_bytes()
        || read_regular(&pin.join("config"), 4096)? != bare_config().as_bytes()
        || read_regular(&pin.join("objects/info/alternates"), 4096)?
            != format!("{}\n", snapshot.join("repository.git/objects").display()).as_bytes()
    {
        bail!("immutable mirror pin changed");
    }
    Ok(())
}

/// A runner authorization must never use the legacy alternates-backed pin.
/// This independently materializes only the target's full reachable ancestry.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        mirror::sync::{ci_route, primary_origin},
        storage::Storage,
    };
    use std::sync::Arc;

    #[test]
    fn primary_is_only_a_trusted_origin() {
        for good in [
            "https://git.example.test",
            "https://git.example.test:8443/",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(primary_origin(good).is_ok(), "{good}");
        }
        for bad in [
            "http://example.test",
            "file:///tmp/repo",
            "https://user:pass@example.test",
            "https://example.test/git",
            "https://example.test/?token=x",
            "https://example.test/#x",
            "ssh://example.test",
        ] {
            assert!(primary_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn exact_oid_path_required() {
        let oid = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            ci_route(&format!("/ci/{oid}/git/a/b.git/info/refs")).unwrap(),
            (oid, "/git/a/b.git/info/refs")
        );
        for path in [
            "/git/a/b.git/info/refs",
            "/ci/main/git/a/b.git/info/refs",
            "/ci/../git/a/b.git/info/refs",
        ] {
            assert!(ci_route(path).is_err());
        }
    }

    #[test]
    fn metadata_and_pin_corruption_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        atomic_file(&root, "pointer", b"complete").unwrap();
        assert_eq!(
            read_regular(&root.join("pointer"), 32).unwrap(),
            b"complete"
        );
        assert!(read_regular(&root.join("pointer"), 2).is_err());
        std::os::unix::fs::symlink(root.join("pointer"), root.join("link")).unwrap();
        assert!(read_regular(&root.join("link"), 32).is_err());
        std::os::unix::fs::symlink(&root, root.join("escaped")).unwrap();
        assert!(verify_directory(&root.join("escaped")).is_err());
    }

    // Native Git coverage without a database server: exercise the exact views,
    // retained pins and replacement ref semantics, not HTTP/authentication.
    #[tokio::test]
    async fn native_git_views_keep_exact_pins_and_ignore_replacements() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let git = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join("git"))
            .find(|p| p.is_file())
            .unwrap()
            .canonicalize()
            .unwrap();
        let run = |dir: &FsPath, args: &[&str]| -> String {
            let output = std::process::Command::new(&git)
                .current_dir(dir)
                .env_clear()
                .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "Git fixture failed");
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        run(&source, &["init", "--initial-branch=main", "--template="]);
        std::fs::write(source.join("hello"), b"first\n").unwrap();
        run(&source, &["add", "hello"]);
        run(
            &source,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "first",
            ],
        );
        let oid = run(&source, &["rev-parse", "HEAD"]);
        let blob = run(&source, &["rev-parse", "HEAD:hello"]);
        // This is legal outside refs/heads and can arrive via a normal push.
        run(
            &source,
            &["update-ref", &format!("refs/replace/{blob}"), &oid],
        );
        let config = Config {
            database_url: "postgres://unused@127.0.0.1/unused".into(),
            data_dir: root.join("mirror"),
            bind: "127.0.0.1:0".parse().unwrap(),
            git,
            max_request_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_concurrent_git: 2,
            git_timeout: std::time::Duration::from_secs(20),
            git_memory_bytes: 1024 * 1024 * 1024,
            max_repo_bytes: 1024 * 1024 * 1024,
            max_pending_deliveries: 100,
            outbox_worker: false,
            metrics_bind: None,
        };
        let state = AppState {
            pool: db::pool(&config.database_url).unwrap(),
            storage: Storage::open_mirror(&config).unwrap(),
            config,
            mirror_primary: Some("http://127.0.0.1".into()),
            hooks: None,
            git_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            transfer_metrics: Arc::new(crate::metrics::TransferCounters::default()),
            dispatch: crate::dispatch::Signals::default(),
        };
        let repo = db::Repository {
            id: Uuid::new_v4(),
            name: "demo".into(),
            owner: "alice".into(),
            state: "ready".into(),
            clone_path: String::new(),
            storage_backend: "gitfs".into(),
            storage_generation: 1,
        };
        let repo_root = state.storage.root.join("repos").join(repo.id.to_string());
        private_directory(&repo_root).unwrap();
        let snapshot = Snapshot {
            repository_id: repo.id,
            storage_generation: 1,
            snapshot: Uuid::new_v4(),
        };
        let snapshot_root = repo_root.join(snapshot.snapshot.to_string());
        private_directory(&snapshot_root).unwrap();
        private_directory(&snapshot_root.join("pins")).unwrap();
        let mut clone = mirror_git(&state);
        clone
            .args(["clone", "--mirror", "--no-hardlinks"])
            .arg(&source)
            .arg(snapshot_root.join("repository.git"));
        git_http::collect_git_output(clone, 4096, state.config.git_timeout)
            .await
            .unwrap();
        atomic_file(
            &repo_root,
            "current.json",
            &serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();
        assert_eq!(
            pinned_path(&state, &repo, &blob).await.unwrap_err().0,
            StatusCode::CONFLICT
        );
        let pin = pinned_path(&state, &repo, &oid).await.unwrap();
        validate_pin(&pin, &oid, &snapshot_root).unwrap();
        let mut clone = mirror_git(&state);
        clone
            .arg("clone")
            .arg("--no-local")
            .arg(&pin)
            .arg(root.join("checkout"));
        git_http::collect_git_output(clone, 4096, state.config.git_timeout)
            .await
            .unwrap();
        let mut head = mirror_git(&state);
        head.arg("-C")
            .arg(root.join("checkout"))
            .args(["rev-parse", "HEAD"]);
        assert_eq!(
            String::from_utf8(
                git_http::collect_git_output(head, 128, state.config.git_timeout)
                    .await
                    .unwrap()
            )
            .unwrap()
            .trim(),
            oid
        );
        // A later current snapshot cannot erase a previously established pin.
        let next = Snapshot {
            snapshot: Uuid::new_v4(),
            ..snapshot
        };
        atomic_file(
            &repo_root,
            "current.json",
            &serde_json::to_vec(&next).unwrap(),
        )
        .unwrap();
        assert_eq!(pinned_path(&state, &repo, &oid).await.unwrap(), pin);
        std::fs::write(pin.join("refs/heads/main"), format!("{blob}\n")).unwrap();
        assert_eq!(
            pinned_path(&state, &repo, &oid).await.unwrap_err().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
