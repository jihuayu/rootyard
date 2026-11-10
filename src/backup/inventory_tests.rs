//! Focused regressions for native inventory and restored-metadata comparison.
use super::restore::restore_metadata_repositories;
use super::*;
use std::path::Path;

fn config(git: &Path) -> Config {
    Config {
        database_url: String::new(),
        data_dir: std::env::temp_dir(),
        bind: "127.0.0.1:0".parse().unwrap(),
        git: git.to_owned(),
        max_request_bytes: 0,
        max_output_bytes: 0,
        max_concurrent_git: 1,
        git_timeout: std::time::Duration::from_secs(30),
        git_memory_bytes: 0,
        max_repo_bytes: 0,
        max_pending_deliveries: 0,
        outbox_worker: false,
        metrics_bind: None,
    }
}

fn git() -> std::path::PathBuf {
    std::env::var_os("ROOTYARD_TEST_GIT")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("ROOTYARD_GIT").map(std::path::PathBuf::from))
        .unwrap_or_else(|| "git".into())
        .canonicalize()
        .expect("test Git executable must exist")
}

fn repo(backend: &str) -> Repository {
    Repository {
        id: Uuid::from_u128(1),
        generation: 3,
        incident_revision: 2,
        state: "recovering".into(),
        recovery_reason: Some("git_outcome_unknown".into()),
        backend: (!backend.is_empty()).then(|| backend.to_owned()),
        unknown_operations: 1,
        refs: Some("refs/heads/main 0123456789abcdef0123456789abcdef01234567 \n".into()),
        head: Some("ref: refs/heads/main\n".into()),
    }
}

async fn run(mut command: Command) {
    assert!(command.status().await.unwrap().success(), "{command:?} failed");
}

/// A bare repository shaped exactly like the one a native volume carries for
/// every gitfs/pando repository, with a linear history readable by git.
async fn native_repository(root: &Path, id: Uuid, git: &Path) {
    let path = root.join("repos").join(format!("{id}.git"));
    let mut init = command(git);
    init.args(["init", "--quiet", "--bare"]).arg(&path);
    run(init).await;
    let mut config = command(git);
    config.args(["--git-dir"]).arg(&path).args(["config", "rootyard.repositoryId", &id.to_string()]);
    run(config).await;
    // Commit an empty tree so `fsck --full --strict` has a real object graph.
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    for args in [
        vec!["init", "--quiet"],
        vec!["config", "user.name", "Test"],
        vec!["config", "user.email", "test@example.invalid"],
        vec!["commit", "--quiet", "--allow-empty", "-m", "root"],
    ] {
        let mut cmd = command(git);
        cmd.current_dir(&work).args(args);
        cmd.env("GIT_AUTHOR_DATE", "1700000000 +0000").env("GIT_COMMITTER_DATE", "1700000000 +0000");
        run(cmd).await;
    }
    let mut push = command(git);
    push.current_dir(&work).args(["push", "--quiet"]).arg(&path).arg("HEAD:refs/heads/main");
    run(push).await;
}

#[tokio::test]
async fn native_inventory_never_relabels_the_database_backend() {
    let config = config(&git());
    let tmp = tempfile::tempdir().unwrap();
    let id = repo("").id;
    native_repository(tmp.path(), id, &config.git).await;
    for backend in ["gitfs", "pando"] {
        let mut repos = vec![repo(backend)];
        git_inventory(&config, tmp.path(), &mut repos, true).await.unwrap();
        assert_eq!(repos[0].backend.as_deref(), Some(backend), "native inventory must keep the database backend");
        assert!(repos[0].refs.is_some());
        assert!(repos[0].head.is_some());
    }
    // An archive without a backend field stays unknown; it is never defaulted
    // to gitfs (genuine old Pando archives exist).
    let mut repos = vec![repo("")];
    git_inventory(&config, tmp.path(), &mut repos, false).await.unwrap();
    assert_eq!(repos[0].backend, None, "inventory must not synthesize a backend");
}

#[tokio::test]
async fn native_inventory_still_requires_the_bare_repository() {
    let config = config(&git());
    let tmp = tempfile::tempdir().unwrap();
    let mut missing = vec![repo("gitfs")];
    assert!(git_inventory(&config, tmp.path(), &mut missing, false).await.is_err());
    assert_eq!(missing[0].backend.as_deref(), Some("gitfs"));
}

#[test]
fn historical_archives_compare_legacy_backend_from_the_database() {
    for backend in ["gitfs", "pando"] {
        let archived = repo("");
        // The comparison copy drops the backend; everything else is compared.
        assert!(restore_metadata_repositories(&[archived.clone()], vec![repo(backend)], false).is_ok());
        // A pg_refstore repository owns no native bare repository.
        assert!(restore_metadata_repositories(&[archived.clone()], vec![repo("pg_refstore")], false).is_err());
        assert!(restore_metadata_repositories(&[archived.clone()], vec![repo("")], false).is_err());
        assert!(restore_metadata_repositories(&[archived.clone()], vec![repo("blob")], false).is_err());
        // The backend allowance never excuses a real metadata difference.
        let mut other = repo(backend);
        other.unknown_operations = 0;
        assert!(restore_metadata_repositories(&[other], vec![repo(backend)], false).is_err());
        let mut changed_refs = repo(backend);
        changed_refs.refs = Some("refs/heads/main fedcba9876543210fedcba9876543210fedcba98 \n".into());
        assert!(restore_metadata_repositories(&[changed_refs], vec![repo(backend)], false).is_err());
    }
}

#[test]
fn backend_is_absent_only_when_the_archive_had_no_field() {
    const HISTORICAL: &str = r#"{"id":"00000000-0000-0000-0000-000000000001","generation":1,
        "incident_revision":0,"state":"ready","recovery_reason":null,"unknown_operations":0,
        "refs":null,"head":null}"#;
    let decoded: Repository = serde_json::from_str(HISTORICAL).unwrap();
    assert_eq!(decoded.backend, None, "a historical archive has no backend field");
    let mut current = serde_json::from_str::<serde_json::Value>(HISTORICAL).unwrap();
    current["backend"] = "pando".into();
    let decoded: Repository = serde_json::from_value(current).unwrap();
    assert_eq!(decoded.backend.as_deref(), Some("pando"));
}

#[test]
fn current_archives_require_an_exact_backend() {
    assert!(restore_metadata_repositories(&[repo("gitfs")], vec![repo("gitfs")], true).is_ok());
    assert!(restore_metadata_repositories(&[repo("gitfs")], vec![repo("pando")], true).is_err());
    assert!(restore_metadata_repositories(&[repo("pando")], vec![repo("gitfs")], true).is_err());
    // A current archive decoded without its backend (the old
    // `#[serde(default)]` empty string) never equals a real database backend.
    let unset = repo("");
    assert!(restore_metadata_repositories(&[unset], vec![repo("gitfs")], true).is_err());
}
