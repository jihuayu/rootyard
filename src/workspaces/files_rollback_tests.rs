use super::*;

#[test]
fn put_rollback_restores_files_and_failed_atomic_put_leaves_no_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    fs::write(repo.join("existing.txt"), b"v1\n").unwrap();
    fs::set_permissions(repo.join("existing.txt"), fs::Permissions::from_mode(0o644)).unwrap();

    let mut rb = PutRollback::capture(repo, "existing.txt", None, None).unwrap();
    atomic_put(rb.target(), b"v2-rejected\n", 0o600).unwrap();
    rb.restore_now();
    assert_eq!(fs::read(repo.join("existing.txt")).unwrap(), b"v1\n");
    assert_eq!(fs::metadata(repo.join("existing.txt")).unwrap().permissions().mode() & 0o777, 0o644);

    let mut rb_new = PutRollback::capture(repo, "nested/sub/new.txt", None, None).unwrap();
    atomic_put(rb_new.target(), b"created\n", 0o600).unwrap();
    rb_new.restore_now();
    assert!(!repo.join("nested").exists());

    fs::create_dir(repo.join("dir_target")).unwrap();
    assert!(atomic_put(&repo.join("dir_target"), b"boom", 0o600).is_err());
    let leftovers: Vec<_> = fs::read_dir(repo)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".rootyard-"))
        .collect();
    assert!(leftovers.is_empty(), "atomic_put failure must unlink temporary file");
}

#[test]
fn git_rollback_cleans_index_lock_fails_closed_and_triggers_upper_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("mount");
    let upper = dir.path().join("upper");
    fs::create_dir_all(repo.join(".git/objects/aa")).unwrap();
    fs::create_dir_all(&upper).unwrap();
    fs::write(repo.join(".git/index"), b"index-v1").unwrap();
    fs::write(repo.join(".git/objects/aa/keep"), b"keep").unwrap();
    fs::write(repo.join("hello.txt"), b"hello").unwrap();

    assert!(walk_git_objects_bounded(&repo.join(".git/objects"), 1).is_err());
    fs::set_permissions(repo.join(".git/objects/aa"), fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(repo.join(".git/objects/aa")).is_err() {
        assert!(GitRollback::capture(&repo, &[String::from("hello.txt")], None, None).is_err());
    }
    fs::set_permissions(repo.join(".git/objects/aa"), fs::Permissions::from_mode(0o700)).unwrap();

    let mut rb = GitRollback::capture(&repo, &[String::from("hello.txt")], Some(upper.clone()), None).unwrap();
    fs::create_dir_all(upper.join(".git/objects/bb")).unwrap();
    fs::write(upper.join(".git/index"), b"index-v2-rejected").unwrap();
    fs::write(upper.join(".git/index.lock"), b"stranded-by-timeout").unwrap();
    fs::write(upper.join(".git/objects/bb/newblob"), b"new").unwrap();
    fs::create_dir_all(repo.join(".git/objects/bb")).unwrap();
    fs::write(repo.join(".git/objects/bb/newblob"), b"new").unwrap();
    fs::set_permissions(repo.join(".git/objects/bb"), fs::Permissions::from_mode(0o500)).unwrap();

    rb.state.take().unwrap().restore_sync();
    fs::set_permissions(repo.join(".git/objects/bb"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!upper.join(".git/index.lock").exists(), "upper fallback must remove index.lock");
    assert!(!upper.join(".git/index").exists(), "upper fallback must remove copy-up index");
    assert!(!upper.join(".git/objects/bb").exists(), "upper fallback must prune loose objects");

    let mut rb_direct = GitRollback::capture(&repo, &[String::from("hello.txt")], None, None).unwrap();
    fs::write(repo.join(".git/index"), b"index-v2").unwrap();
    fs::write(repo.join(".git/index.lock"), b"lock").unwrap();
    fs::create_dir_all(repo.join(".git/objects/cc")).unwrap();
    fs::write(repo.join(".git/objects/cc/newblob"), b"new").unwrap();
    fs::set_permissions(repo.join(".git/objects/cc/newblob"), fs::Permissions::from_mode(0o444)).unwrap();
    rb_direct.state.take().unwrap().restore_sync();
    assert_eq!(fs::read(repo.join(".git/index")).unwrap(), b"index-v1");
    assert!(!repo.join(".git/index.lock").exists() && !repo.join(".git/objects/cc").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_put_and_git_rollback_complete_even_when_io_slots_saturated() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    fs::create_dir_all(repo.join(".git/objects")).unwrap();
    fs::write(repo.join("hello.txt"), b"v1\n").unwrap();
    fs::write(repo.join(".git/index"), b"idx-v1").unwrap();

    let mut held_io = Vec::new();
    while let Ok(p) = crate::workspaces::blocking::io_slots().clone().try_acquire_owned() {
        held_io.push(p);
    }

    let put_rb = PutRollback::capture(repo, "hello.txt", None, None).unwrap();
    atomic_put(put_rb.target(), b"v2-uncommitted\n", 0o600).unwrap();
    put_rb.rollback().await;
    assert_eq!(fs::read(repo.join("hello.txt")).unwrap(), b"v1\n");

    let git_rb = GitRollback::capture(repo, &[String::from("hello.txt")], None, None).unwrap();
    fs::write(repo.join(".git/index"), b"idx-v2-uncommitted").unwrap();
    fs::write(repo.join(".git/index.lock"), b"lock").unwrap();
    git_rb.rollback().await;
    assert_eq!(fs::read(repo.join(".git/index")).unwrap(), b"idx-v1");
    assert!(!repo.join(".git/index.lock").exists());

    drop(held_io);
}
