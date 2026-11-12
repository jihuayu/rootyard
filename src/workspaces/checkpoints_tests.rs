use super::copy_snapshot;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn write(root: &Path, name: &str, bytes: &[u8]) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(&path, bytes).expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
}

#[test]
fn restore_copy_never_replaces_a_preexisting_lower_tree() {
    let root = tempfile::tempdir().expect("temp dir");
    let source = root.path().join("checkpoint");
    fs::create_dir(&source).expect("source");
    write(&source, "a.txt", b"a");

    let dest = root.path().join("workspaces/id");
    fs::create_dir_all(&dest).expect("dest");
    fs::write(dest.join("sentinel"), b"sentinel").expect("sentinel");
    assert!(copy_snapshot(&source, &dest).is_err(), "an existing lower tree is never replaced");
    assert_eq!(fs::read(dest.join("sentinel")).expect("sentinel bytes"), b"sentinel");
    assert!(!dest.join("a.txt").exists(), "nothing is copied into the existing tree");
    let staged: Vec<String> = fs::read_dir(root.path().join("workspaces"))
        .expect("workspaces dir")
        .map(|child| child.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!staged.iter().any(|name| name.starts_with(".restore-")), "a refused restore leaves no staging tree");

    let fresh = root.path().join("workspaces/fresh");
    copy_snapshot(&source, &fresh).expect("restore copy").keep();
    assert_eq!(fs::read(fresh.join("a.txt")).expect("copied a.txt"), b"a");
    assert_eq!(fs::read(dest.join("sentinel")).expect("sentinel bytes"), b"sentinel");
}

#[test]
fn restore_copy_guard_cleans_up_only_before_commit() {
    let root = tempfile::tempdir().expect("temp dir");
    let source = root.path().join("checkpoint");
    fs::create_dir(&source).expect("source");
    write(&source, "a.txt", b"a");
    let workspaces = root.path().join("workspaces");
    fs::create_dir_all(&workspaces).expect("workspaces dir");

    let failed = workspaces.join("failed");
    let guard = copy_snapshot(&source, &failed).expect("restore copy");
    assert_eq!(fs::read(failed.join("a.txt")).expect("copied"), b"a");
    drop(guard);
    assert!(!failed.exists(), "a definite pre-COMMIT failure cleans up the published tree");

    let retained = workspaces.join("retained");
    copy_snapshot(&source, &retained).expect("restore copy").keep();
    assert_eq!(fs::read(retained.join("a.txt")).expect("copied"), b"a");
}
