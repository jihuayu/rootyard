use super::*;
// The owned teardown helpers live in `ownership` with their original
// privacy; tests reach them through the module, never a production re-export.
use super::ownership::{mount_id_in, owns_current_mount};

struct NotManaged;

impl LazySource for NotManaged {
    fn file(&self, _: &Path) -> io::Result<Option<File>> {
        Ok(None)
    }
}

#[test]
fn unknown_lazy_path_fails_closed_but_git_is_eager() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("worktree.txt"), b"remote placeholder").unwrap();
    let entry = Entry::new(root.path(), Path::new("worktree.txt"), false).unwrap();
    let error = open_lower(Some(&NotManaged), Path::new("worktree.txt"), &entry).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EIO));

    fs::create_dir(root.path().join(".git")).unwrap();
    fs::write(root.path().join(".git/config"), b"[core]").unwrap();
    let entry = Entry::new(root.path(), Path::new(".git/config"), false).unwrap();
    let file = open_lower(Some(&NotManaged), Path::new(".git/config"), &entry).unwrap();
    assert_eq!(file.metadata().unwrap().len(), 6);
}

#[test]
fn freeze_rejects_mutations_without_blocking_reads() {
    let root = tempfile::tempdir().unwrap();
    let lower = root.path().join("lower");
    let upper = root.path().join("upper");
    fs::create_dir_all(&lower).unwrap();
    fs::write(lower.join("file.txt"), b"readable").unwrap();
    let gate = MutationGate::new_with_lease(1, i64::MAX).unwrap();
    let overlay = Overlay::new_with_gate(lower, upper, gate.clone()).unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let freeze_gate = gate.clone();
        scope.spawn(move || {
            freeze_gate.freeze(|| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let error = gate.mutation().err().and_then(|error| error.raw_os_error());
        assert_eq!(error, Some(libc::EAGAIN));
        let attr = overlay.attr(Path::new("file.txt"), 2).expect("read metadata ignores the freeze");
        assert_eq!(attr.size, 8);
        release_tx.send(()).unwrap();
    });
    drop(gate.mutation().expect("thaw admits mutations"));
}

#[test]
fn helper_mount_options_add_auto_unmount_without_widening_the_owner_acl() {
    let legacy = mount_options(false);
    assert!(!legacy.contains(&MountOption::AutoUnmount), "the legacy mount keeps its option list");
    let helper = mount_options(true);
    assert!(helper.contains(&MountOption::AutoUnmount), "AutoUnmount is helper-only");
    assert!(helper.contains(&MountOption::DefaultPermissions), "permission checks stay enabled");
    // fuser derives SessionACL from the options it is given, so adding an
    // Allow* option here would widen the session ACL; AutoUnmount alone
    // keeps SessionACL::Owner while fusermount still gets its implicit
    // allow_other for auto_unmount.
    assert!(!helper.contains(&MountOption::AllowOther), "AllowOther must not be added explicitly");
    assert!(!helper.contains(&MountOption::AllowRoot), "AllowRoot must not be added explicitly");
    let stripped: Vec<MountOption> =
        helper.iter().filter(|option| **option != MountOption::AutoUnmount).cloned().collect();
    assert_eq!(stripped, legacy, "the helper adds exactly one option");
}

#[test]
fn mount_handle_offers_a_consuming_joined_teardown_and_a_borrowable_stop() {
    // Compile-time contract only (no mount is created here): the owned
    // helper teardown consumes the handle and returns after the session
    // join, while the legacy non-consuming stop stays callable through a
    // shared borrow for existing callers.
    fn owning(handle: MountHandle) {
        handle.shutdown_and_join();
    }
    fn borrowed(handle: &MountHandle) {
        handle.shutdown();
    }
    let _: fn(MountHandle) = owning;
    let _: fn(&MountHandle) = borrowed;
}

#[test]
fn mountinfo_identity_is_the_single_exact_mount_at_the_owned_path() {
    let mountinfo = "\
36 35 0:32 / /srv/rootyard/workspaces/a/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
37 35 0:33 / /srv/rootyard/workspaces/a/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
38 35 0:34 / /srv/rootyard/workspaces/a/mnt-extra rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
39 35 0:35 / /srv/rootyard/workspaces/with\\040space/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
";
    // Stacked mounts at one path are ambiguous: never pick one, and do not
    // assume the largest (or newest) opaque kernel ID is the visible mount.
    let err = mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/a/mnt"))
        .expect_err("stacked mounts must not resolve to one identity");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    // The same stack in the reverse ID order is just as ambiguous.
    let reversed = "\
37 35 0:33 / /srv/rootyard/workspaces/a/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
36 35 0:32 / /srv/rootyard/workspaces/a/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
";
    assert_eq!(
        mount_id_in(reversed, Path::new("/srv/rootyard/workspaces/a/mnt"))
            .expect_err("stacked mounts are ambiguous in either ID order")
            .kind(),
        io::ErrorKind::InvalidData
    );
    // A single exact match is the owned identity.
    assert_eq!(mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/a/mnt-extra")).unwrap(), Some(38));
    // An absent path has no identity at all.
    assert_eq!(mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/a")).unwrap(), None);
    // mountinfo escapes whitespace octally; the comparison is on the path.
    assert_eq!(mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/with space/mnt")).unwrap(), Some(39));
}

#[test]
fn owned_unmount_requires_the_captured_mount_id() {
    assert!(owns_current_mount(37, Some(37)));
    assert!(!owns_current_mount(37, Some(38)), "a newer mount at the path is not owned");
    assert!(!owns_current_mount(37, None), "an already unmounted path needs no unmount");
}

#[test]
fn direct_upper_whiteout_rollback_keeps_overlay_reads_and_subsequent_unlinks_consistent() {
    let root = tempfile::tempdir().unwrap();
    let lower = root.path().join("lower");
    let upper = root.path().join("upper");
    fs::create_dir_all(&lower).unwrap();
    fs::write(lower.join("a.txt"), b"from-lower-a").unwrap();
    fs::write(lower.join("b.txt"), b"from-lower-b").unwrap();

    let gate = MutationGate::new_with_lease(1, i64::MAX).unwrap();
    let mut overlay = Overlay::new_with_gate(lower, upper.clone(), gate.clone()).unwrap();

    // 1. Unlink lower file `a.txt` through Overlay; snapshot `.rootyard-whiteouts.json`.
    overlay.op_unlink(1, OsStr::new("a.txt")).unwrap();
    assert_eq!(overlay.op_lookup(1, OsStr::new("a.txt")).unwrap_err().raw_os_error(), Some(libc::ENOENT));
    let whiteout_path = upper.join(".rootyard-whiteouts.json");
    let prior_whiteouts = fs::read(&whiteout_path).unwrap();
    assert_eq!(serde_json::from_slice::<Vec<String>>(&prior_whiteouts).unwrap(), vec!["a.txt"]);

    // 2. Write over `a.txt` via atomic temp create + write + rename (clearing `a.txt` whiteout).
    let tmp = overlay.op_create(1, OsStr::new(".tmp-put"), 0o600).unwrap();
    overlay.op_write(tmp.ino, 0, b"rejected-put-a").unwrap();
    overlay.op_rename(1, OsStr::new(".tmp-put"), 1, OsStr::new("a.txt"), 0).unwrap();
    let a_attr = overlay.op_lookup(1, OsStr::new("a.txt")).unwrap();
    assert_eq!(a_attr.size, 14);
    assert!(serde_json::from_slice::<Vec<String>>(&fs::read(&whiteout_path).unwrap()).unwrap().is_empty());

    // 3. Fence FUSE and simulate direct upper-layer rollback restoring `.rootyard-whiteouts.json`.
    gate.fence();
    fs::remove_file(upper.join("a.txt")).unwrap();
    let rollback_tmp = upper.join(".rollback-whiteouts");
    fs::write(&rollback_tmp, &prior_whiteouts).unwrap();
    fs::rename(&rollback_tmp, &whiteout_path).unwrap();

    // 4. Ungated Overlay reads/lookups/readdir must see ENOENT, never resurrecting `lower/a.txt`.
    assert_eq!(overlay.op_lookup(1, OsStr::new("a.txt")).unwrap_err().raw_os_error(), Some(libc::ENOENT));
    assert_eq!(overlay.op_getattr(a_attr.ino).unwrap_err().raw_os_error(), Some(libc::ENOENT));
    assert_eq!(overlay.read_plan(a_attr.ino).err().and_then(|e| e.raw_os_error()), Some(libc::ENOENT));
    let listed: Vec<String> = overlay
        .op_readdir(1)
        .unwrap()
        .into_iter()
        .map(|(_, _, n)| n.to_string_lossy().into_owned())
        .filter(|n| n != "." && n != "..")
        .collect();
    assert_eq!(listed, vec!["b.txt"]);

    // 5. Same-host lease handoff + unrelated unlink of `b.txt` must preserve `a.txt` whiteout on disk.
    gate.handoff(2, i64::MAX).unwrap();
    overlay.op_unlink(1, OsStr::new("b.txt")).unwrap();
    assert_eq!(overlay.op_lookup(1, OsStr::new("a.txt")).unwrap_err().raw_os_error(), Some(libc::ENOENT));
    assert_eq!(overlay.op_lookup(1, OsStr::new("b.txt")).unwrap_err().raw_os_error(), Some(libc::ENOENT));
    let saved: Vec<String> = serde_json::from_slice(&fs::read(&whiteout_path).unwrap()).unwrap();
    assert_eq!(saved, vec!["a.txt", "b.txt"]);
}
