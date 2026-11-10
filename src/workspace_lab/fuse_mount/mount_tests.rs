//! Ownership, option-list and teardown-contract tests for the FUSE mount.
//!
//! The identity helpers are named once through `super::ownership`, the module
//! whose functions `unmount_owned` actually calls, so these cases exercise the
//! implementation that gates a real unmount.

use super::{MountHandle, mount_options, ownership, ownership::owns_current_mount};
use std::{io, path::Path};

#[test]
fn helper_mount_options_add_auto_unmount_without_widening_the_owner_acl() {
    let legacy = mount_options(false);
    assert!(!legacy.contains(&fuser::MountOption::AutoUnmount), "the legacy mount keeps its option list");
    let helper = mount_options(true);
    assert!(helper.contains(&fuser::MountOption::AutoUnmount), "AutoUnmount is helper-only");
    assert!(helper.contains(&fuser::MountOption::DefaultPermissions), "permission checks stay enabled");
    // fuser derives SessionACL from the options it is given, so adding an
    // Allow* option here would widen the session ACL; AutoUnmount alone
    // keeps SessionACL::Owner while fusermount still gets its implicit
    // allow_other for auto_unmount.
    assert!(!helper.contains(&fuser::MountOption::AllowOther), "AllowOther must not be added explicitly");
    assert!(!helper.contains(&fuser::MountOption::AllowRoot), "AllowRoot must not be added explicitly");
    let stripped: Vec<fuser::MountOption> =
        helper.iter().filter(|option| **option != fuser::MountOption::AutoUnmount).cloned().collect();
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
    let err = ownership::mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/a/mnt"))
        .expect_err("stacked mounts must not resolve to one identity");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    // The same stack in the reverse ID order is just as ambiguous.
    let reversed = "\
37 35 0:33 / /srv/rootyard/workspaces/a/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
36 35 0:32 / /srv/rootyard/workspaces/a/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
";
    assert_eq!(
        ownership::mount_id_in(reversed, Path::new("/srv/rootyard/workspaces/a/mnt"))
            .expect_err("stacked mounts are ambiguous in either ID order")
            .kind(),
        io::ErrorKind::InvalidData
    );
    // A single exact match is the owned identity.
    assert_eq!(ownership::mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/a/mnt-extra")).unwrap(), Some(38));
    // An absent path has no identity at all.
    assert_eq!(ownership::mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/a")).unwrap(), None);
    // mountinfo escapes whitespace octally; the comparison is on the path.
    assert_eq!(
        ownership::mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/with space/mnt")).unwrap(),
        Some(39)
    );
}

#[test]
fn owned_unmount_requires_the_captured_mount_id() {
    assert!(owns_current_mount(37, Some(37)));
    assert!(!owns_current_mount(37, Some(38)), "a newer mount at the path is not owned");
    assert!(!owns_current_mount(37, None), "an already unmounted path needs no unmount");
}
