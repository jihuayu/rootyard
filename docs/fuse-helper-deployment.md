# Independent FUSE helper deployment: mount ownership and AutoUnmount

The `fuse-helper` workspace mount mode runs one helper process per host. The
helper owns every FUSE descriptor it mounts; the API parent only speaks the
length-prefixed control protocol over a Unix socket and never receives a
`/dev/fuse` descriptor. That is the whole point of the mode: no process other
than the helper can keep a mount alive, and nothing outside the helper unmounts
on its behalf.

## What changed

Helper mounts now pass `MountOption::AutoUnmount` (`fuse_mount::spawn_helper`).
With `fuser` 0.16 on Linux this uses the pure-Rust `fusermount3` path: `fuser`
keeps the fusermount monitor socket inside its session/mount object, so when the
helper dies (including `SIGKILL`, which runs no destructor) the kernel closes the
last FUSE descriptor and that socket together, and `fusermount3` unmounts exactly
the mount it created. No `umount` from the API parent or from a test harness is
involved.

The option list is intentionally not widened:

* `AllowOther`/`AllowRoot` are **not** added. `fuser` implicitly adds
  `allow_other` on the *fusermount command line* because `auto_unmount` needs it,
  but it derives `SessionACL` from the options it was given, so the session stays
  `SessionACL::Owner`.
* `DefaultPermissions` stays enabled; userspace/kernel permission checks are not
  disabled.
* The legacy in-process mount (`fuse`) and the lab mount keep their historical
  option list without `AutoUnmount`, so an existing deployment is not silently
  switched onto the `fusermount3` path.

## Qualification (host policy)

`AutoUnmount` is a host capability, not a switch this service can grant itself:

* `fusermount3` must be installed and executable (`util-linux` `unshare` for the
  namespaced shape).
* The caller must be allowed to use `auto_unmount`/`allow_other`.
* The supported shape for a conventionally non-root host is a private user and
  mount namespace entered as namespace root, i.e. `unshare -Urm --propagation
  private`, which is the shape `tests/fuse_helper_lifecycle.py` targets. CI
  preflight requires `fuse3`/`fusermount3` and `unshare`.
* A conventional non-root host *without* that wrapper is **not qualified** and
  may additionally need `user_allow_other` in the host `/etc/fuse.conf`. That
  scenario is pending native qualification.

Hard rules:

* This service never edits a global `fuse.conf` and never changes LSM
  (AppArmor/SELinux) policy.
* No unsupported rootless guarantee is implied by this change.

## Verification status

`tests/fuse_helper_lifecycle.py` now asserts, for both the direct helper
`SIGKILL` case and the external RPC parent-stub `SIGKILL` case:

1. the exact owned mount IDs are captured while the mounts are live,
2. after the owner is confirmed dead and the queued writer has terminated, those
   IDs must disappear within a bounded time **before** the normal owned cleanup
   backstop, and
3. a fresh helper must mount, read and write the same workspace UUID path again.

This is the AutoUnmount contract on a qualified environment; it is not an
assumption that any killed FUSE mount disappears, and the cleanup backstop is
never used as evidence for it.

These assertions were written without running the harness: compilation and all
native execution belong to the root workflow. This document makes no claim that
CI has already executed the helper, and the legacy in-process mount path must
never be reported as evidence for the helper cleanup contract.

## Known limitations

* The production API client's own abrupt-death (`SIGKILL`) semantics are not
  covered by the lifecycle harness; it uses an external RPC parent stub, so no
  API-client signal/cleanup guarantee is claimed.
* The `ROOTYARD_TEST_FUSE_BACKEND=fuse-helper` API-level selector in
  `tests/test_workspace_fuse_service.py` is provided for the root workflow; the
  default `fuse` selector exercises only the legacy in-process mount.
* Mounts created by a helper build older than this change carry no
  `AutoUnmount`; they keep their previous cleanup behaviour until remounted.
