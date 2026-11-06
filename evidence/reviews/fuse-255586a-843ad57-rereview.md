# FUSE confinement and whiteout re-review

Reviewed `255586a`, `1acabbb`, and `843ad57` in an isolated worktree based on `868ef14` (`9ccdd3962500e1a48e3833748c9fd635779446fc`). Built native `rootyard-vfs-mount`; binary SHA-256 `3af5a48c2e9601edb407ecafe40d9f14e55cd9097085cf4788ac7edc52f230e1`.

`python3 -m unittest tests.test_workspace_fuse -v` — PASS, 2/2 against actual kernel FUSE in a user/mount namespace. The first native test now includes both the moved `nested/up -> ..` escape and the whiteout-temp attack: both renames are rejected, no sibling escape file is created, whiteout metadata stays a regular file, and whiteout state survives unmount/remount. The transparent CoW, mmap, concurrent read, write, rename, and remount persistence checks also pass.

The earlier whiteout metadata corruption finding is fixed in `843ad57`: all `.rootyard-whiteouts.*` names are reserved from FUSE path lookup/rename, startup rejects symlink metadata, and whiteout state is published through a unique `O_EXCL|O_NOFOLLOW` temp entry followed by `renameat` and directory sync. No further escape or whiteout issue found in this pass.

This is still a focused FUSE acceptance slice for #30. It does not establish production cgroup delegation, lock support, or the full issue-level behavior beyond these tested kernel operations.
