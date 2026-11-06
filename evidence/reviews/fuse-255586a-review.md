# Independent FUSE review: 255586a

Cherry-picked `255586a` onto the isolated review stack based at `868ef14` (`b4ed03104688eae8c4a4f0c4e8ff0fa651168ec3`). Rebuilt native `rootyard-vfs-mount`; binary SHA-256 `c996cf319a2167a8a9e483e29c2661746ede2b8b9acb966b1cddb342574549a5`.

`python3 -m unittest tests.test_workspace_fuse -v` — PASS, 2/2 using real kernel FUSE in a user/mount namespace. The previously reported moved-symlink escape is rejected with `PermissionError`; CoW, concurrent reads, mmap, write, rename, and persistence across remount pass.

## Finding: whiteout control-file corruption

The reserved temporary name `.rootyard-whiteouts.tmp` is omitted by `readdir` but is accepted by `child()`. `save_whiteouts()` still uses path-based `fs::write(upper/.rootyard-whiteouts.tmp, ...)`, which follows a symlink. Native kernel reproduction at `/tmp/fuse_whiteout_repro.py`: create `lower/nested/special -> .rootyard-whiteouts.json`, mount, then rename `mount/nested/special` to `mount/.rootyard-whiteouts.tmp`. The rename passes link confinement; whiteout publication follows the temp symlink and then renames it over `.rootyard-whiteouts.json`, leaving the JSON path as a self-symlink. The source is hidden during the first mount but reappears after remount because `.exists()` follows the broken self-link and the whiteout set is discarded. This is reachable from repository-controlled lower-tree symlinks and corrupts persisted overlay state. Finding sent to workspace executor and root; fix pending re-review.

The mount remains partial for broader #30 acceptance: this pass validates the specific confinement and CoW behavior, not production cgroup delegation or all FUSE operations/locks.
