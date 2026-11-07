# Phase-five workspace foundation: local experiment

## Decision and scope

This opt-in binary is an executable semantics experiment, not a production Workspace API. It builds on phase-two GitFS baseline `373138a` without changing HTTP, database schema, repository ownership, refs authority, outbox or serving paths. Native GitFS remains authoritative for the hosting service. Nothing here depends on or silently switches to the experimental Pando backend.

A workspace contains a **complete independent copy** of native Git metadata and selected working files. Its starting full SHA-1 commit OID is fixed in metadata, even after local HEAD moves. Each agent receives its own `.git`, HEAD, index, refs, reflogs, objects and worktree. There are no hardlinks, shared alternates, reflinks or copy-on-write claims. An immutable-looking checkpoint directory is an operator convention, not a kernel-enforced security boundary.

Only Linux, case-sensitive local filesystems, ordinary files, internal relative symlinks and Unix execution bits are within scope. Agent names are labels, not authenticated identities. A store must be private (0700), owned and operated by a trusted single OS identity. **Do not expose this binary to untrusted users or untrusted repositories.** Use a dedicated empty store outside the source repository and outside the Git hosting data volume.

This laboratory spans single-repository workspace primitives, Phase-5 Track D cross-node remote CAS and multi-repository Namespace extensions (`push-remote`, `pull-remote`, `namespace-mount`, `verify-namespace`, `namespace-git-view`), Phase-5 Track 3 on-demand VFS mounts (`vfs-mount`, `vfs-hydrate`, `vfs-status`, `vfs-evict`), writable namespace reverse-mapping and agent leases (`agent-lease`, `namespace-write`, `namespace-commit-back`), and Phase-5 Track 4 Copy-on-Write overlay sandboxes and power-loss crash recovery (`overlay-mount`, `overlay-op`, `overlay-write`, `overlay-delete`, `overlay-rename`, `overlay-chmod`, `overlay-git-add-f`, `overlay-status`, `crash-drill`, `crash-recover`). Native paths remain native paths; no FUSE, live capture, watcher, daemon, automatic `git add`, commit, push, or HTTP interface is introduced.

## Commands

Build explicitly so the production server invocation remains unambiguous:

```sh
cargo build --locked --bin rootyard-workspace-lab
export ROOTYARD_WORKSPACE_GIT=/absolute/path/to/qualified/git
LAB=target/debug/rootyard-workspace-lab
BASE=$(git -C /path/to/trusted/source rev-parse HEAD)
$LAB init /private/workspace-store /path/to/trusted/source agent-one "$BASE" --quiescent
$LAB checkpoint /private/workspace-store WORKSPACE_UUID --quiescent
$LAB restore /private/workspace-store CHECKPOINT_UUID agent-two
$LAB inspect /private/workspace-store WORKSPACE_UUID
$LAB status /private/workspace-store WORKSPACE_UUID
$LAB changeset /private/workspace-store BASE_CHECKPOINT_UUID SOURCE_CHECKPOINT_UUID
$LAB apply /private/workspace-store WORKSPACE_UUID CHANGESET_UUID --quiescent
$LAB sync-dirty /private/workspace-store SOURCE_WORKSPACE_UUID [TARGET_WORKSPACE_UUID] --quiescent
$LAB verify-readonly-view /private/workspace-store CHECKPOINT_UUID [VIEW_PATH]
$LAB push-remote /private/workspace-store WORKSPACE_OR_CHECKPOINT_UUID /private/remote-cas [--quiescent]
$LAB pull-remote /private/workspace-store /private/remote-cas CHECKPOINT_UUID agent-three
$LAB namespace-mount /private/workspace-store NAMESPACE_NAME apps/payments=CHECKPOINT_UUID_1 libs/common=CHECKPOINT_UUID_2
$LAB verify-namespace /private/workspace-store NAMESPACE_UUID [VIEW_PATH]
$LAB namespace-git-view /private/workspace-store NAMESPACE_UUID [VIEW_PATH]
$LAB vfs-mount /private/workspace-store CHECKPOINT_UUID agent-four [--remote-cas /private/remote-cas] [--inline-threshold 4096] [--hydrate-pattern "src/**"]
$LAB vfs-hydrate /private/workspace-store VFS_UUID "assets/*.bin" [--cow-write CONTENT_OR_FILE] [--prewarm]
$LAB vfs-status /private/workspace-store VFS_UUID
$LAB vfs-evict /private/workspace-store VFS_UUID "assets/*.bin" [--quiescent] [--skip-dirty]
$LAB overlay-mount /private/workspace-store CHECKPOINT_UUID agent-five [--remote-cas /private/remote-cas]
$LAB overlay-op /private/workspace-store OVERLAY_UUID <write|delete|rename|chmod|git-add-f|status> [ARGS...]
$LAB overlay-write /private/workspace-store OVERLAY_UUID src/lib.rs "updated content"
$LAB overlay-delete /private/workspace-store OVERLAY_UUID obsolete.txt
$LAB overlay-rename /private/workspace-store OVERLAY_UUID src/old.rs src/new.rs
$LAB overlay-chmod /private/workspace-store OVERLAY_UUID bin/run.sh 0755
$LAB overlay-git-add-f /private/workspace-store OVERLAY_UUID build/forced.out
$LAB overlay-status /private/workspace-store OVERLAY_UUID
$LAB crash-drill /private/workspace-store TARGET_UUID <before_wal_fsync|after_wal_before_publish|after_publish_before_ack|index_update_interrupted> [--quiescent]
$LAB crash-recover /private/workspace-store TARGET_UUID
```

The store's parent must already exist. The tool creates the store itself with 0700 permissions if absent. Output is JSON with workspace/checkpoint UUIDs, base OID and repo path. IDs must be canonical UUIDs, not paths. `init` requires a normal independent `.git` directory and HEAD exactly equal to the supplied full base OID. It copies the current staged and unstaged state as well; it does not reset the source or implicitly check out a different commit. The source and store may not overlap. `restore` always creates a new workspace, never replaces an existing workspace. Forking means restoring the same completed local checkpoint under a new agent label. `status` reports clean/dirty state, staged/unstaged/untracked/unmerged paths, `.gitignore`/`.rootyardignore` classification, and SHA-256 `dirty_entries`. `changeset` computes an ordered checkpoint-to-checkpoint delta (`changesets/<uuid>/changeset.json` and `.sha256`), `apply` atomically applies a changeset with pre-flight conflict detection failing closed on any target divergence, `sync-dirty` incrementally synchronizes dirty managed files while excluding ignored files, and `verify-readonly-view` projects and validates immutable read-only (`mode & 0o555`) checkpoint views and detects tampering. `push-remote` and `pull-remote` synchronize local checkpoints and dirty-file manifests with a content-addressed remote store (`blobs/<sha256[0..2]>/<sha256>`) for cross-node workspace recovery. `namespace-mount`, `verify-namespace`, and `namespace-git-view` mount non-overlapping checkpoints under a pinned multi-repository `BaseVector`, verify read-only virtual namespace trees without upper `.git` directories, and project deterministic `task_snapshot` Git repositories passing `git clone` and `git fsck --full --strict`. `vfs-mount` builds a lazy sparse virtual workspace mount (`vfs/<uuid>/vfs.json`, `vfs.sha256`, and `mount/`) from a local or remote CAS checkpoint, materializing `.git` metadata and small or pattern-matched files (`--inline-threshold`, `--hydrate-pattern`) while keeping unaccessed large files `dehydrated`. `vfs-hydrate` transparently pulls and verifies (`O_NOFOLLOW`, SHA-256, and byte size) dehydrated blobs on demand, before Copy-on-Write modification (`--cow-write`), or during batch offline prewarm (`--prewarm`). `vfs-status` classifies entries into `dehydrated`, `hydrated_clean`, and `hydrated_dirty` while respecting `.gitignore` and `.rootyardignore` and reporting byte savings (`unhydrated_bytes`). `vfs-evict` reclaims disk space by dehydrating `hydrated_clean` files while strictly protecting `hydrated_dirty` Copy-on-Write files against eviction (failing closed with a conflict error unless `--skip-dirty` is passed). `overlay-mount` creates a Copy-on-Write overlay sandbox (`overlays/<uuid>/overlay.json`, `overlay.sha256`, read-only `lower/`, writable delta `upper/`, and projected `merged/`) with strict `(st_dev, st_ino)` isolation across lower, upper, merged, and sibling agent overlays. `overlay-op` (and direct aliases `overlay-write`, `overlay-delete`, `overlay-rename`, `overlay-chmod`, `overlay-git-add-f`, `overlay-status`) performs Copy-on-Write writes, whiteout tombstone deletions, `EXDEV` cross-layer copy-up renames, permission updates, and synchronous `git add -f` promotion of `.gitignore`/`.rootyardignore` files into `managed_paths` and `staged_paths`. `crash-drill` and `crash-recover` exercise deterministic power-loss and process-kill windows (`before_wal_fsync`, `after_wal_before_publish`, `after_publish_before_ack`, `index_update_interrupted`) backed by a checksummed WAL (`crash_journal.json` and `crash_journal.sha256`), truncating corrupt un-fsynced WAL tails, replaying committed WAL records idempotently, purging `.tmp-*` debris and stale `.git/index.lock` files, reporting `unsynced_paths`, and verifying post-recovery `git status` and `git fsck --full --strict`.

Pass an absolute qualified Git executable in `ROOTYARD_WORKSPACE_GIT`, or the binary uses `git` from PATH. The exact Git version string is captured. Restore rejects a different version; cross-version migration has not been implemented. No server environment variables or database connection are required.

## Consistency contract

`--quiescent` is an explicit **caller assertion** that all editors, Git processes, build processes, background writers and open writable mappings are stopped until capture returns. The tool does not establish that condition. A store-wide advisory lock serializes this tool's operations only; it cannot fence other processes. A file-length change or Git lock is rejected where detected, but unchanged length, mtime or a successful scan does not prove a consistent instant. The lab therefore cannot offer strong checkpoint consistency for a live workspace.

Local-only checkpoints return `state=local_complete`, `durability=local_filesystem_only` and `consistency=caller_quiescent`. When `push-remote` persists a checkpoint to a content-addressed remote store (`REMOTE_CAS_DIR`), every referenced content blob and `dirty_manifest.json` are written via `.tmp-<uuid>`, `O_NOFOLLOW`, `fsync`, and read-back SHA-256 + byte-size verification before publishing `checkpoints/<uuid>/manifest.json` with `state=COMMITTED` and `durability=remote_cas_committed`, enabling `pull-remote` cross-node workspace restore.

A local checkpoint captures:

- The current HEAD, including symbolic or detached form; independent fixed starting base OID remains in workspace metadata.
- The original index bytes, including partial staging, conflict stages 1/2/3, intent-to-add and resolve-undo state. It never uses `write-tree` as a substitute for an unmerged index.
- Complete supported `.git` contents, including local refs, reflogs, merge/rebase/cherry-pick/sequencer data and objects. This intentionally copies more history than the current commit alone.
- Raw worktree bytes, symlink targets, deletion absence and ordinary permission bits. Worktree bytes are not reconstructed from index blobs or a diff.

Managed worktree paths are the union of HEAD tree paths, every index stage's paths and Git's untracked/nonignored paths that are also not excluded by `.rootyardignore`. Native `git ls-files --others --exclude-standard` together with hierarchical `.rootyardignore` evaluation implements ignore hierarchy and `!` negation. A tracked file remains managed under an ignored parent or matching `.rootyardignore`. `git add -f` promotes a path via the index. `git rm --cached` leaves it managed through HEAD until the deletion is committed. Ignored untracked data remains in the original live workspace, but is excluded from init copies, checkpoints, forks and `sync-dirty`. Ignore changes do not remove local files or rewrite older snapshots. Empty directories are not captured.

Global/system Git configuration and global excludes/attributes are disabled for deterministic behavior. Repository `.gitignore`, `.git/info/exclude`, and `.rootyardignore` apply. This is a deliberate narrower environment, not a claim to reproduce arbitrary user-global ignore policy. Restoring raw index bytes to newly created inodes invalidates ordinary stat observations. Optional Git lock/refresh writes are disabled while observing; unsupported index caches are rejected instead of being silently dropped.

## Publication, integrity and recovery

Layout:

```text
store/
  .lock
  workspaces/<uuid>/workspace.json
  workspaces/<uuid>/crash_journal.json
  workspaces/<uuid>/crash_journal.sha256
  workspaces/<uuid>/repo/
  checkpoints/<uuid>/manifest.json
  checkpoints/<uuid>/manifest.sha256
  checkpoints/<uuid>/repo/
  changesets/<uuid>/changeset.json
  changesets/<uuid>/changeset.sha256
  changesets/<uuid>/files/
  views/<uuid>/repo/
  namespaces/<uuid>/namespace.json
  namespaces/<uuid>/namespace.sha256
  namespaces/<uuid>/tree/<mount_path>/
  namespaces/<uuid>/git-view/repo/
  vfs/<uuid>/vfs.json
  vfs/<uuid>/vfs.sha256
  vfs/<uuid>/mount/
  overlays/<uuid>/overlay.json
  overlays/<uuid>/overlay.sha256
  overlays/<uuid>/crash_journal.json
  overlays/<uuid>/crash_journal.sha256
  overlays/<uuid>/lower/
  overlays/<uuid>/upper/
  overlays/<uuid>/merged/
  staging/<uuid>/

remote-cas/
  blobs/<sha256[0..2]>/<sha256>
  checkpoints/<uuid>/dirty_manifest.json
  checkpoints/<uuid>/dirty_manifest.sha256
  checkpoints/<uuid>/manifest.json
  checkpoints/<uuid>/manifest.sha256
```

A checkpoint is built in staging, ordinary files are individually fsynced, directory trees are fsynced, and the complete directory is renamed into `checkpoints/`, followed by parent-directory fsync. Restore checks manifest identity/state/version, manifest SHA-256, exact file inventory, every file/symlink hash, mode and size, native Git object integrity, index format and base OID before publication of a new workspace. Missing, modified or unexpected files fail closed. Destination copies are rechecked against the captured inventory before publication. This is corruption detection, **not** cryptographic authentication against an attacker who can rewrite both manifest and hashes.

A process exit before rename cannot publish a partial checkpoint. Staging debris is never used as a recovery root and can be inspected by the operator before manual cleanup. An exit after rename may leave a completed checkpoint even though no response was returned. Check `checkpoints/` and validate/restore its ID before retrying; absence of a success response does not prove absence of publication. There is no latest pointer to regress, no checkpoint garbage collector, no automatic cleanup and no cross-store transaction. A failure to fsync after rename is reported as an uncertain publication result with the affected path.

Laboratory-only `ROOTYARD_WORKSPACE_TEST_FAILPOINT=before_publish` / `after_publish` exits with code 86 / 87 during checkpoint publication. It is not consulted on the production server path. Tests exercise process boundaries; they do not cut power, crash the VM or validate storage-controller durability.

## Support matrix: lab preflight versus production Workspace API

This round adds one narrow thing: the `init` admission checks of the **local lab binary** now run before the store is opened, so a refused source cannot create a store directory, `.lock`, staging directory or destination UUID directory. It is an early-rejection boundary, not a new feature implementation.

| Area | Local lab binary (`rootyard-workspace-lab`), this stage | Production Workspace API, this stage |
| --- | --- | --- |
| Admission order | Argument checks, source/store overlap, repository validation, managed `.gitattributes` filter check and managed symlink check all run **before** `Store::open`; the same checks plus capture re-run afterwards because a source may change in between | No workspace-API admission preflight has been added. Nothing here is wired into HTTP, serving or database paths |
| Repository object format | Independent **SHA-1** repositories only. SHA-256 is explicitly **rejected**; no SHA-256 support was added | No SHA-256 path exists. The raw-byte checkpoint of a repository is not a claim that a SHA-256 object chain is supported end to end |
| Index formats | Index **v2/v3** with `TREE`/`REUC` extensions only. Split index, sparse index, skip-worktree, fsmonitor, untracked cache and unknown extensions are rejected | Not verified. A raw-byte checkpoint copies index bytes without validating or closing these formats |
| Git shape | Independent native `.git` directory only. `.git` files, linked worktrees, shared worktree admin, submodules (`.git/modules`), external object alternates, shallow clones, grafts, replacement refs and custom hooks are rejected | Not covered. The API checkpoint is a byte-level capture, not a compatibility verdict for linked worktrees, submodules or alternates |
| Filters and LFS | Any managed `.gitattributes` mentioning `filter`, and `.git/info/attributes` mentioning `filter`, are rejected (no clean/smudge/LFS execution). LFS is **not** implemented | No filter execution path is introduced; LFS content is not implemented or claimed |
| Symlinks | Managed worktree symlinks must be relative, stay inside the repository and never target `.git`; the check now runs before the store exists. Link targets are read with `read_link`; no target content is opened and no external symlink is followed | Not verified by this stage |
| Ignore semantics | `.gitignore` plus hierarchical `.rootyardignore` decide which untracked paths are managed; unmanaged attribute files and unmanaged escaping symlinks are deliberately **not** newly rejected | Not applicable yet |
| Consistency and recovery | Local `local_complete` checkpoints under a caller `--quiescent` promise; local filesystem durability only; no write barrier, no remote recovery claim | The current API checkpoint stores raw bytes. That raw-byte checkpoint does **not** mean these states are closed, admission-checked or remotely recoverable, and the API does **not** inherit the lab rejection matrix above |
| Feature enablement | Every unsupported shape stays explicitly refused | No submodule, LFS, linked-worktree or SHA-256 support is implemented or advertised |

Consequences for `#88`, which is not finished by this stage:

- A **production API** admission preflight still has to be designed and accepted; the lab preflight only protects the lab CLI.
- **SHA-256 end-to-end** (objects, index, manifests, remote CAS, restore) is still unimplemented; the lab keeps rejecting SHA-256 repositories.
- Feature enablement stays **item by item**: submodule, LFS/filter, linked-worktree and sparse/split index support each need their own closure contract and evidence. This stage only refuses them earlier and defines the real compatibility boundary.

## Safety and compatibility limits

- `.git` files, `.git` symlinks, linked worktrees, shared worktree administration, object alternates, Git-internal symlinks, submodules, shallow clones, replacement refs and grafts are rejected. `init` refuses them **before** opening or creating the store, so no store, lock, staging or destination directory appears for a refused source. Source hardlinks are read as bytes and broken into independent destination files.
- Worktree symlinks must be relative and stay within the repository after component-by-component symlink-chain resolution, outside `.git`. The same rule is applied to managed symlinks by the read-only `init` preflight before any store exists, reusing `validate_symlink`, so an absolute, escaping or `.git`-targeting link no longer needs a created store to be refused. Link targets are never followed during preflight, copy or hash. This does not turn a workspace into an execution sandbox; arbitrary code running as the same OS user can access other files.
- Git metadata locks cause a busy error. The tool never deletes them or guesses whether an interrupted operation is safe to rerun. Quiescent merge conflicts are supported and retain their state.
- SHA-1 repositories with an initial commit are supported. Unborn HEAD and SHA-256 are rejected for now. Native index v2/v3 is accepted, with TREE/REUC extensions only. Split index, sparse checkout/index, skip-worktree, fsmonitor, untracked cache and unknown extensions are rejected.
- Local Git config is allowlisted: repository format 0, nonbare, native filemode/logallrefupdates, case-sensitive paths, non-precomposed paths, user name/email and native line-ending options. Remotes, credential settings, includes, executable filters, external hooks and other configuration are rejected rather than copied without review. Custom hooks are rejected; inert sample hooks can be copied. Attributes requesting filters/LFS are not supported; the `init` preflight refuses such managed `.gitattributes` files before the store exists and `capture` re-checks them. Attribute files or symlinks that `.gitignore`/`.rootyardignore` keep unmanaged are not newly refused.
- Special files such as sockets/FIFOs/device nodes cannot be managed checkpoint entries. Setuid/setgid/sticky file bits are rejected. Empty directories, xattrs, ACLs, ownership, file times, filesystem locks, open descriptors and running processes are not restored.
- Up to 100,000 file entries, 1 GiB of regular-file bytes and 64 MiB manifest/index metadata are admitted. These are prototype bounds, not filesystem quotas, child CPU/RSS limits or a performance SLA. No adversarial Git-process sandbox, resource watchdog or multi-tenant authorization is provided.
- Copies and checkpoints include repository history and reflogs. Ignore rules and hidden refs do not hide that history or protect secrets. Do not import real credentials or confidential fixtures into this lab.

## Tests and next gates

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --bin rootyard-workspace-lab
python3 tests/workspaces.py --binary target/debug/rootyard-workspace-lab --report test-results/workspaces.json
```

The real-Git harness covers independent agent forks, partial staging, true merge conflict recovery, intent-to-add, ignore/add-f/rm-cached behavior, deletion/rename, raw names and symlinks, executable files, fixed base, damage rejection and pre/post-publication process exits. It also asserts, with a fresh non-existent store path per case, that rejected `init` calls leave the source bytes, refs and index unchanged and create no store, staging or destination directory, using real `git worktree add`, a real local `git submodule add`, tracked `filter=lfs` attributes, ordinary sparse checkout, split index, shared-clone alternates, a SHA-256 repository and managed absolute/escaping/`.git`-targeting symlinks, together with no-false-rejection cases for unmanaged attribute files and symlinks. The exact executed checks and Git version are in its report and the [verification record](workspace-verification.md); passing this suite does not pass the full fifth-phase release gates.

Remaining work includes controlled process admission and complete write barriers, tenant/agent authorization, namespace mounts and BaseVector, remote object/metadata commit and retention, resumable capture and outbox, supported Git-operation policy, capability negotiation, permissions and adversarial path audits, loss-of-power tests, scale measurements and integration with the chosen authoritative backend. Keep those interfaces out of the hosting service until their contracts and tests are ready.
