# Phase-five workspace foundation: local experiment

## Decision and scope

This opt-in binary is an executable semantics experiment, not a production Workspace API. It builds on phase-two GitFS baseline `373138a` without changing HTTP, database schema, repository ownership, refs authority, outbox or serving paths. Native GitFS remains authoritative for the hosting service. Nothing here depends on or silently switches to the experimental Pando backend.

A workspace contains a **complete independent copy** of native Git metadata and selected working files. Its starting full SHA-1 commit OID is fixed in metadata, even after local HEAD moves. Each agent receives its own `.git`, HEAD, index, refs, reflogs, objects and worktree. There are no hardlinks, shared alternates, reflinks or copy-on-write claims. An immutable-looking checkpoint directory is an operator convention, not a kernel-enforced security boundary.

Only Linux, case-sensitive local filesystems, ordinary files, internal relative symlinks and Unix execution bits are within scope. Agent names are labels, not authenticated identities. A store must be private (0700), owned and operated by a trusted single OS identity. **Do not expose this binary to untrusted users or untrusted repositories.** Use a dedicated empty store outside the source repository and outside the Git hosting data volume.

This is the first slice of phase five. Namespace revision is fixed to 1 with one repository per workspace. There is no virtual mount tree or multi-repository BaseVector yet. Native paths remain native paths; no FUSE, live capture, watcher, daemon, automatic `git add`, commit, push, remote storage or HTTP interface is introduced.

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
```

The store's parent must already exist. The tool creates the store itself with 0700 permissions if absent. Output is JSON with workspace/checkpoint UUIDs, base OID and repo path. IDs must be canonical UUIDs, not paths. `init` requires a normal independent `.git` directory and HEAD exactly equal to the supplied full base OID. It copies the current staged and unstaged state as well; it does not reset the source or implicitly check out a different commit. The source and store may not overlap. `restore` always creates a new workspace, never replaces an existing workspace. Forking means restoring the same completed local checkpoint under a new agent label.

Pass an absolute qualified Git executable in `ROOTYARD_WORKSPACE_GIT`, or the binary uses `git` from PATH. The exact Git version string is captured. Restore rejects a different version; cross-version migration has not been implemented. No server environment variables or database connection are required.

## Consistency contract

`--quiescent` is an explicit **caller assertion** that all editors, Git processes, build processes, background writers and open writable mappings are stopped until capture returns. The tool does not establish that condition. A store-wide advisory lock serializes this tool's operations only; it cannot fence other processes. A file-length change or Git lock is rejected where detected, but unchanged length, mtime or a successful scan does not prove a consistent instant. The lab therefore cannot offer strong checkpoint consistency for a live workspace.

Checkpoints return `state=local_complete`, `durability=local_filesystem_only` and `consistency=caller_quiescent`. They are deliberately **not** named `COMMITTED`, which the full design reserves for complete remotely persisted dependencies and metadata publication. No cross-node recovery, power-loss RPO or production crash-safety claim follows from these local tests.

A local checkpoint captures:

- The current HEAD, including symbolic or detached form; independent fixed starting base OID remains in workspace metadata.
- The original index bytes, including partial staging, conflict stages 1/2/3, intent-to-add and resolve-undo state. It never uses `write-tree` as a substitute for an unmerged index.
- Complete supported `.git` contents, including local refs, reflogs, merge/rebase/cherry-pick/sequencer data and objects. This intentionally copies more history than the current commit alone.
- Raw worktree bytes, symlink targets, deletion absence and ordinary permission bits. Worktree bytes are not reconstructed from index blobs or a diff.

Managed worktree paths are the union of HEAD tree paths, every index stage's paths and Git's untracked/nonignored paths. Native `git ls-files --others --exclude-standard` implements ignore hierarchy and negation. A tracked file remains managed under an ignored parent. `git add -f` promotes a path via the index. `git rm --cached` leaves it managed through HEAD until the deletion is committed. Ignored untracked data remains in the original live workspace, but is excluded from init copies, checkpoints and forks. Ignore changes do not remove local files or rewrite older snapshots. Empty directories are not captured.

Global/system Git configuration and global excludes/attributes are disabled for deterministic behavior. Repository `.gitignore` and `.git/info/exclude` apply. This is a deliberate narrower environment, not a claim to reproduce arbitrary user-global ignore policy. Restoring raw index bytes to newly created inodes invalidates ordinary stat observations. Optional Git lock/refresh writes are disabled while observing; unsupported index caches are rejected instead of being silently dropped.

## Publication, integrity and recovery

Layout:

```text
store/
  .lock
  workspaces/<uuid>/workspace.json
  workspaces/<uuid>/repo/
  checkpoints/<uuid>/manifest.json
  checkpoints/<uuid>/manifest.sha256
  checkpoints/<uuid>/repo/
  staging/<uuid>/
```

A checkpoint is built in staging, ordinary files are individually fsynced, directory trees are fsynced, and the complete directory is renamed into `checkpoints/`, followed by parent-directory fsync. Restore checks manifest identity/state/version, manifest SHA-256, exact file inventory, every file/symlink hash, mode and size, native Git object integrity, index format and base OID before publication of a new workspace. Missing, modified or unexpected files fail closed. Destination copies are rechecked against the captured inventory before publication. This is corruption detection, **not** cryptographic authentication against an attacker who can rewrite both manifest and hashes.

A process exit before rename cannot publish a partial checkpoint. Staging debris is never used as a recovery root and can be inspected by the operator before manual cleanup. An exit after rename may leave a completed checkpoint even though no response was returned. Check `checkpoints/` and validate/restore its ID before retrying; absence of a success response does not prove absence of publication. There is no latest pointer to regress, no checkpoint garbage collector, no automatic cleanup and no cross-store transaction. A failure to fsync after rename is reported as an uncertain publication result with the affected path.

Laboratory-only `ROOTYARD_WORKSPACE_TEST_FAILPOINT=before_publish` / `after_publish` exits with code 86 / 87 during checkpoint publication. It is not consulted on the production server path. Tests exercise process boundaries; they do not cut power, crash the VM or validate storage-controller durability.

## Safety and compatibility limits

- `.git` files, `.git` symlinks, linked worktrees, object alternates, Git-internal symlinks, submodules, shallow clones, replacement refs and grafts are rejected. Source hardlinks are read as bytes and broken into independent destination files.
- Worktree symlinks must be relative and stay within the repository after component-by-component symlink-chain resolution, outside `.git`. They are never followed during copy/hash. This does not turn a workspace into an execution sandbox; arbitrary code running as the same OS user can access other files.
- Git metadata locks cause a busy error. The tool never deletes them or guesses whether an interrupted operation is safe to rerun. Quiescent merge conflicts are supported and retain their state.
- SHA-1 repositories with an initial commit are supported. Unborn HEAD and SHA-256 are rejected for now. Native index v2/v3 is accepted, with TREE/REUC extensions only. Split index, sparse checkout/index, skip-worktree, fsmonitor, untracked cache and unknown extensions are rejected.
- Local Git config is allowlisted: repository format 0, nonbare, native filemode/logallrefupdates, case-sensitive paths, non-precomposed paths, user name/email and native line-ending options. Remotes, credential settings, includes, executable filters, external hooks and other configuration are rejected rather than copied without review. Custom hooks are rejected; inert sample hooks can be copied. Attributes requesting filters/LFS are not supported.
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

The real-Git harness covers independent agent forks, partial staging, true merge conflict recovery, intent-to-add, ignore/add-f/rm-cached behavior, deletion/rename, raw names and symlinks, executable files, fixed base, damage rejection and pre/post-publication process exits. The exact executed checks and Git version are in its report and the [verification record](workspace-verification.md); passing this suite does not pass the full fifth-phase release gates.

Remaining work includes controlled process admission and complete write barriers, tenant/agent authorization, namespace mounts and BaseVector, remote object/metadata commit and retention, resumable capture and outbox, supported Git-operation policy, capability negotiation, permissions and adversarial path audits, loss-of-power tests, scale measurements and integration with the chosen authoritative backend. Keep those interfaces out of the hosting service until their contracts and tests are ready.
