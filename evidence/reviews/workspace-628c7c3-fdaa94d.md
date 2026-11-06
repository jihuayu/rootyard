# Independent workspace API / capture / sandbox review — 628c7c3 + fdaa94d

Reviewed by cherry-picking the exact executor commits into `/workspace/rootyard-review` as `ebc9c63` and `d5eaf45`.

## Tests actually run

- `source /workspace/shared/rootyard-env.sh; CARGO_TARGET_DIR=/workspace/rootyard-review/target cargo build --bin rootyard` — passed.
- `source /workspace/shared/rootyard-env.sh; python3 -m unittest tests.test_sandbox_service -v` — passed 1/1 against the native Rust HTTP server, PostgreSQL 17 and actual Bubblewrap jobs; covered isolation, logs, cancel, timeout.
- `source /workspace/shared/rootyard-env.sh; python3 -m unittest tests.test_workspaces_service -v` — passed 1/1 against native Rust/PostgreSQL; covered lifecycle, checkpoint/fork/restore/restart and editor change event.

## Findings

- **Sandbox child leak on registration failure:** `src/sandbox/runner.rs` spawns Bubblewrap before awaiting pool acquisition and updating `sandbox_jobs` to `running`. If either DB operation errors, `launch` returns before starting its monitor task. The handler marks the row `failed`, but the spawned child is not killed or reaped. Kill and wait on every post-spawn failure, with an injected DB error regression.
- **No aggregate resource bounds:** the sandbox binds a writable job workspace directly to host storage. `RLIMIT_FSIZE` limits each file to 16 MiB, not total bytes; `RLIMIT_AS` limits each process to 512 MiB, not total job memory; `RLIMIT_NPROC=1024` still permits high aggregate use. Arbitrary commands can exhaust shared volume or host memory. No cgroup/disk quota is available in this environment; keep this as an explicit safety acceptance gap.
- **Checkpoint copy is not snapshot-consistent under concurrent external edits:** workspace row lock serializes service API writers, but it does not fence editors. Comparing source fingerprint/index before and after `copy_all` can accept an ABA/mixed copy where the source returns to its original fingerprint after the copied files reflect intermediate values. A filesystem snapshot, external-writer lock, or equality check of the copied tree against both source scans is needed before claiming a point-in-time checkpoint.
- **Path traversal TOCTOU remains in native file operations:** `safe_file` checks components with `symlink_metadata`, then `atomic_put` uses path-based `create_dir_all`/`rename`; a concurrently replaced parent directory symlink can redirect the write. `core::copy_all` similarly walks paths and later opens them with `O_NOFOLLOW` only on the leaf, so an ancestor replacement may redirect a checkpoint read. Requires descriptor-based confinement or an explicit non-concurrency limitation; this is separate from the static symlink test for #2.

The workspace executor said it is adding post-spawn kill/reap and a captured-snapshot fingerprint comparison. Aggregate quotas remain unavailable and should remain an acceptance gap. Re-review fixes before approval.
