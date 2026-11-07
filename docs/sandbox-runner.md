# Sandbox runner

The sandbox service executes untrusted Agent and CI commands in Bubblewrap
user, PID, mount, IPC, UTS, network and cgroup namespaces. Every job has a
durable `sandbox_jobs` row, an independent workspace snapshot and its own
start/status/stop/cleanup lifecycle. Interactive jobs additionally expose an
authorized PTY (`terminal/input`, `terminal/output`, `terminal/resize`). The CI
surface binds jobs to a signed checkout claim so a job can only run for the
exact repository, pull candidate, attempt, lease generation and origin
checkout that the external runner claimed.

## Isolation boundary

Bubblewrap runs with `--unshare-all --die-with-parent --clearenv`. The job only
sees read-only `/usr`, `/bin`, `/lib` and `/lib64`, a private `/proc`, a minimal
`/dev`, private bounded `/tmp` and `/run`, a private `/home`, the job workspace
and a dedicated `/artifacts` export directory. The service environment is not
inherited: only `PATH`, `HOME` and `TMPDIR` are set, so database URLs, tokens,
signing secrets and runner configuration are not visible. There is no network
namespace route to the service or PostgreSQL, and the host Docker socket is
never mounted. User code waits behind a start gate until the job cgroup has
been attached, the durable row has been moved to `running`, the workspace lease
or CI claim has been revalidated in the same transaction, and the service has
flushed the gate file.

Artifacts are written to `/artifacts`, a per-job directory bind-mounted into the
sandbox. Export accepts a path relative to that directory and resolves it with
`openat2` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`,
so `..`, absolute paths, symlinks and magic links cannot reach the rest of the
job root or the service volume. Logs are a normal live product feature and can
be read while a job runs; artifact export requires an authenticated owner of the
workspace or the exact current CI claim tuple, a terminal state and no live
process. A superseded claim cannot read a new or old attempt. Files are bounded
at 16 MiB; logs are returned with explicit
`stdout_truncated`/`stderr_truncated` flags instead of failing the request.

## Production resource limits (cgroup mode)

`ROOTYARD_SANDBOX_MODE=cgroup` is required for untrusted production jobs. Set
`ROOTYARD_SANDBOX_CGROUP_ROOT` to a delegated cgroup v2 subtree owned by the
service account; the runner only creates and removes children of that subtree
and never writes the host root hierarchy. `cgroup.controllers` must expose
`cpu`, `memory` and `pids`, and **the same controllers must already be enabled
in `cgroup.subtree_control`** so job children receive `memory.max`, `pids.max`
and `cpu.max`. Reads of both files return bare controller names
(`cpu memory pids`); only writes use the `+cpu`/`-cpu` form. The subtree must
be a `domain` cgroup (not threaded) and the service account must be able to
write `cgroup.procs`, the limit files and `cgroup.kill`; otherwise the launch
fails closed with a `503` and no job process starts. Follow the cgroup v2
no-internal-process rule when provisioning: keep the delegated job root empty
and run the service supervisor in a leaf below it (or in a sibling owned by the
same service), because a non-root cgroup may not both contain processes and
delegate controllers to children.

Delegation can be unprivileged and that is the tested shape in
`scripts/native_kernel_cgroup_setup.sh`: root creates only
`/sys/fs/cgroup/rootyard-native-<run-id>`, enables `cpu`, `memory` and `pids`
for it, and `chown`s just the run root, its `cgroup.procs`,
`cgroup.subtree_control` and the `supervisor` leaf (plus that leaf's
`cgroup.procs`) to the ordinary runner UID/GID. The supervisor and the service
then run as that ordinary account, create their own job cgroups and move
themselves into the supervisor leaf; nothing above the run root is handed over
and no step runs the service as root. `supervisor <run-id> -- <command>` writes
its own `$$` into the leaf, proves the `/proc/self/cgroup` path equals the leaf,
checks that the run root still has no internal processes, and then `exec`s the
command in that same process, so the service and every sandbox job inherit the
leaf. A helper that moves a short-lived child and returns leaves the real test
process outside the cgroup; the native acceptance preflight rejects that (see
below). `cgroup.procs` is a pseudo file with `st_size` 0, so every emptiness
check reads the file content instead of using a size test.

Defaults (all overridable for an operator's deployment):

| Variable | Default | Meaning |
| --- | --- | --- |
| `ROOTYARD_SANDBOX_MEMORY_MAX` | `536870912` (512 MiB) | `memory.max` |
| `ROOTYARD_SANDBOX_PIDS_MAX` | `64` | `pids.max` |
| `ROOTYARD_SANDBOX_CPU_MAX` | `50000 100000` | `cpu.max` quota/period (50%) |
| `ROOTYARD_SANDBOX_WORKSPACE_MAX_BYTES` | `268435456` (256 MiB) | workspace tmpfs and workspace quota |
| `ROOTYARD_SANDBOX_TMP_MAX_BYTES` | `67108864` (64 MiB) | `/tmp` tmpfs |
| `ROOTYARD_SANDBOX_ARTIFACTS_MAX_BYTES` | `67108864` (64 MiB) | per-job artifact export quota |
| `ROOTYARD_SANDBOX_ARTIFACTS_POOL` | unset | required kernel-bounded tmpfs export pool in cgroup mode |
| `ROOTYARD_SANDBOX_ARTIFACTS_POOL_MAX_BYTES` | `268435456` (256 MiB) | maximum accepted pool mount size |
| `ROOTYARD_SANDBOX_MAX_ENTRIES` | `20000` | aggregated file-count quota per tree |
| `ROOTYARD_SANDBOX_RETENTION_SECONDS` | `3600` | terminal root retention before a startup sweep |

`memory.swap.max` is set to `0`. The writable workspace is a private tmpfs of
`ROOTYARD_SANDBOX_WORKSPACE_MAX_BYTES`, so a full disk is a real kernel
`ENOSPC`, not advisory accounting. cgroup v2 has no filesystem-space
controller, so artifacts need a kernel-bounded store: in cgroup mode the
deployment must point `ROOTYARD_SANDBOX_ARTIFACTS_POOL` at a service-owned
tmpfs mount whose total size is at most
`ROOTYARD_SANDBOX_ARTIFACTS_POOL_MAX_BYTES` (default 256 MiB). The service
verifies ownership, mode, mount type and mount size before any job starts and
fails closed with `503` otherwise. Only `tmpfs` is accepted: `ramfs` reports no
capacity and is rejected explicitly, and a normal host directory is never
accepted as a production export store. Each job gets its own `0700` directory in that pool
and the per-job walker enforces the stricter `ARTIFACTS_MAX_BYTES` and entry
quota at 750 ms intervals and again at terminal state. User files are also
capped by `RLIMIT_FSIZE` (16 MiB for user code after the baseline copy). A job
that exceeds a quota is stopped and recorded as `failed` with a bounded note in
its stderr log, even when the shell exited zero.

The job cgroup is killed with `cgroup.kill`, waited until `cgroup.procs` is
empty and removed. Cleanup failure is not swallowed: a terminal job logs the
incomplete reclamation, and startup recovery refuses to admit new work until it
can prove every stale job cgroup is empty and removed. The sweep never removes
a cgroup that is not named after one of its own job UUIDs. Exactly one active
service instance may own a delegated cgroup root; do not share
`ROOTYARD_SANDBOX_CGROUP_ROOT` between independent runner nodes or processes,
because startup recovery reaps every child of that subtree. Development mode
uses the job root for artifacts and therefore has only the walker (a soft
aggregate bound); that mode is explicitly not a production resource boundary.

Attachment of the process tree happens while user code is blocked in the start
gate. The Bubblewrap leader and every descendant are attached recursively and
the scan is repeated until it is stable, so descendants of the gate shell
inherit the constrained cgroup when they fork. A failed attachment, a missing
controller or a non-zero `pids.current` for an unattached namespace aborts the
launch.

## Development mode

`ROOTYARD_SANDBOX_MODE=dev` keeps the same namespace, gate, cancellation,
timeout, PTY, export and lifecycle paths for local tests, but the workspace is
a host directory and resource protection is per-process `RLIMIT_CPU`,
`RLIMIT_AS`, `RLIMIT_FSIZE` and `RLIMIT_NOFILE` plus the bounded workspace and
artifact walkers. It is **not** an aggregate production protection boundary
(for example it cannot account all descendants' memory or enforce a kernel
process limit), so it must not be used for untrusted production jobs.
`tests/test_sandbox_cgroup_native.py` is the opt-in native acceptance for the
production cgroup mode. It must be started through
`scripts/native_kernel_cgroup_setup.sh supervisor <run-id> -- python3
tests/test_sandbox_cgroup_native.py`, and its preflight fails when the test
process itself is not charged to the delegated run root. It exits `3` with a
preflight diagnosis only when the delegated subtree or the bounded tmpfs pool
is unavailable; that is an unexecuted acceptance, never a pass. Exit `1` is a
real failure, including a broken/unpinned `ROOTYARD_BINARY` or a native
assertion that failed.

## Lifecycle and recovery

- `POST /api/workspaces/{id}/sandbox-jobs` starts a job; `GET
  /api/sandbox-jobs/{id}` reports status; `POST /api/sandbox-jobs/{id}/stop`
  cancels; `GET /api/sandbox-jobs/{id}/logs` and `GET
  /api/sandbox-jobs/{id}/artifacts?path=...` export bounded results; `POST
  /api/sandbox-jobs/{id}/cleanup` removes retained logs and artifacts for a
  terminal job.
- The signed CI adapter exposes the same operations under
  `/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs`,
  authenticated by the webhook secret and the exact claim tuple.
- Cancellation, timeout and lease loss stop the process group and write a
  terminal result (`cancelled`, `timed_out`, `failed`). Runner startup proves
  the previous process tree is gone before marking a running job terminal: it
  verifies the recorded PID is still this job's Bubblewrap session leader (job
  root plus `bwrap` in `/proc/<pid>/cmdline`), kills every process group in that
  `setsid` session, and relies on kernel PID-namespace teardown for descendants
  that created their own session or double-forked. It then requires that no
  live process still references the exact job root. Any failure leaves the row
  non-terminal and aborts startup before new work is admitted. Stale job
  cgroups must be proven empty and removed for the same reason, and each
  transient workspace/checkout copy is reclaimed.
- Terminal jobs keep only bounded logs and artifacts. Startup sweeps terminal
  roots older than `ROOTYARD_SANDBOX_RETENTION_SECONDS` (default one hour), and
  an explicit cleanup request removes one root immediately.
- A retry is always a new execution attempt. A re-claimed CI run advances
  `attempt` and `lease_generation`, creates a new job id, and the previous
  attempt remains a terminal, fenced record that cannot be read with the new
  claim tuple. Restoring outputs from an old attempt under a new fence is
  therefore impossible by construction.

The native tests for this boundary are `tests/test_sandbox_service.py`,
`tests/test_ci_sandbox.py` and the opt-in
`tests/test_sandbox_cgroup_native.py`. They require a real PostgreSQL database
(`ROOTYARD_TEST_DATABASE_URL`), the real service binary
(`ROOTYARD_BINARY`), `bwrap`, `git` and `gcc`; they do not use a shared target
directory or simulate success.

## Native kernel acceptance workflow

`.github/workflows/native-kernel-acceptance.yml` is a manual
`workflow_dispatch` job, intentionally separate from ordinary push/pull_request
CI. It has no dispatch inputs, runs with `permissions: contents: read` and
`persist-credentials: false`, uses no repository secrets or provider API keys,
and has a bounded job timeout. Ordinary CI is unchanged: this workflow only
runs when an operator dispatches it.

- Runner image: `ubuntu-22.04`. Ubuntu 24.04 confines unprivileged user
  namespaces with AppArmor, which makes Bubblewrap fail on a stock runner and
  would produce a false BLOCKED. The supported targets are therefore the 22.04
  hosted VM or a dedicated ephemeral VM prepared for rootless `bwrap`; AppArmor
  is never weakened on the current managed cloud host, and that host is never
  modified by this repository.
- Toolchain: `bubblewrap`, `gcc`, `libc6-dev`, `git`, `python3`, `util-linux`
  plus `postgresql-client-17` installed from the official signed PGDG
  repository (`apt.postgresql.org`, key
  `/etc/apt/keyrings/postgresql.gpg`, suite `${VERSION_CODENAME}-pgdg`). The
  service is `postgres:17`, so the distributed clients (14/16) are not enough:
  the dev-roundtrip `pg_dump` must match the server major version.
  `/usr/lib/postgresql/17/bin` is put first on `PATH` with `GITHUB_PATH`; the
  acceptance runs as the ordinary runner account with no `sudo`/`runuser`
  wrapper, so that `PATH` reaches the test and its service unchanged, and the
  build step asserts `pg_dump --version` is 17.
- Source equivalence: the checkout step uses `persist-credentials: false`, the
  build step requires `git rev-parse HEAD == GITHUB_SHA` with a clean tree,
  builds with `cargo build --locked --bin rootyard`, and the receipt records
  both `source_commit` and `binary_sha256` (also written to
  `binary.sha256`). The receipt therefore pins which source was compiled and
  which binary ran; it never claims that a different commit produced an older
  hash. This fix commit changes only workflow/test/script/docs files, so `src/`
  and `Cargo.*` stay byte-identical to the qualified 4c28c39 tree and the
  reported binary hash is directly comparable with the preserved 4c28c39
  artifacts.
- Setup (root, bounded): `scripts/native_kernel_cgroup_setup.sh setup
  "$GITHUB_RUN_ID" "$(id -u)" "$(id -g)"` provisions only
  `/sys/fs/cgroup/rootyard-native-<run-id>` and delegates it to the runner
  account. A unique 64 MiB tmpfs (`size=64m,mode=0700,nodev,nosuid,noexec`) is
  mounted at `$RUNNER_TEMP/rootyard-native-pool-<run-id>`; the mount is
  root-owned `0700` by option, so the workflow `chown`s that one bounded mount
  path to the runner UID/GID and asserts owner and mode. The workflow then reads
  the real capacity with `statvfs` and exports it as
  `ROOTYARD_TEST_ARTIFACTS_POOL_MAX_BYTES`; that number is an acceptance
  threshold for the mounted capacity (asserted `> 0` and `<= 64 MiB`), not a
  logical quota pretending to be the physical bound. The test re-measures the
  mount, records `pool_capacity_bytes_measured` and configures the service with
  the measured value.
- Test execution (unprivileged): `scripts/native_kernel_cgroup_setup.sh
  supervisor "$GITHUB_RUN_ID" -- python3 tests/test_sandbox_cgroup_native.py
  --receipt "$RECEIPT"` runs as the ordinary runner account. The supervisor
  writes its own PID into the leaf, proves `/proc/self/cgroup` membership and
  `exec`s the test, so the service, Bubblewrap and every sandbox job are charged
  to the delegated subtree while the run root stays empty. The earlier
  dev-mode regression step was removed from this VM lane because the dev
  profile is already qualified locally; the native lane must execute the
  production `cgroup` profile, and the receipt validation rejects a passing
  receipt whose `profile` is not `cgroup` or whose actual `runner.uid` is 0.
- Database: one fresh database per dispatch
  (`rootyard_native_cgroup_<run_id>_<run_attempt>`), created and dropped with
  the PostgreSQL 17 client. Schemas are not shared with any other script.
- Failure classification: a setup/preflight that cannot be provided (no
  delegated cgroup v2 subtree, no writable parent `subtree_control`, no
  bounded tmpfs, or a test process that is outside the delegated subtree)
  produces a `blocked` receipt and exit `3`. A successful setup followed by a
  native assertion process that fails or writes no receipt is `failed` (exit
  `1`), never `blocked`. The workflow writes a sanitized fallback receipt for
  the no-receipt case, validates schema, commit, test-file hash, binary hash and
  runner identity, and the `if-no-files-found: error` upload plus the final
  enforce step fail the job for a missing receipt and for every status other
  than `passed`.

The native script writes a sanitized receipt to
`${RUNNER_TEMP}/native-kernel/receipt.json` and a copy to
`${RUNNER_TEMP}/native-kernel/evidence/` (outside the checkout). The uploaded
`native-kernel-cgroup-receipt-<run-id>` artifact contains the receipt, the
binary hash and the evidence directory. A pass requires every executed
assertion, collected from real kernel observations: supervisor cgroup
membership and live controls, cancellation and timeout reclamation, memory OOM,
`pids.max`, aggregate CPU quota, workspace `ENOSPC`, the measured bounded
artifact pool, cross-job build isolation and credential absence, logs/artifact
authorization, artifact/cgroup reclamation, service-crash descendant teardown
and stale-cgroup reaping, two real production CI checkouts that compile inside
their own cgroups, and a fenced retry executed as a new attempt.

Reclaim removes only the run-specific cgroup subtree (its own `cgroup.kill`
scoped to that subtree), that tmpfs mount, its files and the disposable
database; it never kills or removes the parent runner cgroup. The parent runner
cgroup is never written by `setup` beyond `rootyard-native-<run-id>` creation
and the root `cgroup.subtree_control` enable that cgroup v2 requires.

On the current managed development host there is no delegated cgroup v2
subtree (rootless Docker cgroup driver `none`, cgroupfs writes denied), so
positive local acceptance remains BLOCKED until the coordinator dispatches this
workflow on the supported VM. Local verification of this change is limited to
shell syntax, YAML parsing, Python byte-compilation and the existing target
Rust unit tests; it is not a substitute for the hosted run.
