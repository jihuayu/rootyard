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
`cpu`, `memory` and `pids`, and the subtree must allow the service to write
`cgroup.procs`, the limit files and `cgroup.kill`; otherwise the launch fails
closed with a `503` and no job process starts.

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
tmpfs/ramfs mount whose total size is at most
`ROOTYARD_SANDBOX_ARTIFACTS_POOL_MAX_BYTES` (default 256 MiB). The service
verifies ownership, mode, mount type and mount size before any job starts and
fails closed with `503` otherwise; a normal host directory is never accepted as
a production export store. Each job gets its own `0700` directory in that pool
and the per-job walker enforces the stricter `ARTIFACTS_MAX_BYTES` and entry
quota at 750 ms intervals and again at terminal state. User files are also
capped by `RLIMIT_FSIZE` (16 MiB for user code after the baseline copy). A job
that exceeds a quota is stopped and recorded as `failed` with a bounded note in
its stderr log, even when the shell exited zero.

The job cgroup is killed with `cgroup.kill`, waited until `cgroup.procs` is
empty and removed. Cleanup failure is not swallowed: a terminal job logs the
incomplete reclamation, and startup recovery refuses to admit new work until it
can prove every stale job cgroup is empty and removed. The sweep never removes
a cgroup that is not named after one of its own job UUIDs. Development mode
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
production cgroup mode. It exits `3` with a preflight diagnosis when no
delegated cgroup subtree is available; that is an unexecuted acceptance, never
a pass.

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
