# CI acceptance: per-pull-request regressions and the candidate release gate

Two layers cover the native acceptance suites. Neither layer replaces the
specialised cgroup VM gate in `.github/workflows/native-kernel-acceptance.yml`.

## Layer 1 — every pull request and every push to `main` (`.github/workflows/ci.yml`)

The verify job runs on a plain `ubuntu-22.04` host, not in the former
`rust:1-trixie` container. That is the same host profile on which the manual
native-kernel-acceptance workflow passed its 17 assertions (run 42410286276):
an unprivileged runner, host PID 1 adopting and reaping orphaned Git
grandchildren, a usable `/dev/fuse`, and unprivileged `unshare -Urnm`. The
PostgreSQL 17 service is published on the host at the fixed loopback address
`127.0.0.1:55432`; it keeps an ephemeral CI-only password and is never a
repository secret.

`scripts/install_ci_native_tools.sh` prepares the profile and then proves it
functionally before any test runs:

* PostgreSQL 17 client and server from the same signed PGDG repository (with
  the expected key fingerprint pinned) that the manual native workflow trusts.
* Git from the newest audited 2.43.x security revision offered by the signed
  Ubuntu Noble source index (deb-src only: `noble`, `noble-updates`,
  `noble-security`). Ubuntu 22.04 ships 2.34, which workspace_lab rejects.
  The downloaded `.dsc` `Checksums-Sha256` entries are re-verified, and the
  exact source package version and every source-file SHA-256 are recorded in
  `test-results/ci-native-tools/provenance.json`. Git is compiled into an
  owned `RUNNER_TEMP` prefix with `NO_TCLTK=1 NO_GETTEXT=1`; `/usr/bin/git`
  and global Git configuration are untouched.
* bubblewrap `0.9.0-1build1` from the same signed Noble archive, built into the
  same prefix. The capability is proved by actually running `bwrap --size`,
  not by parsing a version string.
* `git-lfs`, `fuse3` (`fusermount3`), `util-linux` (`unshare`, `nsenter`),
  `redis-server`, Java 21, `gcc`/`g++`/`make`/`pkg-config` and the real kernel
  FUSE test prerequisites.

Preflight fails the job if Git is below 2.43, if the prefix tool is shadowed,
if `bwrap --size` cannot start a sandbox, if `/dev/fuse` is missing or not
readable/writable, or if `unshare -Urnm` cannot create private mount and
network namespaces with a mounted tmpfs. Nothing is skipped and no global
subreaper, sysctl or AppArmor policy is changed.

Cheap but real native security, tenancy and concurrency regressions run against
a single `scripts/build_native_batch.py` invocation that builds `target/debug/rootyard`
together with the feature-enabled Cargo metadata bins and both selected RefStore
fixture integration-test executables, recording the batch in
`test-results/native-build-batch.json`; the fixture outputs are written to
`test-results/refstore-snapshot-fixture` and `test-results/refstore-holds-fixture`:

| Suite | What it proves | Evidence |
| --- | --- | --- |
| `tests/web_sessions.py` | Session exchange, CSRF binding, expiry and parent-token revocation over the real Rust service and PostgreSQL 17 | `test-results/web-sessions.json` |
| `tests/ci_webhook_regressions.py` | 201-event batching, concurrent claim fencing, verified TLS delivery and untrusted-CA rejection (no `--report`; the stdout log is the evidence) | `test-results/ci-webhook-regressions.log` |
| `tests/webhook_worker_recovery.py` | Background worker recovery across SIGKILL at the enqueue and ack boundaries, lease overlap and backoff/dead-letter, with no manual dispatch | `test-results/webhook-worker-recovery.json` |
| `tests/webhook_pagination.py` | Webhook delivery sequence allocation, concurrent barriers and cursor pagination over PostgreSQL 17 | `test-results/webhook-pagination.json` |
| `tests/webhook_pr_sync.py` | No-hook, paused-hook and deleted-hook Pull Request ref reconciliation across page boundaries | `test-results/webhook-pr-sync.json` |
| `tests/repository_pagination.py` | Real API/PostgreSQL traversal of 1,001 repositories with keyset ordering, actor scope and mutations | `test-results/repository-pagination.json` |
| `tests/organization_pagination.py` | Real API/PostgreSQL traversal of 101 members and 101 teams with authorization, cursor scope and mutation resume | `test-results/organization-pagination.json` |
| `tests/web_detail_pagination.py` | Real web Issue comments and PR reviews across the 100-row page boundary (105 rows seeded plus the 106th written through real HTTP/Git), including cursor/actor/revocation checks | `test-results/web-detail-pagination.json` |
| `tests/web_repository_pagination.py` | Browser repository-discovery keyset pagination, actor/membership binding and restricted/anonymous scope checks | `test-results/web-repository-pagination.json` |
| `tests/worker_diagnostics.py` | Source-bound structured worker-operation diagnostics isolation under real PostgreSQL `statement_timeout` | `test-results/worker-diagnostics.json` |
| `tests/lfs_read_amplification.py` | Native `/proc/<pid>/io` `rchar` warm-read bound, verification singleflight coalescing, and offline/removed object-store verified local 200 vs. fail-closed cold-miss semantics | `test-results/lfs-read-amplification.json` |
| `tests/lfs_split_tx_races.py` | Split-transaction LFS DB pool release, concurrent `pending -> ready` verification (including three-pass conflict bound and corrupt-byte rejection), post-`ensure_readable` re-authorization (`401`/`403`/`404`/`409`), and duplicate-OID repair deduplication | `test-results/lfs-split-tx-races.json` |

A final step, `scripts/native_report_manifest.py --mode job`, fails the job
unless every report was produced by the exact binary whose SHA-256 appears in
`target/debug/rootyard.build.json`, every declared case passed, the
`ci_webhook_regressions` log is non-empty and contains each expected phase
marker, and the receipt's commit and compiled source-input digest were recorded.
The manifest also binds the pagination, webhook reconciliation, worker
diagnostics and Git LFS concurrency/split-transaction reports
(`repository-pagination.json`, `organization-pagination.json`,
`web-detail-pagination.json`, `web-repository-pagination.json`,
`webhook-pagination.json`, `webhook-pr-sync.json`,
`worker-diagnostics.json`, `lfs-read-amplification.json`,
`lfs-split-tx-races.json`) together with the other verify-job reports and their
harness sources (`tests/lfs.py`, `tests/lfs_remote_contract.py`,
`tests/lfs_read_amplification.py`, `tests/lfs_split_tx_races.py`) to that same
build receipt, so none can be produced by a different binary. These harnesses
are real functional regressions over real API, PostgreSQL, HTTP and Git state,
not scalability benchmarks.
The manifest (`test-results/native-pr-gate.json`) also stores harness SHA-256
digests, `postgres=postgres:17`, the exact `rustc -V` string, `git --version`,
`git lfs version`, `bwrap --version`, the `/dev/fuse` stat and the SHA-256 of
the native tool provenance file. Injecting any of those defects turns the pull
request red instead of leaving the regression to manual re-verification.
The `e2e-report` artifact includes `target/debug/rootyard.build.json`,
`test-results/native-build-batch.json` and both `test-results/evidence/*.jsonl`
and `test-results/*-evidence/*.jsonl`, so downloaded job manifests can be
checked against the build receipt and batch manifest.

## 专项与完整 candidate 分层 (specialised suites vs. the complete gate)

The existing GitHub Actions workflow layering and required checks are unchanged.
The grouped acceptance runner described at the end of this section is optional
and does not alter any CI required status. It does not replace the full required
gate, the candidate-release workflow or the qualified Linux kernel/cgroup
workflow. Choosing a layer:

| Situation | What runs |
| --- | --- |
| Opening or updating any pull request | `CI` → `verify`, `container`; Pando → `isolated-lab`; Redis → `redis-contract`; plus `native` / `log-storage` automatically when their `pull_request.paths` match. This is the **full required gate** and is never skipped by default. |
| Working on one affected area before the PR is ready | Dispatch the affected specialised workflow on the branch: `refstore-protocol-acceptance.yml`, `refcas-log.yml`, `native-kernel-acceptance.yml` (cgroup VM profile), `candidate-release-acceptance.yml` (Chromium + Garage candidate), or `pando-lab.yml` / `redis-contract.yml` (now also dispatachable). Dispatch is additive; it does not change the PR's required result. |
| Merging to `main` | The `push` on `main` re-runs every full-gate workflow on the merged commit (the PR head is a different commit), so the complete gate is re-verified after merge. |

Trigger policy: full-gate workflows (`ci.yml`, `pando-lab.yml`, `redis-contract.yml`) run
`pull_request` on every PR head and `push` only for `main`. An unfiltered `push` duplicated the
whole gate for each feature-branch head (before/after evidence and the limits of what has been
observed are in `docs/acceptance/ci-trigger-dedup-20261110.md`). Do not add `paths:` filters to
those workflows: a required check that is filtered out stays "expected" forever on a PR. The
path-filtered suites above intentionally have none of their jobs as `main` required checks;
their `workflow_dispatch` makes them available at any time.

## Optional local grouped runner (`scripts/run_native_acceptance.py`)

Operator-side scheduling evidence only. It is a Linux-only coordinator that
executes existing suite commands from a JSON plan; it is not a CI job and it
proves nothing about kernel or cgroup behaviour.

* Every `full` suite must depend, directly or transitively, on a `smoke` suite,
  and a failed, timed-out, cancelled or blocked dependency blocks its dependants
  (`blocked` is never a pass). This does not mean all smoke work finishes before
  any full job starts: every eligible suite may run concurrently, in plan order
  subject to dependencies, `max_workers` and resource locks.
* Each suite declares resource keys (`exclusive`, or `shared` with a harness
  isolation declaration). Stateful `global`/`kernel`/`lifecycle` keys need their
  own named isolation entry to be shared; `database: owned_schema` supports
  sharing non-stateful keys; exclusive use needs no declaration. Per-suite
  `timeout_seconds` (at most 86400) and the optional `total_timeout_seconds`
  request cancellation only: they are not wall-clock guarantees, because locks
  stay held until owned descendants are proven quiescent. If that state is
  unknown, the runner and its locks may stay alive indefinitely with no final
  pass or report.
* The runner only executes each suite's `argv` and coordinates flocked resource
  keys; it never provisions or drops PostgreSQL or Garage. Service and resource
  setup and cleanup belong to each suite's existing harness.
* Keep credentials out of plans and pass them through the private runner
  environment. Validation rejects URI-like values under sensitive top-level
  environment keys but does not reject every possible secret string.
* Suite summaries are redacted output, except the supervisor pre-spawn refusal,
  which uses a fixed summary. The self-test marks the run/report failed if a
  known sensitive value remains in the rendered report text. It is detection,
  not prevention: on a detected leak the runner writes and prints the same
  minimal hashed failure payload (kind, version, run id, hashed self-test
  matches, `gate: failed`) instead of the full report; if that file cannot be
  written, it prints no report. Raw per-suite logs
  (`<run-dir>/logs/<suite_id>.log`) are mode `0600` but may contain secrets;
  keep them private.
* The runner requires a readable Linux `/proc` and working pidfds and refuses
  to spawn anything when either is unsupported.
* `--dry-run` validates host support and paths but starts no child and creates no
  run or report directory. A real run creates the run directory and the report
  parent. The lock directory must already exist and be operator-created; lock,
  run, log and report paths must resolve outside `--verify-host` (the plan file
  itself need not be).

A minimal no-secret plan:

```json
{"version": 1,
 "suites": [{"id": "smoke-web-sessions", "phase": "smoke",
             "argv": ["python3", "tests/web_sessions.py", "--binary",
                      "target/debug/rootyard", "--report", "{run_dir}/smoke.json"],
             "depends_on": [],
             "resources": {"instance:pg17": "shared"},
             "timeout_seconds": 600,
             "isolation": {"database": "owned_schema"}}]}
```

Build, validate and run (placeholders; create only the lock directory and export
any credentials in the runner process environment before the run; the runner
creates `/outside/path/runs/run-1` and `report.json`):

```sh
python3 scripts/build_native.py --no-default-features --package-debug 0 --strip-debuginfo --bins
mkdir -p /outside/path/locks
python3 scripts/run_native_acceptance.py --plan /outside/path/plan.json \
  --lock-dir /outside/path/locks --log-dir /outside/path/runs/run-1 \
  --report /outside/path/runs/run-1/report.json --run-id run-1 --dry-run
python3 scripts/run_native_acceptance.py --plan /outside/path/plan.json \
  --lock-dir /outside/path/locks --log-dir /outside/path/runs/run-1 \
  --report /outside/path/runs/run-1/report.json --run-id run-1
```

`--exclude SUITE` (repeatable) drops an unreferenced suite after the original
plan has been validated; if any included suite depends on an excluded suite, or
if exclusion would leave no suites, the runner rejects the invocation with a
bounded preflight error before spawning suites or acquiring resource locks.
`--verify-host` names the checkout root used to refuse in-checkout lock, run,
log and report paths (default: the repository root).

## Layer 2 — candidate release gate (`.github/workflows/candidate-release-acceptance.yml`)

Manual `workflow_dispatch` only. Dispatch it on the branch or tag head that is
the candidate commit; the workflow records `github.sha` as the candidate commit
and every job asserts `git rev-parse HEAD` equals it before building.

* `browser-native` runs `tests/browser_ui.py` against the real system Chromium
  at `/usr/bin/chromium` with a fixed Playwright client (`playwright==1.49.0`).
  No downloaded Playwright browser is substituted for the system package.
  Because container steps run as UID 0 against the host-runner bind mount at
  `$GITHUB_WORKSPACE` (`/__w/...`), a setup step sets container-scoped
  `ROOTYARD_TEST_EVIDENCE_DIR` and exports `GIT_CONFIG_COUNT`/`safe.directory`
  into `$GITHUB_ENV` so Git commands succeed even inside harnesses that pass
  `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=/dev/null`. The manifest
  requires `browser_ui=chromium_browser_workflow` and records the version
  reported by `importlib.metadata` plus the actual `/usr/bin/chromium --version`
  and job-scoped PostgreSQL server/client versions
  (`browser_postgres_server_version` / `browser_postgres_client_version`,
  namespaced away from `object-store-native`'s
  `object_store_postgres_server_version` / `object_store_postgres_client_version`
  so Debian container vs. Ubuntu PGDG client strings do not collide in
  `release-gate`, while `rust` stays shared); the `rust:1-trixie` container tag
  and apt packages are mutable inputs, not immutable pins.
* `object-store-native` starts an ephemeral, job-owned Garage container pinned
  by tag and digest (`dxflrs/garage:v2.1.0@sha256:4c9b34c1...`) and runs:
  * `tests/lfs_hydration_concurrency.py` — concurrent cold hydration through the
    real S3 backend;
  * `tests/lfs_remote.py` — second-node recovery after source-volume loss;
  * `tests/lfs_retention_acceptance.py` — publication and committed-object
    retention with **no** object-store endpoint configured. The step unsets all
    `ROOTYARD_OBJECT_STORE_*` variables in shell (never exporting `""` via step
    `env:`) and asserts `ROOTYARD_OBJECT_STORE_ENDPOINT`/`_BUCKET` are unset, so
    it cannot accidentally inherit the Garage fixture or trigger empty-endpoint
    parsing.
  Git LFS 3.6.1 is downloaded by `scripts/install_git_lfs.sh` with bounded
  `curl` timeouts/size caps and its tarball SHA-256 is verified against both the
  official release `sha256sums.asc` cleartext-signed manifest (requiring PGP
  signed-message framing on `.asc` / default checksum assets and parsing
  strictly inside the PGP signed message body, rejecting unsigned files,
  unsigned tail entries or truncated framing) and the workflow's pinned
  `--expected-sha256`
  (`2138d2e405a12f1a088272e06790b76699b79cb90d0317b77aafaf35de908d76`); the
  release tarball's real `git-lfs-3.6.1/git-lfs` layout is stripped and verified
  to be a regular non-symlink file before install. If the checksum asset is
  unavailable, unsigned, malformed, unsigned-tailed or ambiguous the step fails
  rather than installing an unverified binary. The installed `git-lfs/<version>`
  output and `$RUNNER_TEMP/bin/git-lfs` precedence on `PATH` are asserted.
* `release-gate` downloads both job manifests and runs
  `scripts/native_report_manifest.py --mode release`. It requires the two jobs to
  share the dispatched commit and one compiled source-input digest, re-verifies
  every harness SHA-256 against the dispatched checkout, re-hashes every
  downloaded report and log against the SHA-256 in its job manifest (missing,
  symlinked or traversing artifact names fail closed), requires the
  `browser_ui`, `lfs_hydration`, `lfs_remote` and `lfs_retention` reports, and
  requires the exact `garage_version=2.1.0`, the exact Garage image digest,
  `git_lfs_version=3.6.1`, the exact `git_lfs_tarball_sha256`,
  `playwright_version=1.49.0` and a Chromium version in the fixture record. The Garage image's own version output is
  `garage v2.1.0 [features: ...]`; the helper matches exactly 2.1.0 plus an
  optional feature tail and obtains the node id from the first line of
  `garage node id` (64 hex `@address`), never by grepping 16-hex `status` ids. Its output is `candidate-release-gate.json`.

Reports, stdout logs, build receipts, evidence JSONL and the manifests are
uploaded; download-artifact flattens them under `artifacts/<job>/`, and the
release step passes each job's directory with `--artifact-dir` so the gate
re-hashes the downloaded bytes rather than trusting the manifest alone. A missing report, empty log, failed case, digest mismatch, foreign
commit, stale harness, missing fixture version, absent service or a credential
reaching an artifact fails the gate closed — there is no "success skip".

### Fixture ownership and credentials

`scripts/owned_garage_fixture.sh` creates a canonical private fixture
directory, a `0600` ownership sentinel bound to the canonical path, uid, unique
 nonce and container id, and a container labelled with the same kind/nonce/path/
uid/name. Start refuses a preexisting non-empty, symlinked or dangerous path.
Stop re-reads the sentinel, rejects empty/root/ancestor/symlink/foreign/
non-owned paths, verifies the inspected container id and every ownership label
against the sentinel, and only then removes the container by id and the owned
directory. It never trusts a caller-supplied path or container name. The S3 API
is published only on `127.0.0.1`. `scripts/owned_object_store_env.py` refuses to
run when `ROOTYARD_OBJECT_STORE_*` settings are already present in the
environment (no inherited endpoint, user secret or cross-deployment bucket),
refuses a non-loopback or non-HTTP endpoint, probes the endpoint until it
answers with an S3 XML body (a stub web page fails), and writes the credential
to a `0600` environment file in a `0700` directory outside the checkout. The
cleanup step removes that file and the owned fixture; the file is never
uploaded and values are never printed. The object-store manifest step (`if: always()`)
sources the private file in its own shell when present so the credential scanner
sees this job's generated keys (an actions-step environment is not inherited
across steps), or passes `--fixture "object_store_env="` when an earlier step
failed before fixture startup so `scripts/native_report_manifest.py` still writes
a `rootyard/native-acceptance-failure` manifest while failing closed.

## Reproduction and current status

On a plain Ubuntu 22.04 host, first bootstrap and prove the native tool
profile (the helper uses `sudo` for apt and builds into `$RUNNER_TEMP`; it does
not run in this repository's local checks):

```sh
scripts/install_ci_native_tools.sh install --prefix "$RUNNER_TEMP/rootyard-ci-native" --provenance test-results/ci-native-tools/provenance.json
scripts/install_ci_native_tools.sh preflight --prefix "$RUNNER_TEMP/rootyard-ci-native"
```

Then run the per-pull-request regressions exactly as CI does after building once:

```sh
python3 scripts/build_native_batch.py \
  --all-bins \
  --features pando-lab \
  --strip-debuginfo \
  --test ref_store_snapshot_backup_fixture \
  --output test-results/refstore-snapshot-fixture \
  --test ref_store_holds_backup_fixture \
  --output test-results/refstore-holds-fixture \
  --manifest-out test-results/native-build-batch.json
python3 tests/web_sessions.py --binary target/debug/rootyard --report test-results/web-sessions.json
python3 tests/ci_webhook_regressions.py --binary target/debug/rootyard | tee test-results/ci-webhook-regressions.log
python3 tests/webhook_worker_recovery.py --binary target/debug/rootyard --report test-results/webhook-worker-recovery.json
python3 tests/webhook_pagination.py --binary target/debug/rootyard --report test-results/webhook-pagination.json
python3 tests/webhook_pr_sync.py --binary target/debug/rootyard --report test-results/webhook-pr-sync.json
python3 tests/repository_pagination.py --binary target/debug/rootyard --report test-results/repository-pagination.json
python3 tests/organization_pagination.py --binary target/debug/rootyard --report test-results/organization-pagination.json
python3 tests/web_detail_pagination.py --binary target/debug/rootyard --report test-results/web-detail-pagination.json
python3 tests/web_repository_pagination.py --binary target/debug/rootyard --report test-results/web-repository-pagination.json
python3 tests/worker_diagnostics.py --binary target/debug/rootyard --report test-results/worker-diagnostics.json
python3 tests/lfs_read_amplification.py --binary target/debug/rootyard --report test-results/lfs-read-amplification.json
python3 tests/lfs_split_tx_races.py --binary target/debug/rootyard --report test-results/lfs-split-tx-races.json
```

The native host profile in this change was validated locally only: workflow
YAML parses, every helper passes `bash -n`,
`tests/test_install_ci_native_tools.py` and the Phase-1 CI wiring tests pass,
and no local `sudo`, apt, mount, sysctl or AppArmor change was made. The
coordinator must run the pushed branch on GitHub Actions before any green
ordinary-CI result is claimed. The Git source revision is selected from the
signed Noble index at run time; the actual version and source-file SHA-256
digests are recorded in the provenance artifact rather than fabricated in
advance.

Candidate jobs require Docker with the pinned Garage image, `/usr/bin/chromium`
and a Playwright client. Earlier hosted dispatches exposed the container
`safe.directory` / `$GITHUB_WORKSPACE` boundary, official `sha256sums.asc` asset
name and early-failure `OBJECT_STORE_ENV_FILE` manifest handling (run
`43249639303` on `3f21678`), OpenDAL `RetryLayer` re-issuing a ranged `GET` on
truncated 2xx S3 bodies plus Debian vs. Ubuntu `psql` fixture-key collisions
(run `43292515525` on `027784e`), and step-level YAML `env: KEY: ""` exporting
empty strings instead of unsetting `ROOTYARD_OBJECT_STORE_*` before
`tests/lfs_retention_acceptance.py` (run `43303142078` on `66c31a6`). Locally,
the owned-fixture cleanup and startup-budget guards are covered by
`tests/test_owned_garage_fixture.py`, the Git LFS `sha256sums.asc` and pinned
digest checks plus retention `unset` wiring by `tests/test_install_git_lfs.py`,
and the manifest contract by `tests/test_native_report_manifest.py`.

Hosted `candidate-release-acceptance.yml` run `43306664983`
(`https://github.com/jihuayu/rootyard/actions/runs/43306664983`,
`workflow_dispatch` on `codex/ci76-candidate-gate-20261112`, candidate commit
`a76f6f19b333081b24e06b3f5483d1e4c1a83bf7`, shared `source_inputs_sha256`
`aca2c480eca111f2acc3ea141e935c23d5680d0dd839a3f7cb425b780c0dc470`,
`rustc 1.99.1 (58cf8f9c3 2026-10-13)`) passed all 3/3 jobs:

* `browser-native` (job `131491660347`, `success`): container-built `rootyard`
  SHA-256 `5641446cec9f922f3c1b1f684a0dd4dd477ca141abb6457a81205eb2d68a9171`
  (`rootyard.build.json` SHA-256
  `ecb256f9e0762726ac8103caed0e40fffe29ad11f0c1182e4a45f611e2b4b2bc`,
  `native-job-manifest.json` SHA-256
  `c7ffd5d453e930f6ca283274d793f04eba0bcd2226eee84fa2ba7eb74ab27119`);
  fixtures `chromium_version=Chromium 156.0.8078.79 built on Debian GNU/Linux 13 (trixie)`,
  `playwright_version=1.49.0`,
  `browser_postgres_server_version=17.11 (Debian 17.11-1.pgdg13+2)`,
  `browser_postgres_client_version=psql (PostgreSQL) 17.11 (Debian 17.11-0+deb13u1)`;
  `browser_ui` (`browser-ui.json`, SHA-256
  `2993cc6d1305dcb8e7d322713183beb4368f9860e01efdab28baf68ed3b376a4`) passed
  `chromium_browser_workflow` (`6.5513s`) against `/usr/bin/chromium`.
* `object-store-native` (job `131491659861`, `success`): host-built `rootyard`
  SHA-256 `2aeb51c56ad3bfed0d56dd8ed9876471db871c1ce744ed2c53dd5507adbdcc76`
  (`rootyard.build.json` SHA-256
  `abdb633847824a3b0ba264992ac39ffeb66671f514b4b37766974d00c677d847`,
  `native-job-manifest.json` SHA-256
  `cd889e139984b47ceb86dc99cb70bec70f0b51f1f25b8b159966d21fc1de1c1a`);
  fixtures `garage_version=2.1.0`
  (`dxflrs/garage:v2.1.0@sha256:4c9b34c113e61358466e83fd6e7d66e6d18657ede14b776eb78a93ee8da7cf6a`,
  image id `sha256:246f9db8485da30929ce4d25e87016ae432bac009a26d206667aaaf59906fe6c`),
  `git_lfs_version=3.6.1`
  (`git-lfs/3.6.1 (GitHub; linux amd64; go 1.23.3; git ea47a34b)`),
  `git_lfs_tarball_sha256=2138d2e405a12f1a088272e06790b76699b79cb90d0317b77aafaf35de908d76`,
  `object_store_postgres_server_version=17.11 (Debian 17.11-1.pgdg13+2)`,
  `object_store_postgres_client_version=psql (PostgreSQL) 17.12 (Ubuntu 17.12-1.pgdg24.04+1)`;
  passed `lfs_hydration` (`lfs-hydration.json`, SHA-256
  `c1ac04984727631aa1431693b4a77547686494606dd90fbba8906b6408e3c62f`,
  `concurrent_cold_hydration`, `16.4449s` — shared singleflight `backend_gets=1` /
  `backend_heads=1`, 502 retry, truncated 2xx body `backend_gets_for_shared_flight=1`
  with `partial_final_published=false` and `staging_leftovers=0`, cancellation
  recovery), `lfs_remote` (`lfs-remote.json`, SHA-256
  `9ff78b352866af42f25b40173438a2d50d4416d899ddc850a01152fb2bc27f11`,
  `stock_lfs_second_node_recovery`, `5.4776s`), and `lfs_retention`
  (`lfs-retention.json`, SHA-256
  `7380a6cbc4b72491aac15f532dcea45715d270e3820c8fb5edd658f0f704185e`,
  `valid_and_compatible_publication` `4.6544s`,
  `committed_bytes_survive_failures` `0.1889s`,
  `gitfs_maintenance_during_pointer_publication` `4.7284s` with all
  `ROOTYARD_OBJECT_STORE_*` variables unset).
* `release-gate` (job `131493914554`, `success`): `candidate-release-gate.json`
  (`status: "passed"`, SHA-256
  `7579f03d7c51ef7f49e807a6e1e0e32d78edf843c77bc1cf8af4b4b0aa55c8ed`) verified
  identical `source_commit` and `source_inputs_sha256` across both build
  environments, re-verified all 15 harness digests against the checkout, and
  re-hashed every downloaded report, log and build receipt against its job
  manifest.

Recording run `43306664983` in this file produces a documentation-only follow-up
commit on top of the exact verified code tree `a76f6f1`
(`a76f6f19b333081b24e06b3f5483d1e4c1a83bf7`); no workflow, script, harness or
Rust source changed after `a76f6f1`.

## Limits

* All candidate suites are single-host loopback runs; timings are functional,
  not scalability evidence.
* Chromium and Playwright cannot prove cross-browser behaviour.
* The Git LFS 3.6.1 release tarball (`git-lfs-linux-amd64-v3.6.1.tar.gz`) is
  verified against both the official release `sha256sums.asc` manifest entry
  (parsed strictly inside the PGP signed message body; `gpg` cryptographic
  signature verification is not performed) and the pinned SHA-256 digest
  `2138d2e405a12f1a088272e06790b76699b79cb90d0317b77aafaf35de908d76`
  (`--expected-sha256` and `release-gate` `--require-fixture-exact`). The step
  fails closed if the official checksum asset is missing, malformed,
  unsigned-tailed, ambiguous or does not match.
* Kernel sandbox/cgroup acceptance remains in
  `.github/workflows/native-kernel-acceptance.yml`; Docker-backed Garage tests do
  not exercise it. No Vault dependency is introduced.
* Ordinary CI's Git 2.43 client is selected from the signed Ubuntu Noble source
  index (latest audited 2.43.x security revision) and built per run; its exact
  source package version and source-file SHA-256 digests are recorded at run
  time. The profile therefore records provenance instead of asserting a
  hard-coded digest that could not be verified in this environment.
