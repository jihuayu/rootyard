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
the binary built once by `scripts/build_native.py --features pando-lab --bins`:

| Suite | What it proves | Evidence |
| --- | --- | --- |
| `tests/web_sessions.py` | Session exchange, CSRF binding, expiry and parent-token revocation over the real Rust service and PostgreSQL 17 | `test-results/web-sessions.json` |
| `tests/ci_webhook_regressions.py` | 201-event batching, concurrent claim fencing, verified TLS delivery and untrusted-CA rejection (no `--report`; the stdout log is the evidence) | `test-results/ci-webhook-regressions.log` |
| `tests/webhook_worker_recovery.py` | Background worker recovery across SIGKILL at the enqueue and ack boundaries, lease overlap and backoff/dead-letter, with no manual dispatch | `test-results/webhook-worker-recovery.json` |
| `tests/repository_pagination.py` | Real API/PostgreSQL traversal of 1,001 repositories with keyset ordering, actor scope and mutations | `test-results/repository-pagination.json` |
| `tests/organization_pagination.py` | Real API/PostgreSQL traversal of 101 members and 101 teams with authorization, cursor scope and mutation resume | `test-results/organization-pagination.json` |
| `tests/web_detail_pagination.py` | Real web Issue comments and PR reviews across the 100-row page boundary (105 rows seeded plus the 106th written through real HTTP/Git), including cursor/actor/revocation checks | `test-results/web-detail-pagination.json` |

A final step, `scripts/native_report_manifest.py --mode job`, fails the job
unless every report was produced by the exact binary whose SHA-256 appears in
`target/debug/rootyard.build.json`, every declared case passed, the
`ci_webhook_regressions` log is non-empty and contains each expected phase
marker, and the receipt's commit and compiled source-input digest were recorded.
The manifest also binds the `repository-pagination.json`,
`organization-pagination.json` and `web-detail-pagination.json` reports and
their harness sources to that same build receipt, so none of the three can be
produced by a different binary. These three harnesses are real functional
regressions over real API, PostgreSQL, HTTP and Git state, not scalability
benchmarks.
The manifest (`test-results/native-pr-gate.json`) also stores harness SHA-256
digests, `postgres=postgres:17`, the exact `rustc -V` string, `git --version`,
`git lfs version`, `bwrap --version`, the `/dev/fuse` stat and the SHA-256 of
the native tool provenance file. Injecting any of those defects turns the pull
request red instead of leaving the regression to manual re-verification.

## 专项与完整 candidate 分层 (specialised suites vs. the complete gate)

The existing workflows already carry the layering; no new orchestrator, suite input or
externally-triggered dependency is added. Choosing a layer:

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

## Layer 2 — candidate release gate (`.github/workflows/candidate-release-acceptance.yml`)

Manual `workflow_dispatch` only. Dispatch it on the branch or tag head that is
the candidate commit; the workflow records `github.sha` as the candidate commit
and every job asserts `git rev-parse HEAD` equals it before building.

* `browser-native` runs `tests/browser_ui.py` against the real system Chromium
  at `/usr/bin/chromium` with a fixed Playwright client (`playwright==1.49.0`).
  No downloaded Playwright browser is substituted for the system package. The
  manifest records the version reported by `importlib.metadata` and the actual
  `/usr/bin/chromium --version` and PostgreSQL server/client versions; the
  `rust:1-trixie` container tag and apt packages are mutable inputs, not
  immutable pins.
* `object-store-native` starts an ephemeral, job-owned Garage container pinned
  by tag and digest (`dxflrs/garage:v2.1.0@sha256:4c9b34c1...`) and runs:
  * `tests/lfs_hydration_concurrency.py` — concurrent cold hydration through the
    real S3 backend;
  * `tests/lfs_remote.py` — second-node recovery after source-volume loss;
  * `tests/lfs_retention_acceptance.py` — publication and committed-object
    retention with **no** object-store endpoint configured. The step clears and
    asserts `ROOTYARD_OBJECT_STORE_ENDPOINT`/`_BUCKET` empty, so it cannot
    accidentally inherit the Garage fixture.
  Git LFS 3.6.1 is downloaded and its tarball SHA-256 is compared with the
  official release `sha256sums.txt`; the release tarball's real
  `git-lfs-3.6.1/git-lfs` layout is stripped before install. If the checksum
  asset is unavailable or ambiguous the step fails rather than installing an
  unverified binary. The installed `git-lfs/<version>` output is asserted.
* `release-gate` downloads both job manifests and runs
  `scripts/native_report_manifest.py --mode release`. It requires the two jobs to
  share the dispatched commit and one compiled source-input digest, re-verifies
  every harness SHA-256 against the dispatched checkout, re-hashes every
  downloaded report and log against the SHA-256 in its job manifest (missing,
  symlinked or traversing artifact names fail closed), requires the
  `browser_ui`, `lfs_hydration`, `lfs_remote` and `lfs_retention` reports, and
  requires the exact `garage_version=2.1.0`, the exact Garage image digest,
  `git_lfs_version=3.6.1`, `playwright_version=1.49.0` and a Chromium version in
  the fixture record. The Garage image's own version output is
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
uploaded and values are never printed. The object-store manifest step sources
the private file in its own shell so the credential scanner sees this job's
generated keys; an actions-step environment is not inherited across steps.

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
python3 scripts/build_native.py --features pando-lab --bins
python3 tests/web_sessions.py --binary target/debug/rootyard --report test-results/web-sessions.json
python3 tests/ci_webhook_regressions.py --binary target/debug/rootyard | tee test-results/ci-webhook-regressions.log
python3 tests/webhook_worker_recovery.py --binary target/debug/rootyard --report test-results/webhook-worker-recovery.json
python3 tests/repository_pagination.py --binary target/debug/rootyard --report test-results/repository-pagination.json
python3 tests/organization_pagination.py --binary target/debug/rootyard --report test-results/organization-pagination.json
python3 tests/web_detail_pagination.py --binary target/debug/rootyard --report test-results/web-detail-pagination.json
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
and a Playwright client. The coordinator verifies them against an owned fixture;
the workflow was **not executed on GitHub by this change**, so no green
candidate-release run or release certification is claimed here. The recorded
state is: workflow/script YAML and bash syntax validated, the owned-fixture
cleanup guards covered by `tests/test_owned_garage_fixture.py`, the Git LFS
archive layout/checksum path covered by `tests/test_install_git_lfs.py`, and the
manifest contract covered by `tests/test_native_report_manifest.py`. Those are
local unit/syntax checks only; no Docker fixture, no real Git LFS download and
no GitHub Actions run was executed.

## Limits

* All candidate suites are single-host loopback runs; timings are functional,
  not scalability evidence.
* Chromium and Playwright cannot prove cross-browser behaviour.
* The Git LFS release tarball is pinned by version URL and verified against the
  official release `sha256sums.txt` at run time. No expected digest was
  fabricated or hard-coded in this change; the current environment had no
  network access to fetch and confirm the official 3.6.1 checksum entry. The
  step fails closed if the official checksum asset is missing, ambiguous or
  does not match.
* Kernel sandbox/cgroup acceptance remains in
  `.github/workflows/native-kernel-acceptance.yml`; Docker-backed Garage tests do
  not exercise it. No Vault dependency is introduced.
* Ordinary CI's Git 2.43 client is selected from the signed Ubuntu Noble source
  index (latest audited 2.43.x security revision) and built per run; its exact
  source package version and source-file SHA-256 digests are recorded at run
  time. The profile therefore records provenance instead of asserting a
  hard-coded digest that could not be verified in this environment.
