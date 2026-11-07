# CI acceptance: per-pull-request regressions and the candidate release gate

Two layers cover the native acceptance suites. Neither layer replaces the
specialised cgroup VM gate in `.github/workflows/native-kernel-acceptance.yml`.

## Layer 1 — every push and pull request (`.github/workflows/ci.yml`)

Cheap but real native security, tenancy and concurrency regressions run against
the binary built once by `scripts/build_native.py --features pando-lab --bins`:

| Suite | What it proves | Evidence |
| --- | --- | --- |
| `tests/web_sessions.py` | Session exchange, CSRF binding, expiry and parent-token revocation over the real Rust service and PostgreSQL 17 | `test-results/web-sessions.json` |
| `tests/ci_webhook_regressions.py` | 201-event batching, concurrent claim fencing, verified TLS delivery and untrusted-CA rejection (no `--report`; the stdout log is the evidence) | `test-results/ci-webhook-regressions.log` |
| `tests/webhook_worker_recovery.py` | Background worker recovery across SIGKILL at the enqueue and ack boundaries, lease overlap and backoff/dead-letter, with no manual dispatch | `test-results/webhook-worker-recovery.json` |

A final step, `scripts/native_report_manifest.py --mode job`, fails the job
unless every report was produced by the exact binary whose SHA-256 appears in
`target/debug/rootyard.build.json`, every declared case passed, the
`ci_webhook_regressions` log is non-empty and contains each expected phase
marker, and the receipt's commit and compiled source-input digest were recorded.
The manifest (`test-results/native-pr-gate.json`) also stores harness SHA-256
digests, `postgres=postgres:17` and the exact `rustc -V` string. Injecting any of
those defects turns the pull request red instead of leaving the regression to
manual re-verification.

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

Run the per-pull-request regressions exactly as CI does after building once:

```sh
python3 scripts/build_native.py --features pando-lab --bins
python3 tests/web_sessions.py --binary target/debug/rootyard --report test-results/web-sessions.json
python3 tests/ci_webhook_regressions.py --binary target/debug/rootyard | tee test-results/ci-webhook-regressions.log
python3 tests/webhook_worker_recovery.py --binary target/debug/rootyard --report test-results/webhook-worker-recovery.json
```

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
