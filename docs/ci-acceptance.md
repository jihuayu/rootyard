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
  at `/usr/bin/chromium` with a pinned Playwright client (`playwright_version`
  input, default `1.49.0`). No downloaded Playwright browser is substituted for
  the system package.
* `object-store-native` starts an ephemeral, job-owned Garage 2.1 container
  (`garage_image` input, default `dxflrs/garage:v2.1.0`; the script refuses any
  image whose `/garage --version` is not `garage 2.1.x`) and runs:
  * `tests/lfs_hydration_concurrency.py` — concurrent cold hydration through the
    real S3 backend;
  * `tests/lfs_remote.py` — second-node recovery after source-volume loss;
  * `tests/lfs_retention_acceptance.py` — publication and committed-object
    retention with **no** object-store endpoint configured. The step clears and
    asserts `ROOTYARD_OBJECT_STORE_ENDPOINT`/`_BUCKET` empty, so it cannot
    accidentally inherit the Garage fixture.
  Git LFS `git_lfs_version` (default `3.6.1`) is downloaded from the pinned
  release and its `git-lfs/<version>` output is asserted before the tests run.
* `release-gate` downloads both job manifests and runs
  `scripts/native_report_manifest.py --mode release`. It requires the two jobs to
  share the dispatched commit and one compiled source-input digest, re-verifies
  every harness SHA-256 against the dispatched checkout, requires the
  `browser_ui`, `lfs_hydration`, `lfs_remote` and `lfs_retention` reports, and
  requires `garage=2.1`, `git_lfs=3.6.1` and a `Chromium` version in the fixture
  record. Its output is `candidate-release-gate.json`.

Reports, stdout logs, build receipts, evidence JSONL and the manifests are
uploaded. A missing report, empty log, failed case, digest mismatch, foreign
commit, stale harness, missing fixture version, absent service or a credential
reaching an artifact fails the gate closed — there is no "success skip".

### Fixture ownership and credentials

`scripts/owned_garage_fixture.sh` creates a container, data directory, bucket
and key namespaced to the current run. The S3 API is published only on
`127.0.0.1`. `scripts/owned_object_store_env.py` refuses to run when
`ROOTYARD_OBJECT_STORE_*` settings are already present in the environment
(no inherited endpoint, user secret or cross-deployment bucket), refuses a
non-loopback or non-HTTP endpoint, probes the endpoint until it answers with an
S3 XML body (a stub web page fails), and writes the credential to a `0600`
environment file in a `0700` directory outside the checkout. The cleanup step
removes that file and the container; the file is never uploaded and values are
never printed.

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
state is: workflow and script syntax validated, manifest contract covered by
`tests/test_native_report_manifest.py`, and native execution pending the
candidate dispatch.

## Limits

* All candidate suites are single-host loopback runs; timings are functional,
  not scalability evidence.
* Chromium and Playwright cannot prove cross-browser behaviour.
* The Git LFS release tarball is pinned by immutable version URL and its
  downloaded SHA-256 is recorded, but no digest is hard-coded in the workflow.
* Kernel sandbox/cgroup acceptance remains in
  `.github/workflows/native-kernel-acceptance.yml`; Docker-backed Garage tests do
  not exercise it. No Vault dependency is introduced.
