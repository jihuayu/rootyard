# Round-4 webhook acceptance — automatic delivery and untrusted-CA TLS negative

Concise evidence bundle for the test-only round-4 webhook candidate at
`cff5ddb`. It records the primary coordinator's actual native run and the
independent source/acceptance review. Nothing here is a build: the binary was
compiled earlier from the unchanged production baseline, and this publication
does not compile, retest or exercise any external system.

## Identity

| Item | Value |
| --- | --- |
| Candidate (test-only) HEAD | `cff5ddb0e15558c1300d5d8f239df5653f20411a` |
| Base main | `53e77762a80a2fc28d4d3dcd8ca8c271eb687d47` |
| Compiled production source | `cb8d1b915a3c1e12990c038b7a43e2b7e891ff5f` |
| Immutable local binary | `157748addd3ad1cc67e9aa5fc2c60b76b524de4f6a09ae65bedfdea26f17958f` |
| Production inputs | `0f865a04763c5be077e15151143554b191f8ad8a84462f6746d045eabea3bc90`, 331 files |
| Coordinator | `state=passed`, `stage=complete`, both jobs `exit_code=0` |
| Worker report digest | `75ddfcc95475f313830b1adaf44a9f2fe5c541533b35c649e9c31646df9e7452` (matches `status.json` `report_sha256`) |
| Harness digests | `tests/ci_webhook_regressions.py` `ec86c09f…`; `tests/webhook_worker_recovery.py` `f3f2cffa…` |

The candidate diff is test-only: the new `tests/webhook_worker_recovery.py`
harness and an unrelated-CA TLS negative added to `tests/ci_webhook_regressions.py`.
No `src/`, migration, schema, Cargo or build input changed, so the certified
baseline binary is legitimately reused. The harness HEAD is `cff5ddb`; that is
not a claim that this publication compiled `cff5ddb`, and the round-4 browser
binary `37e9`/source `4eba` is a different, independent identity.

## Two jobs, two different proofs

| Artifact | Worker | `/webhooks/dispatch` | Proves |
| --- | --- | --- | --- |
| `regressions.log` | disabled (`ROOTYARD_OUTBOX_WORKER=false`) | called manually | Bugs #3, #16, #19 regression: batching past 200, claim fence, TLS trust |
| `worker-recovery-report.json` (+ `worker-recovery.log`) | enabled | never called (`manual_dispatch_calls=0`) | Issue #33 automatic durable delivery, crash/retry and dead-letter |

The manual-dispatch regression must not be cited as automatic-worker proof, and
the automatic worker report must not be cited as the concurrency-fence proof.

## Job 1 — `regressions.log` (4 checks, exit 0)

- `201 event batches: passed` — 201 outbox events on one push hook; the first
  manual dispatch enqueued 200, the second enqueued the remaining 1, and all 201
  deliveries reached `delivered`. The permanent >200 event skip is gone (#3).
- `concurrent claim fence: passed` — two concurrent dispatches against one
  pending delivery produced exactly one receiver request and a `delivered` row (#16).
- `verified TLS and plaintext rejection: passed` — a real loopback TLS receiver
  with a test-CA leaf (SAN `127.0.0.1`) delivered once; the same plaintext receiver
  addressed as `https://` was never contacted and ended `dead_letter` (#19).
- `untrusted certificate rejected: …` — a real TLS receiver chained to an
  unrelated CA was rejected: delivery `dead_letter`, non-empty `last_error`, and
  **0 HTTP requests reached that receiver** (#19). The logged text after the colon
  is exactly the harness's 90-character slice of `last_error` (`tests/ci_webhook_regressions.py`),
  not a truncated log capture; the log is a complete 4-line file.

## Job 2 — `worker-recovery-report.json` (5 cases, exit 0, 0 manual dispatch)

| Case | Observed |
| --- | --- |
| `enqueue_boundary_lost_wakeup_recovers` | Row stayed `pending` with the worker hard-stopped, then the periodic/restart scan delivered it (`attempts=1`) with no dispatch. |
| `kill_after_receiver_2xx_before_ack_recovers_at_least_once` | Receiver returned `204`, the real `SELECT … FOR UPDATE` completion was observed blocked, the whole process group was `SIGKILL`ed and its blocked PostgreSQL backend terminated; durable row stayed `leased,1`, real lease expiry followed, attempt 2 reused the same delivery id, terminal `delivered` — at-least-once. |
| `retry_cannot_steal_a_live_worker_lease` | Manual retry during a live worker lease returned HTTP `409`; the owner still delivered it (`attempts=1`). |
| `automatic_backoff_retry_and_dead_letter` | First HTTP `500` → `failed` with the retry due field at integer unix now+2; observed wall interval ≈1.897 s (an observation, not a guaranteed 2 s minimum), then an automatic second attempt hit `500` and became `dead_letter`, observable via `GET /deliveries?state=dead_letter`. No SQL or fake clock was used. |
| `stock_push_updates_open_pull_automatically` | A real stock `git push` to the open-PR branch created a new pin at the pushed OID, a new queued run/check, bumped the PR version 1 → 2, and the owned receiver observed `pull_request` / `synchronize`. |

## Not claimed

Loopback native receivers and one disposable PostgreSQL 17 on one host only. No
external CI contact, no public-CA endpoint, no cross-host failover, no power
loss, no production data, no cloud/KMS use, and no claim that any other round-4
branch (browser #47, LFS #39/#40) or the `37e9` browser binary is tested or done
here. Source-level negatives (redirect/DNS-rebinding, private-resolution) were
inspected, not exercised at runtime.

## Non-blocking residuals (0 P1)

Inherited from `source-review.json`/`source-review.md`: (P2-1) the exact crash
window after the PR-version commit and before the pin/check/delivery/marker is
source-verified through `background::repair_pull_orchestration` and the
last-written progress marker, not crash-injected; (P2-2) the delivered-then-late-500
ordering is covered by the lease-generation fence in source, not reproduced at
runtime; (P2-3) multi-hook/new-subscription backlog semantics are source-defined,
not separately tested; (P2-4) the retry deadline is an integer unix due field (now+2), so the
observed wall interval can land around 1–2 s through second-boundary
quantization, the harness asserts only `>= 1.0 s`, and the observed ≈1.9 s is
an observation, not a guaranteed 2 s minimum; (P2-5) no runtime redirect/DNS-rebinding/private-resolution
receiver. All historical bugs (3/16/19/33-era defects) were already fixed in
production source on main; this PR adds qualification evidence plus the new
untrusted-CA negative.

## Files

- `status.json`, `certificate.json` — raw coordinator status (byte-exact).
- `production-inputs.json` — the 331-file production digest map used by the run (byte-exact).
- `regressions.log`, `worker-recovery.log`, `worker-recovery-report.json` — raw job stdout and the machine report (byte-exact).
- `source-review.json`, `source-review.md` — independent review verdict and narrative (byte-exact).
- `manifest.json` — sizes and SHA-256 of every payload above; `manifest.json` itself is excluded to avoid a self-reference.

Raw JSONL run fixtures, PID files, private TLS keys/CA material and the
`progress.json` working state are deliberately not published.

## Checks run for this publication

- Production digest recomputed from the worktree: `0f865a0…`, 331 files; equals
  the stored map in `production-inputs.json` (no production change).
- Binary re-hashed at the recorded path: `157748a…`.
- `worker-recovery-report.json` digest equals `status.json` `report_sha256`.
- All payload digests equal the manifest entries; log/JSON copies are byte-exact
  with no normalization needed (every file ends with exactly one `\n`, so
  `git diff --check` is clean without edits).
- Marker scan for private keys, tokens and password material across the payloads:
  no matches; no credential, CA or TLS key is included.
