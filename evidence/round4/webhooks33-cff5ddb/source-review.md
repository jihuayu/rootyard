# Independent source review: Issue 33 and bugs 3/16/19

## Scope and exact identity

- Candidate head: `cff5ddb0e15558c1300d5d8f239df5653f20411a`
- Base main: `53e77762a80a2fc28d4d3dcd8ca8c271eb687d47`
- Compiled source: `cb8d1b915a3c1e12990c038b7a43e2b7e891ff5f`
- Binary: baseline `rootyard` sha256 `157748addd3ad1cc67e9aa5fc2c60b76b524de4f6a09ae65bedfdea26f17958f`
- Production inputs: `0f865a04763c5be077e15151143554b191f8ad8a84462f6746d045eabea3bc90`, 331 files
- Candidate diff is test-only: new `tests/webhook_worker_recovery.py` and the unrelated-CA negative in `tests/ci_webhook_regressions.py`. No Cargo/native/runtime/source edits. Reviewer re-verified the 331-file map and binary hash.

## Verdict

- **Source approval: approved.** No P1 production defect found in the reviewed webhook worker, delivery, fence, retry, orchestration, signing/TLS, trust, or run paths.
- **Native status: passed.** Primary coordinated rerun at `webhooks33/coordinator-status.json` has `state=passed`, stage `complete`; both jobs exited 0.
- **Issue 33: closable.** All three acceptance criteria have direct native tests, with the caveat in P2-1 that the exact post-PR-commit repair crash window is source-verified rather than crash-injected.
- **Issue 3: closable.** 201-event/two-batch regression passes; permanent 200-row skip is removed. Residual multi-hook/new-subscription semantics are noted in P2-3.
- **Issue 16: closable.** Concurrent dispatch claim fence and live-lease retry exclusion pass; generation-fenced completion is source-verified. Exact stale-success-vs-late-failure ordering is a P2 test residual.
- **Issue 19: closable.** Trusted local-CA TLS succeeds; plaintext-as-HTTPS and unrelated-CA TLS are rejected with no receiver payload. Redirect/DNS-rebinding runtime negatives are P2-5; external endpoint proof was not required by this task.

## Native evidence actually run

`logs/regressions.log` (worker disabled, manual dispatch only):

```text
201 event batches: passed
concurrent claim fence: passed
verified TLS and plaintext rejection: passed
untrusted certificate rejected: reqwest transport error, 0 receiver requests
```

`logs/worker-recovery.json` (authoritative coordinated rerun, worker enabled, `manual_dispatch_calls=0`):

- `enqueue_boundary_lost_wakeup_recovers`: pending row survived hard stop; recovered `delivered`, attempts 1.
- `kill_after_receiver_2xx_before_ack_recovers_at_least_once`: receiver 204, real `SELECT ... FOR UPDATE` completion barrier observed blocked, process group SIGKILL, blocked backend terminated, durable row `leased,1`, real lease expiry, attempt 2 with the same delivery ID, terminal `delivered`.
- `retry_cannot_steal_a_live_worker_lease`: retry while worker lease live returned HTTP 409; owner attempt delivered, attempts 1.
- `automatic_backoff_retry_and_dead_letter`: first HTTP 500 -> failed with 2 s schedule; automatic second 500 -> `dead_letter`, observable via `/deliveries?state=dead_letter`.
- `stock_push_updates_open_pull_automatically`: PR version 1 -> 2, new pin OID/ref, queued `ci/test` run/check for the new head, receiver `pull_request` `synchronize` delivery; no manual dispatch.

The earlier `reports/webhook_worker_recovery.json` is also passed but records `source_head=53e7776` because it predates the test-only commit. The coordinated rerun is the authoritative artifact and records `source_head=cff5ddb`.

## Important separation

`tests/ci_webhook_regressions.py` calls `/webhooks/dispatch` manually and is the correct proof for bugs 3/16/19. `tests/webhook_worker_recovery.py` never calls `/webhooks/dispatch` (grep-verified), so it is the automatic-feature proof for issue 33. The two proofs are not conflated.

## P2 residuals (no P1)

1. **P2-1 / #33:** No SIGKILL after the open-PR version/head/base `UPDATE` commits and before pin, queued check, delivery, and `ci_pull_sync_progress` marker complete. `background::repair_pull_orchestration` and `sync_pull_events` provide the durable rescan, and the marker is written last, but that precise crash phase was not injected.
2. **P2-2 / #16:** No direct delivered-then-stale-500 completion race. The claim regression proves one sender; the ack test proves same-ID retry. `claims::complete` requires `state=leased` plus matching `lease_generation` and returns the current row on mismatch, which is the source fence.
3. **P2-3 / #3:** 201-event proof uses one push hook and manual dispatch. Multiple hooks, per-hook isolation, and newly created subscription backlog behavior are source-defined by missing-per-hook-delivery selection plus `UNIQUE(webhook_id,event_id)`, but not separately pinned by a native regression.
4. **P2-4 / #33:** Backoff evidence records 2 s schedule and attempts `[1,2]`, but the wall-clock assertion is only `>=1.0 s`; observed dead-letter delay was about 1.9 s. The assertion could pass a shorter real delay.
5. **P2-5 / #19:** Redirect/DNS-rebinding and private-resolution negatives are source/unit covered (`Policy::none`, all-address `permitted_peer`, pinned `.resolve`), not exercised by a native redirect/rebinding receiver. TLS proof is owned loopback with a local CA, not a public external endpoint.

## Supported mode and final-composition warning

The proof supports native compiled Rust, disposable PostgreSQL 17, real Git, real process-group SIGKILL, and owned loopback HTTP/TLS receivers. No external endpoints, cloud, hardware, credentials, or production data were used.

This approval is valid only for `cff5ddb` / base `53e7776` / compiled source `cb8d1b9` / binary `157748a`. The final round-4 composition later uses the new browser production source `3cc` and binary `37e9` / source `4eba`; those are independent. The final combined pipeline must rerun all cases against that actual final browser binary/source, and this review must not be treated as approval of a different compiled source.
