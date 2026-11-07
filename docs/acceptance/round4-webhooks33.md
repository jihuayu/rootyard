# Round-4 issue #33 / bugs #3, #16, #19 acceptance — automatic webhook delivery and untrusted-CA TLS

**Verdict:** native **PASSED**, independent source/acceptance review **approved**
with 0 P1 and 5 non-blocking P2. Issues **#33, #3, #16 and #19 are
close-eligible after the primary's final publication review and merge of PR
#64**. The primary owns GitHub, push, closure and the final decision on the
close count; this document does not close anything. #23, #25, #32 and #38 remain
closed as recorded; #26, #43, #44 and roadmap #48 stay **open** (physical
cross-host/HA), browser #47 and LFS #39/#40 stay **open** pending separate work,
and issues #2–#19 are not mass-closed.

**Identity:** candidate (test-only) HEAD `cff5ddb0e15558c1300d5d8f239df5653f20411a`,
base main `53e77762a80a2fc28d4d3dcd8ca8c271eb687d47`, compiled production source
`cb8d1b915a3c1e12990c038b7a43e2b7e891ff5f`, immutable local binary
`157748addd3ad1cc67e9aa5fc2c60b76b524de4f6a09ae65bedfdea26f17958f`, production
input `0f865a04763c5be077e15151143554b191f8ad8a84462f6746d045eabea3bc90` (331
files, recomputed unchanged during publication).

The candidate diff is **test-only**: a new `tests/webhook_worker_recovery.py`
and an unrelated-CA negative added to `tests/ci_webhook_regressions.py`. No
production source, migration, schema, Cargo or build input changed, so the
certified baseline binary is legitimately reused. **This publication did not
compile `cff5ddb`**; the harness HEAD is `cff5ddb`, and the round-4 browser
identity (`37e9` binary / `4eba` source) is unrelated and is not tested here.

**Actual runs — both coordinator jobs exit 0** (`evidence/round4/webhooks33-cff5ddb/status.json`,
`state=passed`, `stage=complete`, disposable databases dropped after success):

1. `tests/ci_webhook_regressions.py` with the webhook worker disabled and manual
   `/webhooks/dispatch` only:
   - 201 outbox events on one push hook: first dispatch enqueued 200, second
     enqueued the remaining 1, all 201 rows `delivered` — the permanent >200
     event skip is gone (#3).
   - Two concurrent dispatches against one pending delivery produced exactly one
     receiver request and a `delivered` row (#16 claim fence).
   - A real loopback TLS receiver with a test-CA leaf (SAN `127.0.0.1`) delivered
     once; the same plaintext receiver addressed as `https://` was never
     contacted and ended `dead_letter` (#19).
   - A real TLS receiver chained to an **unrelated CA** was rejected: delivery
     `dead_letter`, non-empty `last_error`, and **0 HTTP requests reached that
     receiver** (#19). The published log line ends with the harness's
     90-character slice of `last_error`, not a truncated capture.
2. `tests/webhook_worker_recovery.py` with the worker enabled and
   `manual_dispatch_calls = 0` (no `/webhooks/dispatch` call exists in that
   harness): five cases, all `passed`.
   - `enqueue_boundary_lost_wakeup_recovers`: pending row survived a hard stop
     and was delivered after restart/periodic scan, `attempts = 1`.
   - `kill_after_receiver_2xx_before_ack_recovers_at_least_once`: receiver `204`,
     real `SELECT … FOR UPDATE` completion observed blocked, whole process group
     `SIGKILL`, its blocked PostgreSQL backend terminated, durable row left
     `leased,1`, real lease expiry, attempt 2 with the **same delivery id**,
     terminal `delivered` — at-least-once.
   - `retry_cannot_steal_a_live_worker_lease`: manual retry during a live worker
     lease returned HTTP `409`; the owner delivered it, `attempts = 1`.
   - `automatic_backoff_retry_and_dead_letter`: first HTTP `500` → `failed` with
     the retry due field scheduled at integer unix now+2; the observed wall
     interval was ≈1.897 s, then an automatic second attempt hit `500` and the
     row became `dead_letter`, observable through
     `GET /deliveries?state=dead_letter`. No SQL or fake clock was injected.
   - `stock_push_updates_open_pull_automatically`: a real stock `git push`
     created a new pin at the pushed OID, a new queued run/check, bumped the open
     PR version 1 → 2, and the owned receiver observed `pull_request` /
     `synchronize` — the automatic issue-#33 acceptance path.

## Why the two proofs are not conflated

`tests/ci_webhook_regressions.py` calls `/webhooks/dispatch` manually and is the
proof for #3/#16/#19. `tests/webhook_worker_recovery.py` never calls
`/webhooks/dispatch`, so it is the automatic-feature proof for #33. Neither
artifact may be cited as the other.

## Non-claims

Native compiled Rust service, one disposable PostgreSQL 17 and owned loopback
HTTP/TLS receivers on one host. No external CI contact, public-CA endpoint,
cross-host failover, power-loss, production data, cloud/KMS or production HA
claim. Redirect/DNS-rebinding and private-resolution negatives are source-level
only. The historical webhook defects (#3/#16/#19 and the #33 orchestration gaps)
were already fixed in production source on main; this work adds qualification
evidence and the new untrusted-CA negative, and does not re-implement a feature.

## Non-blocking residuals (0 P1, 5 P2)

1. **P2-1 / #33:** the exact crash window after the open-PR version/head/base
   `UPDATE` commits and before pin, queued check, delivery and
   `ci_pull_sync_progress` marker complete is source-verified
   (`background::repair_pull_orchestration`, marker written last) rather than
   crash-injected.
2. **P2-2 / #16:** no direct delivered-then-late-500 runtime race; the
   generation fence (`state = leased` plus matching `lease_generation`) is
   source-verified and the claim/ack tests cover one sender and same-ID retry.
3. **P2-3 / #3:** the 201-event proof uses one push hook and manual dispatch;
   multiple hooks, per-hook isolation and new-subscription backlog behaviour are
   source-defined, not separately pinned by a native regression.
4. **P2-4 / #33:** the retry deadline is an **integer unix due field** (now+2), so
   the observed wall interval can land around 1–2 s through second-boundary
   quantization plus scan timing; the harness asserts only `>= 1.0 s` and the
   recorded ≈1.9 s is an **observation, not a guaranteed 2 s minimum**.
5. **P2-5 / #19:** redirect/DNS-rebinding/private-resolution cases are
   source/unit covered (`Policy::none`, all-address `permitted_peer`, pinned
   resolution) but not exercised by a native redirect/rebinding receiver; TLS
   proof is owned loopback with a local CA, not a public endpoint.

## Evidence

[round4/webhooks33-cff5ddb](../evidence/round4/webhooks33-cff5ddb/README.md) —
raw coordinator `status.json` and `certificate.json`, the 331-file
`production-inputs.json`, raw `regressions.log`, `worker-recovery.log`,
`worker-recovery-report.json`, the independent `source-review.json`/`.md`, and a
`manifest.json` of payload sizes and SHA-256 values. Raw JSONL run fixtures, PID
files, private TLS keys/CA material and working state are not published.
