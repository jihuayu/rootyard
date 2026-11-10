# Webhook background scheduling (#69 / #72)

Status: implemented in `src/webhooks/background.rs` and
`src/webhooks/scheduling.rs`. PostgreSQL rows remain the only durable work
queue; the in-process cursor is a fairness device, not authority.

## Invariants preserved

- `webhooks::claims::claim` remains the only lease acquisition path. It advances
  `lease_generation` in one `UPDATE ... FROM forge_webhooks`, and completion is
  fenced by `state='leased' AND lease_generation=$generation`.
- No database transaction is held across DNS, TCP, TLS or an HTTP response. A
  send can be cancelled or the process can die; the durable row stays leased and
  becomes reclaimable after the bounded transport deadline.
- At-least-once delivery and manual retry semantics are unchanged. A manual
  retry cannot steal a live worker lease; a stale owner cannot complete a newer
  claim generation.
- Pull reconciliation does not bypass GitFS authority. A PR read first checks
  that this process is the repository's local primary, takes one `git_slots`
  permit, a shared PostgreSQL read lease, and the local read gate before running
  native Git. Capacity exhaustion or a lost lease is a bounded skip/error for
  that repository, never a scan-wide failure loop over unavailable volumes.

## Two phases per round

A round reads at most 16 repository candidates in stable
`(tenant_id, repository_id)` order and advances an in-process round-robin cursor.
Candidates are the union of active webhook repositories and repositories with
open Pull Requests. This keeps repositories with no hooks, paused hooks or
deleted hooks in the PR reconciliation path without creating deliveries.

1. **PR reconciliation** (PostgreSQL and native Git only): resolve changed open
   PR head/base refs and repair missing pin/run/delivery orchestration. The
   changed-ref query uses non-zero `outbox_events` OIDs different from the stored
   PR OIDs, so unchanged pulls do not launch a Git process every scan.
   `ci_pull_sync_progress` is written last; the repair query's bounded `LIMIT`
   therefore advances on later rounds.
2. **Outbox and network delivery**: one bounded outbox backfill call per
   repository (`LIMIT 128` inside), then at most 8 due deliveries, serial within
   a hook. Sends happen only after every PR reconciliation task in the round has
   finished or been bounded out, so a held webhook receiver cannot delay a later
   repository's PR update.

Each phase runs at most four repositories concurrently. PR reconciliation has a
bounded per-repository work deadline and replays an uncompleted page on the next
round. Delivery has *no* whole-repository cancellation timeout: it stops
starting new sends after a per-repository work budget, while an already-started
request keeps running under that hook's declared transport timeout (at most
30 s). A slow receiver therefore occupies one slot for a bounded wave, not the
whole scan, and is never abandoned merely to appear fair. Cancellation aborts
the owned `JoinSet` tasks before the round returns; no detached task survives.
Work is bounded, but this is not a throughput guarantee.

The work window and the outer timeout share one anchor taken by the worker
*before* the candidate query. Work stops at `scan_start + 240 s`
(`SCAN_WORK_BUDGET`) and the outer timeout fires at `scan_start + 300 s`
(`SCAN_TIMEOUT`), so the last 60 s stay reserved for a request that already
started even when the candidate query itself is slow. Candidate-query latency
is charged to the work budget; it can no longer silently shrink the reserve. If
the work window closes while phase one is running, phase two starts no new
backfill or send, and an in-flight send is still never cancelled early.

A restart loses only the in-memory cursor and replays from the beginning. That is
safe because pending deliveries, open PR rows, outbox events and the completion
marker are durable and every phase is idempotent or at-least-once.

## Clock semantics

`dispatch_due_deliveries(..., now_unix)` uses `now_unix` for selection **and**
for every claim/completion in that call. This preserves the manual API's
deterministic virtual-clock contract. The background path is separate: it uses a
fresh wall-clock timestamp for each claim and completion, while `select_now_unix`
only chooses the due batch. A slow batch therefore cannot lease or back off from
its start time, and retry backoff is scheduled from completion. Due rows are
selected in `sequence ASC` order for both paths, so an old due retry is not
inverted behind a newer pending row.

The hook transport uses one absolute end-to-end deadline across DNS resolution,
TCP/TLS connect and the HTTP response. The resolver, client `connect_timeout`
and request timeout all receive the time remaining against that deadline; a
30 s hook can therefore occupy at most about 30 s, not 60 s of separate DNS and
HTTP budgets. This preserves the scan reserve and the claim lease assumption
(`timeout_ms` plus five seconds). Answer checking, DNS pinning, disabled
redirects, `no_proxy` and the default loopback denial/re-check are unchanged.

## Pull cursor state

`PullCursors` keeps one current entry per repository that has an unfinished
multi-page open-PR prefix. Reaching the last page (`set(..., None)`) removes the
entry immediately, and advancing a page replaces the entry in place, so memory
is proportional to the currently eligible repository cardinality rather than to
historical churn.

There is deliberately no age TTL or fixed capacity eviction. Either policy would
reset an active prefix whenever more than the old 4096-repository cap was busy
or a long sweep exceeded the old 30-minute TTL. Instead, one rotating
`BTreeMap::range` page of at most 128 cursor IDs is checked per round against a
bounded SQL query. A cursor is pruned only when its repository row is deleted,
not `ready`, no longer GitFS-backed, or has no open pull left; the current
16-row candidate page is never used as evidence of inactivity. Entries carry a
generation tag, so an eligibility result cannot delete a cursor that was
advanced or recreated while the query was in flight. Query errors retain every
cursor and defer pruning to a later round. A full sweep of N retained cursors
takes `ceil(N / 128)` rounds.

Work remains bounded per round: 16 candidates, 4 concurrent repository tasks,
128 cursor IDs pruned, one 128-pair backfill page and 8 sends per repository.
None of these is a throughput guarantee; together they bound memory and the
work the scheduler can start in one scan.

## Manual dispatch contract

`POST /api/repos/{owner}/{name}/webhooks/dispatch` is unchanged:

- `limit` is optional, integer 1–200 (default 50), and bounds attempted
  deliveries in this call.
- `now_unix` is optional, non-negative, and is a selection floor as described
  above.
- `sync_pulls` defaults to true and runs the existing explicit full open-PR
  orchestration for the authorized repository. The background fair scheduler
  does not use this unbounded manual helper.
- `sync_outbox` defaults to true and performs one `LIMIT 200` outbox scan.
- The response remains `DispatchSummary` with counts and the attempted delivery
  projections.

The manual endpoint intentionally remains a foreground, repository-authorized
operation; it does not become the background scheduler.

## Outstanding-age metric

`rootyard_webhook_delivery_oldest_age_seconds` on the private metrics listener
is exactly one label-free series. Each scrape evaluates, with the database clock
(`statement_timestamp()`), the age of the oldest `forge_webhook_deliveries`
row joined to `forge_webhooks` whose hook is active and whose state is
`pending`, `failed` or `leased`. Retry-delayed `failed` rows and live `leased`
rows are part of the scheduler's outstanding work and therefore count;
`delivered`, `dead_letter` and inactive hooks are excluded. The value is clamped
at zero and is zero for an empty set. It never reads `event_deliveries` or
`outbox_events` and carries no hook, repository or tenant label. A failed SQL
snapshot omits it like every other database-derived gauge.

## Native tests

`tests/webhook_fairness.py` launches the Rust binary with its worker enabled and
never calls manual dispatch. It covers:

- the early repository in sorted order held at a real loopback receiver while a
  later repository is delivered and acknowledged under the same bound;
- a 20-row backlog plus an independently failing hook, bounded in-flight sends,
  hard restart and at-least-once recovery;
- graceful SIGTERM cancellation mid-send, durable `leased,1`, restart with a new
  attempt and completion of the other queued rows.
- a small >128 missing-pair fixture (8 hooks, 17 events) proving the first
  bounded backfill page is 128, the next page is selected in a later round and
  delivery rows keep draining over rounds without manual dispatch;

`tests/webhook_pr_sync.py` covers no active hook, a paused hook and a deleted
hook. Each case performs a separate PR head push and base push and verifies the
PR version/OIDs, deterministic pin ref, queued run/check and progress marker,
with zero delivery rows and zero receiver requests where no active hook exists.

Run only against a disposable database:

```sh
ROOTYARD_TEST_DATABASE_URL=... python3 tests/webhook_fairness.py \
  --binary target/debug/rootyard --report test-results/webhook-fairness.json
ROOTYARD_TEST_DATABASE_URL=... python3 tests/webhook_pr_sync.py \
  --binary target/debug/rootyard --report test-results/webhook-pr-sync.json
```

Scope: one host, owned loopback receivers and one disposable PostgreSQL 17.
These are functional fairness/failure tests, not throughput, multi-host,
power-loss or production-HA measurements.
