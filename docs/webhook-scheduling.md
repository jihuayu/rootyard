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
   repository (`LIMIT 200` inside), then at most 8 due deliveries, serial within
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

## Native tests

`tests/webhook_fairness.py` launches the Rust binary with its worker enabled and
never calls manual dispatch. It covers:

- the early repository in sorted order held at a real loopback receiver while a
  later repository is delivered and acknowledged under the same bound;
- a 20-row backlog plus an independently failing hook, bounded in-flight sends,
  hard restart and at-least-once recovery;
- graceful SIGTERM cancellation mid-send, durable `leased,1`, restart with a new
  attempt and completion of the other queued rows.

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
