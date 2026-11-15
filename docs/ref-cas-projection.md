# Ref-CAS Event Replay, PostgreSQL Projection & Reliable Task Bridge (#117)

## Overview

`src/ref_store/projector` (`src/ref_store/projector.rs` + submodules under `src/ref_store/projector/`) turns committed/rejected `RefCasStateMachine` terminal events into idempotent PostgreSQL read projections, signed webhook deliveries (`forge_webhook_deliveries`), and lease-fenced reliable background tasks (`ref_cas_projection_jobs`).

Standalone PostgreSQL transactional outbox semantics (`src/events.rs`, `src/webhooks/ingestion.rs`) remain unchanged when operating in GitFS mode.

## Deterministic Identity & Single-Transaction Atomicity

1. **Consensus-bound Event Identity** (`src/ref_store/projector/identity.rs`):
   - `op_event_id = SHA-256("rootyard-refcas-op-event-v1" || history_incarnation || group_id || group_epoch || log_index || operation_id || repository_id)`
   - `ref_event_id = SHA-256("rootyard-refcas-ref-event-v1" || op_event_id || ref_sequence || ref_name)`
   - `webhook_event_id = "refcas:" || ref_event_id` (disjoint from standalone `"outbox:*"`)
   - `job_key = SHA-256("rootyard-refcas-job-key-v1" || op_event_id || kind || scope_key)`
   - Event identity and replay frontiers never depend on PostgreSQL `SERIAL` sequences or `MAX(id)`.
2. **Single-Transaction Boundary** (`src/ref_store/projector/pg.rs`):
   - `project_event_in_tx` locks `ref_cas_projection_cursors` (`FOR UPDATE`), verifies contiguous ordering (`validate_cursor_step`), checks duplicate / equivocation digests against `ref_cas_projected_operations`, writes:
     - `ref_cas_projected_operations` (`can_authorize_write = FALSE`)
     - `ref_cas_projected_events` (`ON CONFLICT (event_id) DO NOTHING`)
     - `ref_cas_projected_refs` (monotonic `(group_epoch, log_index, event_seq)` upsert guard, `can_authorize_write = FALSE`)
     - `forge_webhook_deliveries` (`ON CONFLICT (webhook_id, event_id) DO NOTHING`, skipping `refs/rootyard-ci*`)
     - `ref_cas_projection_jobs` (`ON CONFLICT (job_key) DO NOTHING`)
   - Advances `ref_cas_projection_cursors` in the exact same PostgreSQL transaction so pre-commit kills roll back cleanly and post-commit retries are no-op duplicates.

## Cursor Replay, Out-of-Order & Watch Recovery

- Durable stream frontiers live in `ref_cas_projection_cursors`, keyed by `(group_id, history_incarnation)`.
- Replay after PostgreSQL disconnects, Redis/watch drops, or event backlogs resumes strictly from `(applied_event_seq, applied_log_index, applied_log_term)`.
- Out-of-order jumps ahead of `applied_event_seq + 1` fail closed with `ProjectionError::SequenceGap`, never skipping unseen committed entries.
- Stale duplicate replays compare `terminal_digest` and skip without reverting newer `ref_cas_projected_refs` or duplicating webhooks/jobs.

## Historical Revocation Safety & Write Non-Authorization

- `ref_cas_projected_operations` stores optional historical `actor_id` / `token_id` audit snapshots without foreign keys to `tokens` and without `enforce_repository_actor_membership()`, so revoking a token or removing a repository member never blocks projecting previously committed Ref-CAS facts.
- Both `ref_cas_projected_operations` and `ref_cas_projected_refs` enforce `can_authorize_write = FALSE`. `assert_projection_cannot_authorize_write` and `verify_projected_operation_non_authorizing` forbid using any projected receipt or history row to authorize new ref writes.

## Retention / Archive Truncation Closure

- Monotonic truncation watermarks (`TruncationCutoff { log_index, event_seq, log_term, closure_digest, archive_uri }`) bind sealed log/archive compaction boundaries via `compute_truncation_closure_digest`.
- If log retention compacts past the cursor (`earliest_available_event_seq > cursor.applied_event_seq + 1`), `check_stream_continuity` transitions `stream_state` to `resync_required` and returns `ProjectionError::TruncatedBeforeCursor`. Recovery requires explicit closure verification via `complete_cursor_resync` / `complete_cursor_resync_in_tx`.
- Active dedup ledgers (`ref_cas_projected_operations`, `ref_cas_projected_events`) and unresolved `unknown_hold` / `failed` jobs in `ref_cas_projection_jobs` are never expired by wall-clock TTL sweeps.

## Worker Integration

- `src/events.rs`: exposes `process_ref_cas_projection_jobs` and `project_ref_cas_event_in_tx`.
- `src/dispatch.rs`: drives bounded `process_ref_cas_projection_jobs` alongside `events::CONSUMERS` scans (preserving `cache_wake::RedisWake::from_env()`).
- `src/webhooks/background.rs`: invokes `ref_store::projector::sync_webhooks_bounded` alongside legacy outbox backfill inside `deliver_candidate`.
