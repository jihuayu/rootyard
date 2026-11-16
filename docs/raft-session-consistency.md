# Distributed Raft Ref-CAS Session Lower Bounds & Projection Dependency Verification (#175)

## Scope & Authority Boundaries

This module (`src/ref_store/projector/session_fence.rs`, `src/ref_store/projector/dependency.rs`) implements the distributed Raft Ref-CAS causal read fence and asynchronous PostgreSQL projection dependency protocol on top of the Migration `149` projection tables (`#117`), `#115` mTLS `crates/refcas-log` `raft-node` quorum barriers, `#116` deterministic `RefCasStateMachine` pins/roots/holds, and `#174` single-node causal token design (`#172`).

1. **Non-dependence & Scope**:
   * Standalone single-node `pg_refstore` (`#174`) does not depend on this distributed path and retains its own `rs1.` token boundary.
   * Distributed failure qualification strictly respects `#157`: single-host multi-process `raft-node` + PG17 tests prove real process mTLS/quorum/crash/projection-recovery behavior under host loopback conditions, **not** multi-host hardware durability or automatic wide-area failover. Full end-to-end causal consistency across extra queues, services, or cross-repository links requires propagating and testing every participating link explicitly.
   * Keep `#180`–`#185` separation intact: these causal bounds and projection dependency waits do not replace `#180`/`#183` pack/base versioning or `#184` fetch planning, and never require basic projection waits for optional `packfile-uri` (`#185`).

## Strict Coordinate Separation

Tokens (`rrs1.<body>.<mac>`) and projection gates never collapse distinct consensus and projection axes:

* **Consensus Realm Identity (`RaftSessionRealm`)**:
  `group_id`, `group_epoch`, `history_incarnation`, `authority_id`, `authority_epoch`, `cluster_incarnation`, `tenant_id`, `repository_id`, `object_format`.
* **Raft Log Position**: `raft_log_index` (`u64 >= 1`), strictly scoped to one exact `RaftSessionRealm`. Bare `log_index` values are never compared across `group_id`s or rotated realms.
* **Repository Version**: `repo_ref_version` (`i64 >= 1`), tracking `RefCasStateMachine` core gate progression for that repository.
* **Raft `term` Separation**: Raft election `term` is never stored as a business epoch and never treated as sufficient to satisfy a monotonic read lower bound.
* **Projection Cursor Separation**: Asynchronous PostgreSQL projection progress (`ref_cas_projection_cursors.applied_event_seq` / `applied_log_index`) is tracked separately by `ProjectionDependencyTarget` and never substitutes for Raft commit authority.

## Causal Lower-Bound Token (`rrs1.`) & Read Gate (`session_fence.rs`)

* **Authentication & Live Permission Ordering**: Caller authentication (`401`) and live RBAC/scope permission checks (`403`) execute *before* probing or minting causal tokens (`evaluate_raft_read` / `await_raft_read_or_redirect`), preventing version/existence oracles on revoked callers.
* **Authoritative Proof Requirement (`AuthoritySourceKind`)**: Reads require `AuthoritySourceKind::RaftReadIndexQuorum` backed by a proven Raft `ReadIndex` barrier and intact pin/pack closure (`pin_closure_intact`). Falling back to `PgRefsProjection`, `RedisCache`, or `UnverifiedLocalReplica` fails closed with `503 Service Unavailable` (`AuthorityViolation`).
* **Monotonic Wait / Redirect / Fail-Closed (`await_raft_read_or_redirect`)**:
  * When probing a follower returns `ForwardToLeader(leader_id)`, the gate performs bounded leader redirection and re-runs `ReadIndex` + applied-index comparison against `(raft_log_index, repo_ref_version)`.
  * When a replica or quorum is temporarily lagged, the gate waits only within its explicit deadline budget; upon expiry or quorum loss it returns `503 Service Unavailable` (`BehindLowerBound` / `QuorumUnavailable`), never silently serving pre-bound state.
* **Forgery, Expiry & Realm Rotation Refusals**:
  * Tampered or retired-key HMAC-SHA256 `rrs1.` frames fail constant-time `ring::hmac::verify` with `401 Unauthorized`.
  * Malformed frames or duplicate/non-ASCII `x-rootyard-session` headers fail with `400 Bad Request`.
  * Expired tokens (zero future-`iat` skew, half-open `[issued, issued + lifetime)`) and changed `group_id` / `group_epoch` / `history_incarnation` / `authority_id` / `authority_epoch` / `cluster_incarnation` (including post-restore rotation) fail with `409 Conflict` (`Expired` / `RealmMismatch`), even when the new history has higher numeric indices.

## Asynchronous PG Projection Dependency Protocol (`dependency.rs`)

* Reuses Migration `149` tables (`ref_cas_projection_cursors`, `ref_cas_projected_operations`, `ref_cas_projected_events`, `ref_cas_projected_refs`, `ref_cas_projection_jobs`) with zero new schema migrations.
* **Atomic Single-TX Effects + Contiguous Frontier**: `apply_projection_step_atomically` projects operation/event/ref/webhook/job effects and updates `ref_cas_projection_cursors` inside one PostgreSQL transaction; pre-commit aborts roll back cleanly with zero partial side effects.
* **No Gap Skipping & Bounded Dependency Wait**: `apply_projection_stream_stop_on_gap` halts immediately on `SequenceGap`, `ResyncRequired`, or `Equivocation`. `verify_projection_dependency` and `await_projected_event` read `ref_cas_projection_cursors` (never `MAX(id)` or `MAX(event_seq)` across gapped tables), reject `resync_required` streams immediately (`SequenceGapOrResync`), enforce `can_authorize_write = FALSE`, and fail explicitly with `ProjectionDependencyError::Timeout` if the contiguous frontier does not catch up within budget.

## Stock Git Compatibility & Pin/GC Closure

* Standard Git HTTP clients (`git ls-remote`, `git clone`) do not send custom `x-rootyard-session` headers (`presented_token = None`). Endpoints route stock Git reads through the same proven `ReadIndex` + `pin_closure_intact` gate before serving immutable pack/OID closures verified by `git fsck`.
* `RefCasStateMachine` pins and active `RootRecordSm` entries prevent `RetireHoldBatch` until `ReleaseRoot` and paired cursor barriers complete.

## Verification Coverage

* Unit tests (`src/ref_store/projector/session_tests.rs`): `cargo test --locked --lib ref_store::projector`
* Multi-process mTLS Raft + real HTTP + PG17 + stock Git E2E acceptance (`tests/ref_store_raft_session_consistency.rs`): `cargo test --locked --test ref_store_raft_session_consistency -- --ignored --test-threads=1` (executed via `.github/workflows/raft-session-consistency.yml`)
* Offline architecture & workflow contract verification: `python3 -m unittest tests.test_raft_session_consistency_contracts`
